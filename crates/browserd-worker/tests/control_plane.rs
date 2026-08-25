use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use browserd_actions::{ActionKind, ResolutionKind};
use browserd_core::{PageId, PrincipalId, TenantId, WorkerId};
use browserd_features::BuiltinFeature;
use browserd_policy::ApprovalDecision;
use browserd_session::{LeasePolicy, SessionLifecycle, SessionTime, SessionTimeoutPolicy};
use browserd_viewer::ViewerScopes;
use browserd_worker::{
    ActionExecutionResult, ActionStatus, ArtifactUpload, AuthenticatedPeer, ChromiumDriver,
    CreateSessionCommand, DependencyError, InternalEndpoint, SandboxClient, WorkerConfig,
    WorkerControlPlane, WorkerError,
};

#[derive(Default)]
struct FakeDriver {
    qualified: bool,
    executions: Mutex<VecDeque<ActionExecutionResult>>,
    cleanup_count: Mutex<usize>,
    execution_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
}

impl ChromiumDriver for FakeDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
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

    fn cancel_action(
        &self,
        _session_id: &browserd_core::SessionId,
        _action_id: &browserd_core::ActionId,
    ) -> Result<bool, DependencyError> {
        Ok(true)
    }
}

#[derive(Default)]
struct FakeSandbox {
    qualified: bool,
    fail_provision: bool,
    provision_count: Mutex<usize>,
    cleanup_count: Mutex<usize>,
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
        let Ok(mut count) = self.provision_count.lock() else {
            return Err(DependencyError::Unavailable);
        };
        *count += 1;
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
        Ok(())
    }

    fn heartbeat(&self, _worker_id: &WorkerId, _worker_epoch: u64) -> Result<(), DependencyError> {
        Ok(())
    }

    fn store_artifact(
        &self,
        _session_id: &browserd_core::SessionId,
        _upload: &ArtifactUpload,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
}

fn config(queue_capacity: usize) -> Option<WorkerConfig> {
    config_with_max_sessions(queue_capacity, 16)
}

fn config_with_max_sessions(queue_capacity: usize, max_sessions: usize) -> Option<WorkerConfig> {
    let worker_id = WorkerId::new("worker-test").ok()?;
    let endpoint =
        InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9010)).ok()?;
    let peer = AuthenticatedPeer::new("gateway-internal").ok()?;
    let lease = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20)).ok()?;
    let timeout =
        SessionTimeoutPolicy::new(Duration::from_millis(1_000), Duration::from_millis(500)).ok()?;
    WorkerConfig::new(
        worker_id,
        7,
        endpoint,
        peer,
        max_sessions,
        queue_capacity,
        lease,
        timeout,
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
    let worker = WorkerControlPlane::new(config(queue_capacity)?, driver.clone(), sandbox.clone());
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
    let worker = WorkerControlPlane::new(config, driver, sandbox);
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
    let first = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "action-key",
        [3; 32],
        ActionKind::Mutating,
        Some(BuiltinFeature::CoreInput),
        Some(page),
        b"click".to_vec(),
        false,
        SessionTime::new(2),
    );
    assert!(first.is_ok());
    let Some(first) = first.ok() else {
        return;
    };
    let duplicate = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "action-key",
        [3; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        false,
        SessionTime::new(2),
    );
    assert_eq!(duplicate.ok(), Some(first.clone()));
    assert_eq!(
        worker.submit_action(
            &peer,
            &created.session_id,
            &created.fence,
            "second",
            [4; 32],
            ActionKind::ReadOnly,
            None,
            None,
            Vec::new(),
            false,
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
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "create", 1),
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
    assert!(
        worker
            .get_artifact(&peer, &created.session_id, &artifact, &created.fence)
            .is_ok()
    );
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

    let action = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "approval",
        [8; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        true,
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
        &created.session_id,
        &created.fence,
        "running",
        [9; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        false,
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
        &created.session_id,
        &created.fence,
        "running-close",
        [10; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        false,
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
        &created.session_id,
        &created.fence,
        "queued-at-expiry",
        [11; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        false,
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
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "close-pending", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let queued = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "queued",
        [12; 32],
        ActionKind::ReadOnly,
        None,
        None,
        Vec::new(),
        false,
        SessionTime::new(1),
    );
    let pending = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "pending",
        [13; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        true,
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
    let worker = WorkerControlPlane::new(config, driver, sandbox.clone());
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
    let worker = WorkerControlPlane::new(config, driver, sandbox);
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
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "timeout-actions", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let running = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "timeout-running",
        [14; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        false,
        SessionTime::new(1),
    );
    let queued = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "timeout-queued",
        [15; 32],
        ActionKind::ReadOnly,
        None,
        None,
        Vec::new(),
        false,
        SessionTime::new(1),
    );
    let pending = worker.submit_action(
        &peer,
        &created.session_id,
        &created.fence,
        "timeout-pending",
        [16; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        true,
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
                &created.session_id,
                &created.fence,
                "page-bound-action",
                [17; 32],
                ActionKind::Mutating,
                None,
                Some(created.primary_page_id.clone()),
                Vec::new(),
                false,
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
