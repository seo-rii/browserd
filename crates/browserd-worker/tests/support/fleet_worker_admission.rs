use super::*;
use browserd_core::LeaseId;
use browserd_worker::{
    CreatedSessionContext, ResourceVector, WorkerAdmissionBudget, WorkerAdmissionPolicy,
    WorkerReservationPhase, WorkerReservationRequest, WorkerTenantAssignment,
};
use std::sync::atomic::AtomicBool;

fn fixture_error(error: impl std::fmt::Debug) -> Box<dyn Error> {
    std::io::Error::other(format!("admission fixture: {error:?}")).into()
}
fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> Result<T, Box<dyn Error>> {
    result.map_err(fixture_error)
}

struct AdmissionDriver {
    inner: OptionsRecordingDriver,
    fail_create: bool,
    isolation: WorkerIsolationProfile,
    return_weaker: AtomicBool,
}
impl ChromiumDriver for AdmissionDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn effective_isolation(&self) -> WorkerIsolationProfile {
        self.isolation
    }
    fn create_context(&self, session: &SessionId) -> Result<PageId, DependencyError> {
        self.inner.create_context(session)
    }
    fn create_context_owned_with_placement(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        _requested: WorkerIsolationProfile,
    ) -> Result<CreatedSessionContext, DependencyError> {
        if self.fail_create {
            self.inner.calls.fetch_add(1, Ordering::SeqCst);
            return Err(DependencyError::OutcomeUncertain);
        }
        Ok(CreatedSessionContext {
            primary_page_id: self.inner.create_context_owned_with_options(
                tenant,
                session,
                fence,
                options.ok_or(DependencyError::Rejected)?,
            )?,
            effective_isolation: if self.return_weaker.load(Ordering::SeqCst) {
                WorkerIsolationProfile::SharedContext
            } else {
                self.isolation
            },
        })
    }
    fn close_context(&self, session: &SessionId) -> Result<(), DependencyError> {
        if self.fail_create {
            return Err(DependencyError::OutcomeUncertain);
        }
        self.inner.close_context(session)
    }
    fn create_page(&self, session: &SessionId) -> Result<PageId, DependencyError> {
        self.inner.create_page(session)
    }
    fn close_page(&self, session: &SessionId, page: &PageId) -> Result<(), DependencyError> {
        self.inner.close_page(session, page)
    }
    fn activate_page(&self, session: &SessionId, page: &PageId) -> Result<(), DependencyError> {
        self.inner.activate_page(session, page)
    }
    fn execute_action(
        &self,
        session: &SessionId,
        page: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.inner.execute_action(session, page, payload)
    }
    fn inspect_approval_context(
        &self,
        session: &SessionId,
        page: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        self.inner.inspect_approval_context(session, page, proposal)
    }
    fn execute_approved_action(
        &self,
        session: &SessionId,
        page: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        self.inner.execute_approved_action(
            session,
            page,
            payload,
            proposal,
            inspected,
            authorize_and_commit,
        )
    }
    fn cancel_action(
        &self,
        session: &SessionId,
        action: &ActionId,
    ) -> Result<bool, DependencyError> {
        self.inner.cancel_action(session, action)
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    peer: AuthenticatedPeer,
    tenant: TenantId,
    driver: Arc<AdmissionDriver>,
    worker: Arc<WorkerControlPlane<AdmissionDriver, ReadySandbox>>,
}
fn fixture(capacity: u64, fail_create: bool, exclusive: bool) -> Result<Fixture, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let worker_id = WorkerId::new("worker-admission-fixture")?;
    let tenant = TenantId::new();
    let peer = checked(AuthenticatedPeer::new("gateway-admission-fixture"))?;
    let isolation = if exclusive {
        WorkerIsolationProfile::DedicatedWorker
    } else {
        WorkerIsolationProfile::SharedContext
    };
    let assignment = if exclusive {
        Some(checked(WorkerTenantAssignment::new(
            worker_id.clone(),
            tenant.clone(),
            [7; 32],
        ))?)
    } else {
        None
    };
    let policy = checked(WorkerAdmissionPolicy::new(
        [1; 32],
        ResourceVector::new(capacity, capacity, capacity, capacity, capacity, capacity),
        vec![WorkerAdmissionBudget {
            profile_digest: [2; 32],
            isolation,
            resources: ResourceVector::new(1, 1, 1, 1, 1, 1),
        }],
        64,
        assignment,
    ))?;
    let config = checked(WorkerConfig::new(
        worker_id,
        7,
        InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19990)),
        peer.clone(),
        usize::try_from(capacity)?,
        8,
        checked(LeasePolicy::new(
            Duration::from_secs(15),
            Duration::from_secs(3),
        ))?,
        checked(SessionTimeoutPolicy::new(
            Duration::from_secs(60),
            Duration::from_secs(30),
        ))?,
        Duration::from_secs(60),
        checked(ActionJournalConfig::new(
            directory.path(),
            ActionJournalLimits::default(),
        ))?,
    ))?
    .with_session_option_support(SessionOptionSupport::new(
        ["public".to_owned()],
        ["auto_dismiss".to_owned()],
        ["standard".to_owned()],
        true,
    ))
    .with_fleet_admission_policy(policy)
    .map_err(fixture_error)?;
    let driver = Arc::new(AdmissionDriver {
        inner: OptionsRecordingDriver::new(PageId::new()),
        fail_create,
        isolation,
        return_weaker: AtomicBool::new(false),
    });
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config,
        Arc::clone(&driver),
        Arc::new(ReadySandbox),
        Arc::new(FrozenClock),
    ));
    Ok(Fixture {
        _directory: directory,
        peer,
        tenant,
        driver,
        worker,
    })
}
fn request(f: &Fixture, ttl: u64) -> Result<WorkerReservationRequest, Box<dyn Error>> {
    let capacity = checked(f.worker.capacity_status(&f.peer, 7))?;
    let options = session_options();
    let isolation = f.driver.isolation;
    Ok(WorkerReservationRequest {
        request: WorkerCreateSessionRequest {
            operation_id: OperationId::new(),
            tenant_id: f.tenant.clone(),
            idempotency_key: LeaseId::new().to_string(),
            canonical_request_hash: options.canonical_request_hash(isolation),
            expected_worker_epoch: 7,
            placement_version: 1,
            session_incarnation: 1,
            requested_isolation: isolation,
            options_version: WORKER_SESSION_OPTIONS_VERSION,
            options,
            now_unix_millis: 0,
        },
        reservation_id: LeaseId::new(),
        expected_worker_boot_nonce: capacity.worker_boot_nonce,
        compatibility_digest: [1; 32],
        profile_digest: [2; 32],
        resources: ResourceVector::new(1, 1, 1, 1, 1, 1),
        ttl_millis: ttl,
    })
}

#[test]
fn exact_reservation_retry_does_not_extend_ttl_and_cancel_returns_capacity()
-> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let req = request(&f, 2000)?;
    let first = checked(f.worker.reserve_session(&f.peer, req.clone()))?;
    assert_eq!(first.capacity.raw_free, ResourceVector::ZERO);
    assert_eq!(
        first.capacity.acknowledged_debit_sequence,
        first.token.debit_sequence
    );
    std::thread::sleep(Duration::from_millis(20));
    let retry = checked(f.worker.reserve_session(&f.peer, req.clone()))?;
    assert_eq!(retry.token, first.token);
    assert!(retry.remaining_ttl_millis < first.remaining_ttl_millis);
    let mut changed = req;
    changed.ttl_millis += 1;
    assert!(matches!(
        f.worker.reserve_session(&f.peer, changed),
        Err(WorkerError::IdempotencyConflict)
    ));
    let cancelled = checked(f.worker.cancel_session_reservation(&f.peer, &first.token))?;
    assert_eq!(cancelled.phase, WorkerReservationPhase::Cancelled);
    assert_eq!(cancelled.capacity.raw_free.contexts, 1);
    assert_eq!(
        checked(f.worker.commit_reserved_session(&f.peer, &first.token))?.phase,
        WorkerReservationPhase::Cancelled
    );
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn concurrent_reservations_share_the_final_control_plane_capacity_lock()
-> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let requests: Vec<_> = (0..16)
        .map(|_| request(&f, 2000))
        .collect::<Result<_, _>>()?;
    let start = Arc::new(Barrier::new(16));
    let successes = std::thread::scope(|scope| -> Result<usize, std::io::Error> {
        let handles: Vec<_> = requests
            .into_iter()
            .map(|req| {
                let start = Arc::clone(&start);
                let worker = Arc::clone(&f.worker);
                let peer = f.peer.clone();
                scope.spawn(move || {
                    start.wait();
                    worker.reserve_session(&peer, req)
                })
            })
            .collect();
        let results = handles
            .into_iter()
            .map(|h| {
                h.join()
                    .map_err(|_| std::io::Error::other("reservation thread panicked"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results.into_iter().filter(Result::is_ok).count())
    })?;
    assert_eq!(successes, 1);
    assert_eq!(
        checked(f.worker.capacity_status(&f.peer, 7))?
            .raw_free
            .contexts,
        0
    );
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn commit_transfers_one_slot_and_replay_never_recreates_then_exact_cleanup_releases()
-> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let reserved = checked(f.worker.reserve_session(&f.peer, request(&f, 2000)?))?;
    let active = checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?;
    assert_eq!(active.phase, WorkerReservationPhase::Active);
    assert_eq!(active.capacity.raw_free.contexts, 0);
    assert!(
        active
            .session_lease_remaining_millis
            .is_some_and(|ttl| ttl > 0)
    );
    let session = active.session.ok_or("missing session")?;
    assert_eq!(
        checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?.session,
        Some(session.clone())
    );
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 1);
    let fence = OwnershipFence::new(reserved.token.worker_id.clone(), 7, 1, 1);
    f.worker
        .close_session(&f.peer, &session.session_id, &fence, SessionTime::new(1))
        .map_err(fixture_error)?;
    let closed = checked(
        f.worker
            .inspect_session_reservation(&f.peer, &reserved.token),
    )?;
    assert_eq!(closed.phase, WorkerReservationPhase::Released);
    assert_eq!(closed.capacity.raw_free.contexts, 1);
    assert_eq!(f.driver.inner.closed.load(Ordering::SeqCst), 1);
    checked(f.worker.ack_session_reservation(&f.peer, &reserved.token))?;
    Ok(())
}

#[test]
fn only_unexposed_reservations_expire_unknown_creation_stays_charged() -> Result<(), Box<dyn Error>>
{
    let f = fixture(1, false, false)?;
    let reserved = checked(f.worker.reserve_session(&f.peer, request(&f, 1)?))?;
    std::thread::sleep(Duration::from_millis(20));
    let expired = checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?;
    assert_eq!(expired.phase, WorkerReservationPhase::Expired);
    assert_eq!(expired.capacity.raw_free.contexts, 1);
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 0);
    let uncertain = fixture(1, true, false)?;
    let reserved = checked(
        uncertain
            .worker
            .reserve_session(&uncertain.peer, request(&uncertain, 250)?),
    )?;
    assert_eq!(
        checked(
            uncertain
                .worker
                .commit_reserved_session(&uncertain.peer, &reserved.token)
        )?
        .phase,
        WorkerReservationPhase::ExposurePossible
    );
    assert!(
        uncertain
            .worker
            .cancel_session_reservation(&uncertain.peer, &reserved.token)
            .is_err()
    );
    std::thread::sleep(Duration::from_millis(300));
    let replay = checked(
        uncertain
            .worker
            .commit_reserved_session(&uncertain.peer, &reserved.token),
    )?;
    assert_eq!(replay.phase, WorkerReservationPhase::ExposurePossible);
    assert_eq!(replay.capacity.raw_free.contexts, 0);
    assert_eq!(uncertain.driver.inner.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn restart_nonce_profile_hash_and_foreign_tenant_fail_before_browser_effects()
-> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, true)?;
    let valid = request(&f, 2000)?;
    let mut cases = Vec::new();
    let mut wrong = valid.clone();
    wrong.expected_worker_boot_nonce = LeaseId::new();
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.request.tenant_id = TenantId::new();
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.profile_digest = [9; 32];
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.request.canonical_request_hash = [9; 32];
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.compatibility_digest = [9; 32];
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.resources.contexts = 2;
    cases.push(wrong);
    let mut wrong = valid.clone();
    wrong.request.expected_worker_epoch += 1;
    cases.push(wrong);
    for wrong in cases {
        assert!(f.worker.reserve_session(&f.peer, wrong).is_err());
    }
    let reserved = checked(f.worker.reserve_session(&f.peer, valid))?;
    let mut forged = reserved.token.clone();
    forged.worker_reservation_nonce = LeaseId::new();
    assert!(f.worker.commit_reserved_session(&f.peer, &forged).is_err());
    let restarted = fixture(1, false, true)?;
    assert!(
        restarted
            .worker
            .commit_reserved_session(&restarted.peer, &reserved.token)
            .is_err()
    );
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        checked(f.worker.capacity_status(&f.peer, 0))?.worker_epoch,
        7
    );
    assert!(f.worker.capacity_status(&f.peer, 8).is_err());
    Ok(())
}

#[test]
fn renewal_has_exact_revision_and_nonce_replay_and_survives_drain() -> Result<(), Box<dyn Error>> {
    let f = fixture(2, false, false)?;
    let reserved = checked(f.worker.reserve_session(&f.peer, request(&f, 2000)?))?;
    assert_eq!(
        checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?.phase,
        WorkerReservationPhase::Active
    );
    let nonce = LeaseId::new();
    let first = checked(f.worker.renew_reserved_session(
        &f.peer,
        &reserved.token,
        nonce.clone(),
        1,
        10_000,
    ))?;
    assert!(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, nonce.clone(), 2, 10_000)
            .is_err()
    );
    assert_eq!(
        checked(f.worker.renew_reserved_session(
            &f.peer,
            &reserved.token,
            nonce.clone(),
            1,
            10_000
        ))?,
        first
    );
    assert!(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, nonce.clone(), 1, 9000)
            .is_err()
    );
    checked(f.worker.begin_drain(&f.peer))?;
    assert!(checked(f.worker.capacity_status(&f.peer, 7))?.draining);
    assert!(
        f.worker
            .reserve_session(&f.peer, request(&f, 2000)?)
            .is_err()
    );
    checked(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, LeaseId::new(), 2, 10_000),
    )?;
    assert!(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, nonce.clone(), 1, 10_000)
            .is_err()
    );
    assert!(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, nonce, 3, 10_000)
            .is_err()
    );
    assert_eq!(
        checked(
            f.worker
                .inspect_session_reservation(&f.peer, &reserved.token)
        )?
        .phase,
        WorkerReservationPhase::Active
    );
    Ok(())
}

#[tokio::test]
async fn managed_worker_rejects_legacy_create_rpc_bypass() -> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let request = request(&f, 2000)?.request;
    let handler = WorkerControlPlaneRpcHandler::new(Arc::clone(&f.worker), f.peer.clone());
    assert!(
        matches!(handler.handle(WorkerRpcRequest::CreateSession(request)).await,
        WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::InvalidRequest)
    );
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        checked(f.worker.capacity_status(&f.peer, 7))?
            .raw_free
            .contexts,
        1
    );
    Ok(())
}

#[test]
fn ownership_receipts_and_renewals_are_bounded_by_session_and_idle_deadlines()
-> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let mut req = request(&f, 2000)?;
    req.request.options.idle_timeout_seconds = 1;
    req.request.canonical_request_hash = req
        .request
        .options
        .canonical_request_hash(req.request.requested_isolation);
    let reserved = checked(f.worker.reserve_session(&f.peer, req))?;
    let active = checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?;
    assert_eq!(active.session_lease_remaining_millis, Some(1000));
    assert!(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, LeaseId::new(), 1, 10_000)
            .is_err()
    );
    let renewal =
        checked(
            f.worker
                .renew_reserved_session(&f.peer, &reserved.token, LeaseId::new(), 1, 500),
        )?;
    assert_eq!(renewal.granted_ttl_millis, 500);
    Ok(())
}

#[test]
fn cached_renewal_cannot_report_ready_after_confirmed_cleanup() -> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let reserved = checked(f.worker.reserve_session(&f.peer, request(&f, 2000)?))?;
    let active = checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?;
    let nonce = LeaseId::new();
    checked(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, nonce.clone(), 1, 10_000),
    )?;
    let session = active.session.ok_or("missing session")?;
    let fence = OwnershipFence::new(reserved.token.worker_id.clone(), 7, 1, 1);
    checked(
        f.worker
            .close_session(&f.peer, &session.session_id, &fence, SessionTime::new(1)),
    )?;
    assert!(
        f.worker
            .renew_reserved_session(&f.peer, &reserved.token, nonce, 1, 10_000)
            .is_err()
    );
    assert_eq!(
        checked(
            f.worker
                .inspect_session_reservation(&f.peer, &reserved.token)
        )?
        .phase,
        WorkerReservationPhase::Released
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_admission_roundtrips_exact_tokens_and_cleanup_over_authenticated_socket()
-> Result<(), Box<dyn Error>> {
    use browserd_worker::{WorkerRpcClient, WorkerRpcConfig, WorkerRpcServer};
    use std::os::unix::fs::MetadataExt;
    let f = fixture(1, false, false)?;
    let uid = std::fs::metadata("/proc/self")?.uid();
    let socket = f._directory.path().join("admission.sock");
    let config = WorkerRpcConfig::new(
        socket.clone(),
        64 * 1024,
        4,
        Duration::from_secs(2),
        Some(uid),
    )?;
    let handler = Arc::new(WorkerControlPlaneRpcHandler::new(
        Arc::clone(&f.worker),
        f.peer.clone(),
    ));
    let server = WorkerRpcServer::bind(config, handler).await?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(socket, 64 * 1024, Duration::from_secs(2), Some(uid))?;
    let status = client.capacity_status(7).await?;
    assert_eq!(status.raw_free.contexts, 1);
    let reserved = client.reserve_session(request(&f, 2000)?).await?;
    let active = client
        .commit_reserved_session(reserved.token.clone())
        .await?;
    assert_eq!(active.phase, WorkerReservationPhase::Active);
    let replay = client
        .inspect_session_reservation(reserved.token.clone())
        .await?;
    assert_eq!(replay.token, reserved.token);
    assert_eq!(replay.session, active.session);
    let renewal = client
        .renew_reserved_session(reserved.token.clone(), LeaseId::new(), 1, 10_000)
        .await?;
    client.close_session(renewal.session.fence, 0).await?;
    let closed = client
        .inspect_session_reservation(reserved.token.clone())
        .await?;
    assert_eq!(closed.phase, WorkerReservationPhase::Released);
    assert_eq!(
        client.ack_session_reservation(reserved.token).await?.phase,
        WorkerReservationPhase::Released
    );
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 1);
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    Ok(())
}

#[test]
fn pre_effect_checkpoint_failure_has_positive_no_effect_and_is_acknowledgeable()
-> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, false)?;
    let mut req = request(&f, 2000)?;
    req.request.options.checkpoint_ref = Some(uuid::Uuid::new_v4().to_string());
    req.request.canonical_request_hash = req
        .request
        .options
        .canonical_request_hash(req.request.requested_isolation);
    let reserved = checked(f.worker.reserve_session(&f.peer, req))?;
    assert!(
        f.worker
            .ack_session_reservation(&f.peer, &reserved.token)
            .is_err()
    );
    let failed = checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?;
    assert_eq!(failed.phase, WorkerReservationPhase::Cancelled);
    assert!(failed.session.is_none() && failed.disposed_session.is_none());
    assert_eq!(failed.capacity.raw_free.contexts, 1);
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 0);
    checked(f.worker.ack_session_reservation(&f.peer, &reserved.token))?;
    Ok(())
}

#[test]
fn exact_cleanup_after_failed_create_returns_real_disposed_fence() -> Result<(), Box<dyn Error>> {
    let f = fixture(1, false, true)?;
    let reserved = checked(f.worker.reserve_session(&f.peer, request(&f, 2000)?))?;
    f.driver.return_weaker.store(true, Ordering::SeqCst);
    let failed = checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?;
    assert_eq!(failed.phase, WorkerReservationPhase::Released);
    assert!(failed.session.is_none());
    let disposed = failed
        .disposed_session
        .ok_or("missing exact cleanup fence")?;
    assert_eq!(disposed.tenant_id, f.tenant);
    assert_eq!(
        (
            disposed.worker_epoch,
            disposed.placement_version,
            disposed.session_incarnation
        ),
        (7, 1, 1)
    );
    assert_eq!(failed.capacity.raw_free.contexts, 1);
    assert_eq!(f.driver.inner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.driver.inner.closed.load(Ordering::SeqCst), 1);
    assert_eq!(
        checked(f.worker.commit_reserved_session(&f.peer, &reserved.token))?.disposed_session,
        Some(disposed)
    );
    checked(f.worker.ack_session_reservation(&f.peer, &reserved.token))?;
    Ok(())
}
