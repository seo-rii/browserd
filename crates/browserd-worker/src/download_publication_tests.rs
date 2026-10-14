#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::AtomicUsize;

use crate::*;

struct DownloadsDriver {
    pending: Mutex<Vec<BrowserDownloadCompletion>>,
    file: tempfile::NamedTempFile,
    ack_failures: AtomicUsize,
    rejected: AtomicUsize,
    reject_failures: AtomicUsize,
}

impl ChromiumDriver for DownloadsDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
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
        ActionExecutionResult::OutcomeUnknown
    }
    fn inspect_approval_context(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Err(DependencyError::Rejected)
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
        Err(ApprovedActionError::Unavailable)
    }
    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        Ok(false)
    }
    fn pending_browser_downloads(
        &self,
        _: &SessionId,
        _: &OwnershipFence,
        limit: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, DependencyError> {
        Ok(self
            .pending
            .lock()
            .unwrap()
            .iter()
            .take(limit)
            .cloned()
            .collect())
    }
    fn open_browser_download(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<BrowserDownloadFile, DependencyError> {
        BrowserDownloadFile::from_test_file(completion.clone(), self.file.reopen().unwrap())
            .map_err(|_| DependencyError::Rejected)
    }
    fn ack_browser_download(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        if self
            .ack_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(DependencyError::Unavailable);
        }
        self.pending
            .lock()
            .unwrap()
            .retain(|entry| entry != completion);
        Ok(())
    }
    fn reject_browser_download(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        if self
            .reject_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(DependencyError::Unavailable);
        }
        self.rejected.fetch_add(1, Ordering::SeqCst);
        self.pending
            .lock()
            .unwrap()
            .retain(|entry| entry != completion);
        Ok(())
    }
}

#[derive(Default)]
struct DownloadStore {
    stored: Mutex<Vec<Vec<u8>>>,
    fail_scan: AtomicBool,
    bad_receipt: AtomicBool,
    foreign_receipt: AtomicBool,
    discarded: AtomicUsize,
    discard_failures: AtomicUsize,
    discarded_receipts: Mutex<Vec<(ArtifactStoreReceipt, OwnershipFence)>>,
    publications: Mutex<Vec<ArtifactPublication>>,
    publication_mode: AtomicUsize,
    lookup_fails: AtomicBool,
    withdrawal_fails: AtomicBool,
    withdrawals: AtomicUsize,
    scan_evidence_mode: AtomicUsize,
}

impl SandboxClient for DownloadStore {
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
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        if self.fail_scan.load(Ordering::SeqCst) {
            return Err(DependencyError::Rejected);
        }
        assert_eq!(request.source(), ArtifactContentSource::BrowserDownload);
        self.stored.lock().unwrap().push(request.bytes().to_vec());
        ArtifactStoreReceipt::new_browser_download(
            if self.foreign_receipt.load(Ordering::SeqCst) {
                ArtifactKey::new(
                    TenantId::new(),
                    request.key().session_id().clone(),
                    request.key().artifact_id().clone(),
                )
            } else {
                request.key().clone()
            },
            request.expected_size_bytes(),
            if self.bad_receipt.load(Ordering::SeqCst) {
                ArtifactChecksum::new([9; 32])
            } else {
                *request.expected_checksum()
            },
            "application/octet-stream",
            ArtifactObjectGeneration::new([1; 32]),
            ArtifactScanVerdict::Clean,
        )
        .and_then(|receipt| {
            let mode = self.scan_evidence_mode.load(Ordering::SeqCst);
            if mode == 1 {
                return Ok(receipt);
            }
            let fence = if mode == 3 {
                OwnershipFence::new(
                    request.fence().worker_id().clone(),
                    request.fence().worker_epoch() + 1,
                    request.fence().placement_version(),
                    request.fence().session_incarnation(),
                )
            } else {
                request.fence().clone()
            };
            artifact_scan_evidence::attest_test_receipt(
                receipt,
                &fence,
                if mode == 2 {
                    0
                } else {
                    SystemWorkerClock.now()?.get()
                },
            )
        })
        .map_err(|_| DependencyError::Rejected)
    }
    fn publish_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        self.publications.lock().unwrap().push(publication.clone());
        if self.publication_mode.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(DependencyError::OutcomeUncertain)
        }
    }
    fn get_retained_artifact(
        &self,
        key: &ArtifactKey,
        _: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        if self.lookup_fails.load(Ordering::SeqCst) {
            return Err(DependencyError::Unavailable);
        }
        Ok(self
            .publications
            .lock()
            .unwrap()
            .iter()
            .find(|publication| publication.key() == key)
            .cloned())
    }
    fn withdraw_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        self.withdrawals.fetch_add(1, Ordering::SeqCst);
        if self.withdrawal_fails.load(Ordering::SeqCst) {
            return Err(DependencyError::OutcomeUncertain);
        }
        self.publications
            .lock()
            .unwrap()
            .retain(|old| old != publication);
        Ok(())
    }
    fn discard_artifact(
        &self,
        receipt: &ArtifactStoreReceipt,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.discarded.fetch_add(1, Ordering::SeqCst);
        self.discarded_receipts
            .lock()
            .unwrap()
            .push((receipt.clone(), fence.clone()));
        if self
            .discard_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(DependencyError::Unavailable);
        }
        Ok(())
    }
}

struct Fixture {
    worker: WorkerControlPlane<DownloadsDriver, DownloadStore>,
    driver: Arc<DownloadsDriver>,
    store: Arc<DownloadStore>,
    peer: AuthenticatedPeer,
    created: CreateSessionOutcome,
    completion: BrowserDownloadCompletion,
    _journal: tempfile::TempDir,
}

struct DownloadFixtureClock;

impl WorkerClock for DownloadFixtureClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

fn fixture() -> Fixture {
    fixture_with_clock(Arc::new(SystemWorkerClock))
}

fn fixture_with_clock<C: WorkerClock>(clock: Arc<C>) -> Fixture {
    let journal = tempfile::tempdir().unwrap();
    let peer = AuthenticatedPeer::new("download-gateway").unwrap();
    let config = WorkerConfig::new(
        WorkerId::new("download-worker").unwrap(),
        1,
        InternalEndpoint::loopback("127.0.0.1:9022".parse().unwrap()).unwrap(),
        peer.clone(),
        4,
        4,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).unwrap(),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30)).unwrap(),
        Duration::from_secs(5),
        ActionJournalConfig::new(journal.path(), ActionJournalLimits::default()).unwrap(),
    )
    .unwrap()
    .with_artifact_limits(WorkerArtifactLimits::new(32, 64, 32).unwrap());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"download contents").unwrap();
    file.flush().unwrap();
    let driver = Arc::new(DownloadsDriver {
        pending: Mutex::new(Vec::new()),
        file,
        ack_failures: AtomicUsize::new(0),
        rejected: AtomicUsize::new(0),
        reject_failures: AtomicUsize::new(0),
    });
    let store = Arc::new(DownloadStore::default());
    let worker =
        WorkerControlPlane::new_with_clock(config, Arc::clone(&driver), Arc::clone(&store), clock);
    let tenant_id = TenantId::new();
    let created = worker
        .create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant_id.clone(),
                idempotency_key: "download-create".to_owned(),
                canonical_request_hash: [1; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(0),
        )
        .unwrap();
    let completion = BrowserDownloadCompletion {
        guid: "01234567-89ab-4cde-8fab-0123456789ab".to_owned(),
        artifact_id: ArtifactId::new(),
        tenant_id,
        session_id: created.session_id.clone(),
        fence: created.fence.clone(),
        page_id: created.primary_page_id.clone(),
        expected_size_bytes: 17,
    };
    driver.pending.lock().unwrap().push(completion.clone());
    Fixture {
        worker,
        driver,
        store,
        peer,
        created,
        completion,
        _journal: journal,
    }
}

#[test]
fn delayed_maintenance_calls_preserve_the_observed_session_clock() {
    // Only this maintenance regression uses a synthetic clock domain.
    let f = fixture_with_clock(Arc::new(DownloadFixtureClock));
    let executor = f.worker.session(&f.created.session_id).unwrap();
    assert_eq!(
        executor
            .state
            .lock()
            .unwrap()
            .machine
            .snapshot()
            .lease_expires_at,
        Some(SessionTime::new(30_000))
    );
    assert_eq!(f.worker.heartbeat(&f.peer, SessionTime::new(100)), Ok(()));
    assert_eq!(
        executor
            .state
            .lock()
            .unwrap()
            .machine
            .snapshot()
            .lease_expires_at,
        Some(SessionTime::new(30_100))
    );
    assert_eq!(f.worker.expire_due(&f.peer, SessionTime::new(90)), Ok(0));
    assert_eq!(f.worker.heartbeat(&f.peer, SessionTime::new(80)), Ok(()));
    assert_eq!(
        executor.state.lock().unwrap().machine.last_observed_at(),
        SessionTime::new(100)
    );
    assert_eq!(
        executor
            .state
            .lock()
            .unwrap()
            .machine
            .snapshot()
            .lease_expires_at,
        Some(SessionTime::new(30_100))
    );
}

#[test]
fn foreign_store_receipt_is_retained_without_foreign_delete_or_republication() {
    let f = fixture();
    f.store.foreign_receipt.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            f.worker
                .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
            Err(WorkerError::DependencyUnavailable)
        );
    }
    assert_eq!(f.store.stored.lock().unwrap().len(), 1);
    assert_eq!(f.store.discarded.load(Ordering::SeqCst), 0);
    assert_eq!(f.driver.rejected.load(Ordering::SeqCst), 0);
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let state = executor.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 17);
    assert_eq!(state.pending_download_rollbacks.len(), 1);
    assert!(state.durability_degraded);
}

#[test]
fn maintenance_publishes_downloads_without_an_artifact_list_request() {
    let f = fixture();
    assert_eq!(f.worker.reconcile_browser_downloads_due(&f.peer), Ok(1));
    let artifact = f
        .worker
        .get_artifact(
            &f.peer,
            &f.created.session_id,
            &f.completion.artifact_id,
            &f.created.fence,
        )
        .unwrap();
    assert_eq!(artifact.state, ArtifactState::Available);
    assert!(f.driver.pending.lock().unwrap().is_empty());
}

#[test]
fn download_publication_exposes_the_same_id_and_scanned_content() {
    let f = fixture();
    let listed = f
        .worker
        .list_artifacts(&f.peer, &f.created.session_id, &f.created.fence, None, 100)
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].artifact_id, f.completion.artifact_id);
    assert_eq!(listed[0].state, ArtifactState::Available);
    assert_eq!(listed[0].source, ArtifactContentSource::BrowserDownload);
    assert_eq!(listed[0].origin, "browserd-worker-download");
    assert_eq!(
        *f.store.stored.lock().unwrap(),
        [b"download contents".to_vec()]
    );
    assert!(f.driver.pending.lock().unwrap().is_empty());
    assert_eq!(
        f.worker
            .list_artifacts(
                &f.peer,
                &f.created.session_id,
                &f.created.fence,
                Some(&f.completion.artifact_id),
                100
            )
            .unwrap(),
        []
    );
}

#[test]
fn retry_after_failed_ack_never_stores_a_second_object() {
    let f = fixture();
    f.driver.ack_failures.store(1, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Ok(1)
    );
    assert_eq!(f.store.stored.lock().unwrap().len(), 1);
    let state = f.worker.session(&f.created.session_id).unwrap();
    let state = state.state.lock().unwrap();
    assert_eq!(state.artifact_committed_bytes, 17);
    assert_eq!(state.artifact_reserved_bytes, 0);
}

#[test]
fn foreign_session_completion_cannot_publish_or_delete() {
    let f = fixture();
    f.driver.pending.lock().unwrap()[0].session_id = SessionId::new();
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::StaleFence)
    );
    assert!(f.store.stored.lock().unwrap().is_empty());
    assert_eq!(f.driver.rejected.load(Ordering::SeqCst), 0);
}

#[test]
fn rejected_scan_cleans_scratch_and_releases_publication_reservation() {
    let f = fixture();
    f.store.fail_scan.store(true, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(f.driver.rejected.load(Ordering::SeqCst), 1);
    let state = f.worker.session(&f.created.session_id).unwrap();
    let state = state.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 0);
    assert_eq!(state.artifact_committed_bytes, 0);
    assert!(state.artifacts.is_empty());
}

#[test]
fn mismatched_store_receipt_rolls_back_the_exact_generation() {
    let f = fixture();
    f.store.bad_receipt.store(true, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(f.store.discarded.load(Ordering::SeqCst), 1);
    assert_eq!(f.driver.rejected.load(Ordering::SeqCst), 1);
    let state = f.worker.session(&f.created.session_id).unwrap();
    let state = state.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 0);
    assert!(state.artifacts.is_empty());
}

#[test]
fn missing_stale_or_foreign_fence_scan_evidence_never_acknowledges_download() {
    for mode in [1, 2, 3] {
        let f = fixture();
        f.store.scan_evidence_mode.store(mode, Ordering::SeqCst);
        assert_eq!(
            f.worker
                .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
            Err(WorkerError::DependencyUnavailable)
        );
        assert!(f.store.publications.lock().unwrap().is_empty());
        assert_eq!(f.store.discarded.load(Ordering::SeqCst), 1);
        assert_eq!(f.driver.rejected.load(Ordering::SeqCst), 1);
        let state = f.worker.session(&f.created.session_id).unwrap();
        let state = state.state.lock().unwrap();
        assert!(state.artifacts.is_empty());
        assert_eq!(state.artifact_reserved_bytes, 0);
        assert_eq!(state.artifact_committed_bytes, 0);
    }
}

#[test]
fn failed_rollback_retains_exact_receipt_and_quota_until_retry() {
    let f = fixture();
    f.store.bad_receipt.store(true, Ordering::SeqCst);
    f.store.discard_failures.store(1, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    {
        let executor = f.worker.session(&f.created.session_id).unwrap();
        let state = executor.state.lock().unwrap();
        assert_eq!(state.artifact_reserved_bytes, 17);
        assert_eq!(state.pending_download_rollbacks.len(), 1);
        assert!(state.artifacts.is_empty());
    }
    assert_eq!(f.driver.rejected.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Ok(0)
    );
    let discarded = f.store.discarded_receipts.lock().unwrap();
    assert_eq!(discarded.len(), 2);
    assert_eq!(discarded[0], discarded[1]);
    assert_eq!(
        discarded[0].0.key().artifact_id(),
        &f.completion.artifact_id
    );
    assert_eq!(
        discarded[0].0.object_generation(),
        ArtifactObjectGeneration::new([1; 32])
    );
    assert_eq!(discarded[0].1, f.created.fence);
    assert_eq!(f.store.stored.lock().unwrap().len(), 1);
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let state = executor.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 0);
    assert_eq!(state.artifact_committed_bytes, 0);
    assert!(state.pending_download_rollbacks.is_empty());
}

#[test]
fn scratch_cleanup_retry_does_not_repeat_confirmed_object_deletion() {
    let f = fixture();
    f.store.bad_receipt.store(true, Ordering::SeqCst);
    f.driver.reject_failures.store(1, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Ok(0)
    );
    assert_eq!(f.store.discarded.load(Ordering::SeqCst), 1);
    assert_eq!(f.store.stored.lock().unwrap().len(), 1);
    let executor = f.worker.session(&f.created.session_id).unwrap();
    assert_eq!(executor.state.lock().unwrap().artifact_reserved_bytes, 0);
}

#[test]
fn download_publication_lost_reply_adopts_exact_winner_before_ack() {
    let f = fixture();
    f.store.publication_mode.store(1, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Ok(1)
    );
    let publications = f.store.publications.lock().unwrap();
    assert_eq!(publications.len(), 1);
    let publication = &publications[0];
    assert_eq!(publication.original_fence(), &f.created.fence);
    assert_eq!(
        publication.metadata().source(),
        ArtifactContentSource::BrowserDownload
    );
    assert_eq!(publication.scan_verdict(), Some(ArtifactScanVerdict::Clean));
    assert_eq!(publication.key().artifact_id(), &f.completion.artifact_id);
    assert!(f.driver.pending.lock().unwrap().is_empty());
    assert_eq!(f.store.discarded.load(Ordering::SeqCst), 0);
    assert_eq!(f.store.withdrawals.load(Ordering::SeqCst), 0);
}
#[test]
fn download_uncertain_publication_holds_charge_until_exact_withdrawal_and_scratch_cleanup() {
    let f = fixture();
    f.store.publication_mode.store(1, Ordering::SeqCst);
    f.store.lookup_fails.store(true, Ordering::SeqCst);
    f.store.withdrawal_fails.store(true, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(f.store.discarded.load(Ordering::SeqCst), 0);
    assert_eq!(f.driver.pending.lock().unwrap().len(), 1);
    assert_eq!(f.store.publications.lock().unwrap().len(), 1);
    {
        let executor = f.worker.session(&f.created.session_id).unwrap();
        let state = executor.state.lock().unwrap();
        assert_eq!(state.artifact_reserved_bytes, 17);
        assert_eq!(state.pending_download_rollbacks.len(), 1);
        assert!(state.artifacts.is_empty());
    }
    f.store.withdrawal_fails.store(false, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Ok(0)
    );
    assert_eq!(f.store.stored.lock().unwrap().len(), 1);
    assert_eq!(f.store.discarded.load(Ordering::SeqCst), 1);
    assert!(f.store.publications.lock().unwrap().is_empty());
    assert!(f.driver.pending.lock().unwrap().is_empty());
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let state = executor.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 0);
    assert!(state.pending_download_rollbacks.is_empty());
}
#[test]
fn download_ack_retry_preserves_one_durable_publication_and_one_object_generation() {
    let f = fixture();
    f.driver.ack_failures.store(1, Ordering::SeqCst);
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::DependencyUnavailable)
    );
    let published = f.store.publications.lock().unwrap()[0].clone();
    assert_eq!(
        f.worker
            .reconcile_browser_downloads(&f.peer, &f.created.session_id, &f.created.fence),
        Ok(1)
    );
    assert_eq!(*f.store.publications.lock().unwrap(), vec![published]);
    assert_eq!(f.store.stored.lock().unwrap().len(), 1);
}
