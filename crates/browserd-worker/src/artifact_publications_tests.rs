#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use crate::*;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::mpsc;
use std::thread;

struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}
#[derive(Default)]
struct Gate {
    started: Mutex<Option<mpsc::Sender<()>>>,
    released: Mutex<bool>,
    signal: Condvar,
}
impl Gate {
    fn enter(&self) {
        if let Some(sender) = self.started.lock().unwrap().take() {
            sender.send(()).unwrap();
        }
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.signal.wait(released).unwrap();
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.signal.notify_all();
    }
}
#[derive(Default)]
struct Driver {
    effects: AtomicUsize,
    inline: AtomicBool,
    aborted: Arc<AtomicUsize>,
}
struct Sink {
    receipt: ArtifactStoreReceipt,
    aborted: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl GeneratedArtifactSink for Sink {
    async fn write_chunk(&mut self, _: &[u8]) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    async fn finish(&mut self) -> Result<ArtifactStoreReceipt, DependencyError> {
        Ok(self.receipt.clone())
    }
    async fn abort(&mut self) -> Result<(), DependencyError> {
        self.aborted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl ChromiumDriver for Driver {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(PageId::new())
    }
    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn create_page(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn close_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn activate_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
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
        Err(ApprovedActionError::DispatchRevoked)
    }
    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        Ok(true)
    }
    fn pending_browser_downloads(
        &self,
        _: &SessionId,
        _: &OwnershipFence,
        _: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, DependencyError> {
        Ok(Vec::new())
    }
    fn execute_capture_until(
        &self,
        _: &SessionId,
        _: &PageId,
        _: browserd_features::CaptureCommand,
        request: GeneratedArtifactRequest,
        _: Arc<dyn SandboxClient>,
        _: Instant,
    ) -> Result<GeneratedCaptureResult, DependencyError> {
        if self.inline.load(Ordering::SeqCst) {
            return Ok(GeneratedCaptureResult {
                result: b"inline".to_vec(),
                receipt: None,
                cleanup: None,
            });
        }
        let receipt = ArtifactStoreReceipt::new_generated(
            request.key().clone(),
            4,
            ArtifactChecksum::new([3; 32]),
            request.content_type(),
            ArtifactObjectGeneration::new([7; 32]),
        )
        .unwrap();
        Ok(GeneratedCaptureResult {
            result: serde_json::to_vec(
                &serde_json::json!({"artifact_id":request.key().artifact_id()}),
            )
            .unwrap(),
            receipt: Some(receipt.clone()),
            cleanup: Some(Box::new(Sink {
                receipt,
                aborted: self.aborted.clone(),
            })),
        })
    }
}
#[derive(Default)]
struct Store {
    publications: Mutex<HashMap<ArtifactKey, ArtifactPublication>>,
    bytes: Mutex<HashMap<ArtifactKey, Vec<u8>>>,
    writes: AtomicUsize,
    publishes: AtomicUsize,
    discards: AtomicUsize,
    withdrawals: AtomicUsize,
    lifecycle: AtomicUsize,
    mode: AtomicUsize,
    lookup_fails: AtomicBool,
    withdrawal_fails: AtomicBool,
    quarantined: AtomicBool,
    scan_evidence_mode: AtomicUsize,
    publish_gate: Mutex<Option<Arc<Gate>>>,
    store_gate: Mutex<Option<Arc<Gate>>>,
}
struct Reader(Option<Vec<u8>>);
impl ArtifactReadStream for Reader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
        Ok(self.0.take())
    }
}
impl SandboxClient for Store {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.lifecycle.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.lifecycle.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn cleanup(&self, _: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        self.lifecycle.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        self.lifecycle.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn store_artifact(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.bytes
            .lock()
            .unwrap()
            .insert(request.key().clone(), request.bytes().to_vec());
        if let Some(gate) = self.store_gate.lock().unwrap().clone() {
            gate.enter();
        }
        let receipt = ArtifactStoreReceipt::new(
            request.key().clone(),
            request.expected_size_bytes(),
            *request.expected_checksum(),
            request.declared_content_type(),
            ArtifactObjectGeneration::new([7; 32]),
            if self.quarantined.load(Ordering::SeqCst) {
                ArtifactScanVerdict::Quarantined
            } else {
                ArtifactScanVerdict::Clean
            },
        )
        .unwrap();
        let mode = self.scan_evidence_mode.load(Ordering::SeqCst);
        if mode == 1 || receipt.scan_verdict() != Some(ArtifactScanVerdict::Clean) {
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
        let attested = artifact_scan_evidence::attest_test_receipt(
            receipt,
            &fence,
            if mode == 2 { 0 } else { 1000 },
        )
        .unwrap();
        if mode == 2 {
            let mut observation = attested.scan_attestation().unwrap().observation().clone();
            observation.max_database_age_millis = 1;
            let stale = ArtifactScanAttestation::new(
                attested.key(),
                &fence,
                attested.source(),
                attested.object_generation(),
                attested.size_bytes(),
                *attested.checksum(),
                observation,
            )
            .unwrap();
            return Ok(attested.with_scan_attestation(stale).unwrap());
        }
        Ok(attested)
    }
    fn open_artifact(
        &self,
        request: &ArtifactReadRequest,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        Ok(Box::new(Reader(Some(
            self.bytes
                .lock()
                .unwrap()
                .get(request.key())
                .ok_or(DependencyError::Unavailable)?
                .clone(),
        ))))
    }
    fn publish_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = self.publish_gate.lock().unwrap().clone() {
            gate.enter();
        }
        let mode = self.mode.load(Ordering::SeqCst);
        if mode != 2 {
            self.publications
                .lock()
                .unwrap()
                .insert(publication.key().clone(), publication.clone());
        }
        if mode == 0 {
            Ok(())
        } else {
            Err(DependencyError::OutcomeUncertain)
        }
    }
    fn withdraw_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        self.withdrawals.fetch_add(1, Ordering::SeqCst);
        if self.withdrawal_fails.load(Ordering::SeqCst) {
            return Err(DependencyError::OutcomeUncertain);
        }
        let mut records = self.publications.lock().unwrap();
        if records
            .get(publication.key())
            .is_some_and(|old| old != publication)
        {
            return Err(DependencyError::Rejected);
        }
        records.remove(publication.key());
        Ok(())
    }
    fn discard_artifact(
        &self,
        receipt: &ArtifactStoreReceipt,
        _: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.discards.fetch_add(1, Ordering::SeqCst);
        self.bytes.lock().unwrap().remove(receipt.key());
        Ok(())
    }
    fn get_retained_artifact(
        &self,
        key: &ArtifactKey,
        now: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        if self.lookup_fails.load(Ordering::SeqCst) {
            return Err(DependencyError::Unavailable);
        }
        Ok(self
            .publications
            .lock()
            .unwrap()
            .get(key)
            .filter(|p| now < p.expires_at_unix_millis())
            .cloned())
    }
    fn list_retained_artifacts(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        after: Option<&ArtifactId>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        let mut records: Vec<_> = self
            .publications
            .lock()
            .unwrap()
            .values()
            .filter(|p| {
                p.key().tenant_id() == tenant
                    && p.key().session_id() == session
                    && now < p.expires_at_unix_millis()
                    && after.is_none_or(|id| p.key().artifact_id() > id)
            })
            .cloned()
            .collect();
        records.sort_by(|a, b| a.key().artifact_id().cmp(b.key().artifact_id()));
        records.truncate(limit);
        Ok(records)
    }
    fn open_retained_artifact(
        &self,
        publication: &ArtifactPublication,
        _: ArtifactReadLimits,
        _: u64,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        Ok(Box::new(Reader(Some(
            self.bytes
                .lock()
                .unwrap()
                .get(publication.key())
                .ok_or(DependencyError::Unavailable)?
                .clone(),
        ))))
    }
}
struct Fixture {
    worker: Arc<WorkerControlPlane<Driver, Store>>,
    driver: Arc<Driver>,
    store: Arc<Store>,
    clock: Arc<Clock>,
    peer: AuthenticatedPeer,
    tenant_id: TenantId,
    created: CreateSessionOutcome,
    _journal: tempfile::TempDir,
}
fn worker(
    epoch: u64,
    store: Arc<Store>,
    driver: Arc<Driver>,
    clock: Arc<Clock>,
    journal: &Path,
) -> (Arc<WorkerControlPlane<Driver, Store>>, AuthenticatedPeer) {
    let peer = AuthenticatedPeer::new("publication-gateway").unwrap();
    let config = WorkerConfig::new(
        WorkerId::new("publication-worker").unwrap(),
        epoch,
        InternalEndpoint::loopback("127.0.0.1:9041".parse().unwrap()).unwrap(),
        peer.clone(),
        4,
        4,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).unwrap(),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30)).unwrap(),
        Duration::from_secs(5),
        ActionJournalConfig::new(journal, ActionJournalLimits::default()).unwrap(),
    )
    .unwrap()
    .with_artifact_limits(WorkerArtifactLimits::new(32, 64, 32).unwrap());
    (
        Arc::new(WorkerControlPlane::new_with_clock(
            config, driver, store, clock,
        )),
        peer,
    )
}
fn fixture() -> Fixture {
    let journal = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::default());
    let driver = Arc::new(Driver::default());
    let clock = Arc::new(Clock(AtomicU64::new(1000)));
    let (worker, peer) = worker(
        1,
        store.clone(),
        driver.clone(),
        clock.clone(),
        journal.path(),
    );
    let tenant_id = TenantId::new();
    let created = worker
        .create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-publication".to_owned(),
                canonical_request_hash: [1; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(1000),
        )
        .unwrap();
    Fixture {
        worker,
        driver,
        store,
        clock,
        peer,
        tenant_id,
        created,
        _journal: journal,
    }
}
fn upload(f: &Fixture) -> Result<ArtifactId, WorkerError> {
    f.worker.upload_artifact_named(
        &f.peer,
        &f.created.session_id,
        &f.created.fence,
        ArtifactUpload {
            bytes: b"retained content".to_vec(),
            content_type: "text/plain".to_owned(),
        },
        "보고서.txt".to_owned(),
        SessionTime::new(1001),
    )
}
fn capture(f: &Fixture, key: &str) -> WorkerActionSnapshot {
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let admitted_at = executor
        .state
        .lock()
        .unwrap()
        .machine
        .last_observed_at()
        .get()
        + 1;
    f.worker
        .submit_action(
            &f.peer,
            PrincipalId::new(),
            &f.created.session_id,
            &f.created.fence,
            key,
            [2; 32],
            ActionKind::ReadOnly,
            None,
            Some(f.created.primary_page_id.clone()),
            br#"{"type":"screenshot"}"#.to_vec(),
            None,
            SessionTime::new(admitted_at),
        )
        .unwrap();
    f.worker
        .run_next_action(
            &f.peer,
            &f.created.session_id,
            &f.created.fence,
            SessionTime::new(admitted_at + 1),
        )
        .unwrap()
        .unwrap()
}
#[test]
fn upload_publication_is_durable_before_available_and_survives_without_a_live_session() {
    let f = fixture();
    let id = upload(&f).unwrap();
    let key = ArtifactKey::new(
        f.tenant_id.clone(),
        f.created.session_id.clone(),
        id.clone(),
    );
    let expected = f
        .store
        .publications
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .clone();
    assert!(expected.scan_attestation().is_some());
    assert_eq!(
        f.worker
            .get_artifact(&f.peer, &f.created.session_id, &id, &f.created.fence)
            .unwrap()
            .display_filename
            .as_deref(),
        Some("보고서.txt")
    );
    let restart = tempfile::tempdir().unwrap();
    let (restarted, peer) = worker(
        5,
        f.store.clone(),
        f.driver.clone(),
        f.clock.clone(),
        restart.path(),
    );
    assert_eq!(
        restarted.get_session(&peer, &f.created.session_id, &f.created.fence),
        Err(WorkerError::SessionNotFound)
    );
    let effects = f.driver.effects.load(Ordering::SeqCst);
    let lifecycle = f.store.lifecycle.load(Ordering::SeqCst);
    let found = restarted
        .get_retained_artifact(&peer, expected.original_fence().worker_id(), 5, &key)
        .unwrap();
    assert_eq!(found, expected);
    assert_eq!(
        restarted
            .list_retained_artifacts(
                &peer,
                expected.original_fence().worker_id(),
                5,
                key.tenant_id(),
                key.session_id(),
                None,
                101
            )
            .unwrap(),
        vec![expected.clone()]
    );
    let mut reader = restarted
        .open_retained_artifact(
            &peer,
            expected.original_fence().worker_id(),
            5,
            &expected,
            64 * 1024,
        )
        .unwrap();
    assert_eq!(
        reader.next_chunk().unwrap(),
        Some(b"retained content".to_vec())
    );
    assert_eq!(reader.next_chunk().unwrap(), None);
    assert_eq!(f.driver.effects.load(Ordering::SeqCst), effects);
    assert_eq!(f.store.lifecycle.load(Ordering::SeqCst), lifecycle);
}

#[test]
fn missing_stale_or_foreign_fence_scan_evidence_never_publishes_available_upload() {
    for mode in [1, 2, 3] {
        let f = fixture();
        f.store.scan_evidence_mode.store(mode, Ordering::SeqCst);
        assert_eq!(upload(&f), Err(WorkerError::DependencyUnavailable));
        assert_eq!(f.store.publishes.load(Ordering::SeqCst), 0);
        assert_eq!(f.store.discards.load(Ordering::SeqCst), 1);
        let state = f.worker.session(&f.created.session_id).unwrap();
        let state = state.state.lock().unwrap();
        assert!(state.artifacts.is_empty());
        assert_eq!(state.artifact_reserved_bytes, 0);
        assert_eq!(state.artifact_committed_bytes, 0);
    }
}
#[test]
fn upload_quarantine_stays_live_only() {
    let f = fixture();
    f.store.quarantined.store(true, Ordering::SeqCst);
    let id = upload(&f).unwrap();
    assert_eq!(
        f.worker
            .get_artifact(&f.peer, &f.created.session_id, &id, &f.created.fence)
            .unwrap()
            .state,
        ArtifactState::Quarantined
    );
    assert_eq!(f.store.publishes.load(Ordering::SeqCst), 0);
    assert!(f.store.publications.lock().unwrap().is_empty());
}
#[test]
fn publish_commit_then_error_is_adopted_exactly_without_deletion() {
    let f = fixture();
    f.store.mode.store(1, Ordering::SeqCst);
    let id = upload(&f).unwrap();
    assert!(
        f.worker
            .get_artifact(&f.peer, &f.created.session_id, &id, &f.created.fence)
            .is_ok()
    );
    assert_eq!(f.store.discards.load(Ordering::SeqCst), 0);
    assert_eq!(f.store.withdrawals.load(Ordering::SeqCst), 0);
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let state = executor.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 0);
    assert_eq!(state.artifact_committed_bytes, 16);
}
#[test]
fn uncertain_publication_without_exact_read_or_withdrawal_holds_bytes_and_charge() {
    let f = fixture();
    f.store.mode.store(1, Ordering::SeqCst);
    f.store.lookup_fails.store(true, Ordering::SeqCst);
    f.store.withdrawal_fails.store(true, Ordering::SeqCst);
    assert_eq!(upload(&f), Err(WorkerError::DependencyUnavailable));
    assert_eq!(f.store.discards.load(Ordering::SeqCst), 0);
    assert_eq!(f.store.bytes.lock().unwrap().len(), 1);
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let state = executor.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 16);
    assert_eq!(state.artifact_committed_bytes, 0);
    assert!(state.artifacts.is_empty());
    assert!(state.durability_degraded);
}
#[test]
fn known_withdrawal_precedes_generation_discard_after_failed_publication() {
    let f = fixture();
    f.store.mode.store(2, Ordering::SeqCst);
    assert_eq!(upload(&f), Err(WorkerError::DependencyUnavailable));
    assert_eq!(f.store.withdrawals.load(Ordering::SeqCst), 1);
    assert_eq!(f.store.discards.load(Ordering::SeqCst), 1);
    assert!(f.store.bytes.lock().unwrap().is_empty());
    let executor = f.worker.session(&f.created.session_id).unwrap();
    assert_eq!(executor.state.lock().unwrap().artifact_reserved_bytes, 0);
}
#[test]
fn close_cannot_change_authority_during_publication() {
    let f = fixture();
    let (sent, received) = mpsc::channel();
    let gate = Arc::new(Gate {
        started: Mutex::new(Some(sent)),
        ..Gate::default()
    });
    *f.store.publish_gate.lock().unwrap() = Some(gate.clone());
    let worker = f.worker.clone();
    let peer = f.peer.clone();
    let created = f.created.clone();
    let upload = thread::spawn(move || {
        worker.upload_artifact_named(
            &peer,
            &created.session_id,
            &created.fence,
            ArtifactUpload {
                bytes: b"retained content".to_vec(),
                content_type: "text/plain".to_owned(),
            },
            "report.txt".to_owned(),
            SessionTime::new(1001),
        )
    });
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    let executor = f.worker.session(&f.created.session_id).unwrap();
    assert!(executor.state.try_lock().is_err());
    let worker = f.worker.clone();
    let peer = f.peer.clone();
    let created = f.created.clone();
    let (done, completed) = mpsc::channel();
    let closing = thread::spawn(move || {
        let result = worker.close_session(
            &peer,
            &created.session_id,
            &created.fence,
            SessionTime::new(1002),
        );
        done.send(()).unwrap();
        result
    });
    assert!(completed.recv_timeout(Duration::from_millis(50)).is_err());
    gate.release();
    assert!(upload.join().unwrap().is_ok());
    assert!(closing.join().unwrap().is_ok());
    assert_eq!(f.store.publishes.load(Ordering::SeqCst), 1);
}
#[test]
fn closing_before_publication_rejects_staged_bytes_without_publishing() {
    let f = fixture();
    let (sent, received) = mpsc::channel();
    let gate = Arc::new(Gate {
        started: Mutex::new(Some(sent)),
        ..Gate::default()
    });
    *f.store.store_gate.lock().unwrap() = Some(gate.clone());
    let worker = f.worker.clone();
    let peer = f.peer.clone();
    let created = f.created.clone();
    let upload = thread::spawn(move || {
        worker.upload_artifact(
            &peer,
            &created.session_id,
            &created.fence,
            ArtifactUpload {
                bytes: b"staged".to_vec(),
                content_type: "text/plain".to_owned(),
            },
            SessionTime::new(1001),
        )
    });
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    let executor = f.worker.session(&f.created.session_id).unwrap();
    {
        let mut state = executor.state.lock().unwrap();
        state
            .machine
            .begin_close(&f.created.fence, SessionTime::new(1002))
            .unwrap();
    }
    gate.release();
    assert_eq!(
        upload.join().unwrap(),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(f.store.publishes.load(Ordering::SeqCst), 0);
    assert_eq!(f.store.discards.load(Ordering::SeqCst), 1);
}
#[test]
fn generated_capture_publishes_but_inline_result_has_no_publication() {
    let f = fixture();
    assert_eq!(capture(&f, "generated").status, ActionStatus::Succeeded);
    assert_eq!(f.store.publishes.load(Ordering::SeqCst), 1);
    let publication = f
        .store
        .publications
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(
        publication.metadata().source(),
        ArtifactContentSource::Generated
    );
    assert_eq!(publication.scan_verdict(), None);
    f.driver.inline.store(true, Ordering::SeqCst);
    assert_eq!(capture(&f, "inline").status, ActionStatus::Succeeded);
    assert_eq!(f.store.publishes.load(Ordering::SeqCst), 1);
    assert_eq!(f.driver.aborted.load(Ordering::SeqCst), 0);
}
#[test]
fn generated_uncertain_publication_never_aborts_published_generation() {
    let f = fixture();
    f.store.mode.store(1, Ordering::SeqCst);
    f.store.lookup_fails.store(true, Ordering::SeqCst);
    f.store.withdrawal_fails.store(true, Ordering::SeqCst);
    assert_eq!(capture(&f, "unknown").status, ActionStatus::FailedKnown);
    assert_eq!(f.driver.aborted.load(Ordering::SeqCst), 0);
    let executor = f.worker.session(&f.created.session_id).unwrap();
    let state = executor.state.lock().unwrap();
    assert_eq!(state.artifact_reserved_bytes, 32);
    assert!(state.artifacts.is_empty());
}
#[test]
fn retained_scope_expiry_and_changed_publication_fail_closed() {
    let f = fixture();
    let id = upload(&f).unwrap();
    let key = ArtifactKey::new(f.tenant_id.clone(), f.created.session_id.clone(), id);
    let publication = f
        .store
        .publications
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .clone();
    let worker_id = publication.original_fence().worker_id();
    assert_eq!(
        f.worker
            .get_retained_artifact(&f.peer, &WorkerId::new("wrong-worker").unwrap(), 1, &key),
        Err(WorkerError::StaleFence)
    );
    assert_eq!(
        f.worker.get_retained_artifact(&f.peer, worker_id, 2, &key),
        Err(WorkerError::StaleFence)
    );
    assert_eq!(
        f.worker.get_retained_artifact(
            &AuthenticatedPeer::new("untrusted").unwrap(),
            worker_id,
            1,
            &key
        ),
        Err(WorkerError::UnauthorizedPeer)
    );
    let mut wire = ArtifactPublicationWire::from_publication(&publication);
    wire.artifact.display_filename = Some("changed.txt".to_owned());
    let changed = wire.to_publication().unwrap();
    assert!(matches!(
        f.worker
            .open_retained_artifact(&f.peer, worker_id, 1, &changed, 64 * 1024),
        Err(WorkerError::StaleFence)
    ));
    assert_eq!(
        f.worker.list_retained_artifacts(
            &f.peer,
            worker_id,
            1,
            key.tenant_id(),
            key.session_id(),
            None,
            102
        ),
        Err(WorkerError::InvalidConfiguration)
    );
    f.clock
        .0
        .store(publication.expires_at_unix_millis(), Ordering::SeqCst);
    assert_eq!(
        f.worker.get_retained_artifact(&f.peer, worker_id, 1, &key),
        Err(WorkerError::ArtifactNotFound)
    );
}
#[test]
fn publication_wire_validates_full_origin_name_scan_and_ttl() {
    let f = fixture();
    upload(&f).unwrap();
    let publication = f
        .store
        .publications
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let wire = ArtifactPublicationWire::from_publication(&publication);
    assert_eq!(wire.to_publication().unwrap(), publication);
    for case in 0..8 {
        let mut changed = wire.clone();
        match case {
            0 => changed.artifact.state = WorkerArtifactState::Quarantined,
            1 => changed.scan_verdict = None,
            2 => changed.artifact.fence.worker_epoch = 0,
            3 => changed.artifact.fence.placement_version = 0,
            4 => changed.artifact.fence.session_incarnation = 0,
            5 => changed.artifact.object_generation = [0; 32],
            6 => changed.artifact.display_filename = Some("../secret".to_owned()),
            _ => {
                changed.expires_at_unix_millis =
                    changed.published_at_unix_millis + ARTIFACT_PUBLICATION_TTL_MILLIS + 1
            }
        };
        assert!(changed.to_publication().is_err(), "case {case}");
    }
    let mut value = serde_json::to_value(&wire).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ArtifactPublicationWire>(value).is_err());
    let mut old = serde_json::to_value(&wire.artifact).unwrap();
    old.as_object_mut().unwrap().remove("display_filename");
    assert_eq!(
        serde_json::from_value::<WorkerArtifactReceipt>(old)
            .unwrap()
            .display_filename,
        None
    );
}
#[tokio::test]
async fn retained_rpc_without_session_enforces_serving_identity_and_scope() {
    let f = fixture();
    let id = upload(&f).unwrap();
    let publication = f
        .store
        .publications
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let restart = tempfile::tempdir().unwrap();
    let (worker, peer) = worker(
        5,
        f.store.clone(),
        f.driver.clone(),
        f.clock.clone(),
        restart.path(),
    );
    let handler = WorkerControlPlaneRpcHandler::new(worker.clone(), peer);
    let scope = WorkerRetainedArtifactScope {
        worker_id: publication.original_fence().worker_id().clone(),
        worker_epoch: 5,
        tenant_id: publication.key().tenant_id().clone(),
        session_id: publication.key().session_id().clone(),
    };
    let receipt = match handler
        .handle(WorkerRpcRequest::GetRetainedArtifact {
            scope: scope.clone(),
            artifact_id: id.clone(),
        })
        .await
    {
        WorkerRpcResponse::RetainedArtifact(receipt) => receipt,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(receipt.publication.to_publication().unwrap(), publication);
    let stream_id = match handler
        .handle(WorkerRpcRequest::OpenRetainedArtifact {
            scope: scope.clone(),
            publication: receipt.publication,
            max_chunk_bytes: 64 * 1024,
        })
        .await
    {
        WorkerRpcResponse::RetainedArtifactOpened { receipt, stream_id } => {
            assert_eq!(receipt.serving_worker_epoch, 5);
            stream_id
        }
        other => panic!("unexpected {other:?}"),
    };
    let mut foreign = scope.clone();
    foreign.tenant_id = TenantId::new();
    assert!(matches!(
        handler
            .handle(WorkerRpcRequest::ReadRetainedArtifact {
                scope: foreign,
                stream_id: stream_id.clone(),
                sequence: 0
            })
            .await,
        WorkerRpcResponse::Failure(_)
    ));
    assert!(
        matches!(handler.handle(WorkerRpcRequest::ReadRetainedArtifact{scope:scope.clone(),stream_id:stream_id.clone(),sequence:0}).await,WorkerRpcResponse::RetainedArtifactChunk{bytes,end:false,..} if bytes==b"retained content")
    );
    assert!(
        matches!(handler.handle(WorkerRpcRequest::ReadRetainedArtifact{scope:scope.clone(),stream_id:stream_id.clone(),sequence:1}).await,WorkerRpcResponse::RetainedArtifactChunk{bytes,end:true,..} if bytes.is_empty())
    );
    let mut wrong = scope;
    wrong.worker_epoch = 1;
    assert!(matches!(
        handler
            .handle(WorkerRpcRequest::GetRetainedArtifact {
                scope: wrong,
                artifact_id: id
            })
            .await,
        WorkerRpcResponse::Failure(WorkerRpcFailure {
            code: WorkerRpcFailureCode::FenceMismatch,
            ..
        })
    ));
    assert!(worker.lock_worker().unwrap().sessions.is_empty());
}

#[test]
fn live_metadata_pagination_and_stream_cannot_bypass_publication_expiry() {
    let f = fixture();
    let first = upload(&f).unwrap();
    let publication = f
        .store
        .publications
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let mut stream = f
        .worker
        .open_artifact(
            &f.peer,
            &f.created.session_id,
            &first,
            &f.created.fence,
            64 * 1024,
        )
        .unwrap();
    f.clock
        .0
        .store(publication.expires_at_unix_millis() - 1, Ordering::SeqCst);
    let second = f
        .worker
        .upload_artifact(
            &f.peer,
            &f.created.session_id,
            &f.created.fence,
            ArtifactUpload {
                bytes: b"fresh".to_vec(),
                content_type: "text/plain".to_owned(),
            },
            SessionTime::new(1002),
        )
        .unwrap();
    f.clock
        .0
        .store(publication.expires_at_unix_millis(), Ordering::SeqCst);
    assert_eq!(
        f.worker
            .get_artifact(&f.peer, &f.created.session_id, &first, &f.created.fence),
        Err(WorkerError::ArtifactNotFound)
    );
    assert!(matches!(
        f.worker.open_artifact(
            &f.peer,
            &f.created.session_id,
            &first,
            &f.created.fence,
            64 * 1024
        ),
        Err(WorkerError::ArtifactNotFound)
    ));
    assert!(stream.next_chunk().is_err());
    let page = f
        .worker
        .list_artifacts(&f.peer, &f.created.session_id, &f.created.fence, None, 1)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].artifact_id, second);
}
