#![allow(clippy::expect_used)]

use crate::*;

#[derive(Clone)]
struct ReadPlan {
    generation: ArtifactObjectGeneration,
    chunks: Vec<Result<Vec<u8>, DependencyError>>,
}

type ReadHook = Arc<dyn Fn() + Send + Sync>;

struct Reader {
    chunks: VecDeque<Result<Vec<u8>, DependencyError>>,
    hook: Option<ReadHook>,
}

impl ArtifactReadStream for Reader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
        if let Some(hook) = self.hook.take() {
            hook();
        }
        self.chunks.pop_front().transpose()
    }
}

#[derive(Default)]
struct AttachmentStore {
    objects: Mutex<HashMap<ArtifactKey, ReadPlan>>,
    requests: Mutex<Vec<ArtifactReadRequest>>,
    open_hook: Mutex<Option<ReadHook>>,
    hook: Mutex<Option<ReadHook>>,
}

impl SandboxClient for AttachmentStore {
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
        _: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn open_artifact(
        &self,
        request: &ArtifactReadRequest,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        self.requests
            .lock()
            .expect("read requests")
            .push(request.clone());
        let open_hook = self.open_hook.lock().expect("open hook").clone();
        if let Some(hook) = open_hook {
            hook();
        }
        let plan = self
            .objects
            .lock()
            .expect("objects")
            .get(request.key())
            .cloned()
            .ok_or(DependencyError::Rejected)?;
        if plan.generation != request.generation() {
            return Err(DependencyError::Rejected);
        }
        Ok(Box::new(Reader {
            chunks: plan.chunks.into(),
            hook: self.hook.lock().expect("read hook").clone(),
        }))
    }
}

struct Dispatch {
    session: SessionId,
    page: PageId,
    fence: OwnershipFence,
    node_ref: String,
    files: Vec<BrowserFileAttachment>,
    deadline: Instant,
}

struct AttachmentDriver {
    calls: Mutex<Vec<Dispatch>>,
    generic_calls: std::sync::atomic::AtomicUsize,
    outcome: ActionExecutionResult,
    hook: Mutex<Option<ReadHook>>,
}

impl ChromiumDriver for AttachmentDriver {
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
        self.generic_calls.fetch_add(1, Ordering::SeqCst);
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
    fn execute_file_attachment_until(
        &self,
        session: &SessionId,
        page: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        files: Vec<BrowserFileAttachment>,
        deadline: Instant,
    ) -> ActionExecutionResult {
        let hook = self.hook.lock().expect("driver hook").clone();
        if let Some(hook) = hook {
            hook();
        }
        self.calls.lock().expect("dispatches").push(Dispatch {
            session: session.clone(),
            page: page.clone(),
            fence: fence.clone(),
            node_ref: node_ref.to_owned(),
            files,
            deadline,
        });
        self.outcome.clone()
    }
}

struct Fixture {
    worker: WorkerControlPlane<AttachmentDriver, AttachmentStore>,
    executor: Arc<SessionExecutor>,
    driver: Arc<AttachmentDriver>,
    store: Arc<AttachmentStore>,
    created: CreateSessionOutcome,
    peer: AuthenticatedPeer,
    _journal: tempfile::TempDir,
}

impl Fixture {
    fn new(outcome: ActionExecutionResult, limits: WorkerArtifactLimits) -> Self {
        let journal = tempfile::tempdir().expect("journal directory");
        let peer = AuthenticatedPeer::new("attachment-gateway").expect("peer");
        let config = WorkerConfig::new(
            WorkerId::new("attachment-worker").expect("worker"),
            3,
            InternalEndpoint::loopback("127.0.0.1:9100".parse().expect("address"))
                .expect("endpoint"),
            peer.clone(),
            4,
            16,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).expect("lease"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
                .expect("timeouts"),
            Duration::from_secs(5),
            ActionJournalConfig::with_default_limits(journal.path()).expect("journal"),
        )
        .expect("config")
        .with_artifact_limits(limits);
        let driver = Arc::new(AttachmentDriver {
            calls: Mutex::new(Vec::new()),
            generic_calls: std::sync::atomic::AtomicUsize::new(0),
            outcome,
            hook: Mutex::new(None),
        });
        let store = Arc::new(AttachmentStore::default());
        let worker = WorkerControlPlane::new(config, driver.clone(), store.clone());
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: TenantId::new(),
                    idempotency_key: "attachment-create".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(0),
            )
            .expect("session");
        let executor = worker.session(&created.session_id).expect("executor");
        Self {
            worker,
            executor,
            driver,
            store,
            created,
            peer,
            _journal: journal,
        }
    }

    fn ready() -> Self {
        Self::new(
            ActionExecutionResult::Succeeded(b"attached".to_vec()),
            WorkerArtifactLimits::default(),
        )
    }

    fn insert(&self, bytes: &[u8], filename: Option<&str>, state: ArtifactState) -> ArtifactId {
        self.insert_declared(bytes, bytes.len() as u64, filename, state)
    }

    fn insert_declared(
        &self,
        bytes: &[u8],
        declared: u64,
        filename: Option<&str>,
        state: ArtifactState,
    ) -> ArtifactId {
        let id = ArtifactId::new();
        let mut session = self.executor.state.lock().expect("session state");
        let key = ArtifactKey::new(
            session.tenant_id.clone(),
            self.created.session_id.clone(),
            id.clone(),
        );
        let metadata = ArtifactContentMetadata::new(
            declared,
            ArtifactChecksum::new(Sha256::digest(bytes).into()),
            "application/octet-stream",
            ArtifactContentSource::ClientUpload,
            "browserd-worker-upload",
        )
        .expect("metadata");
        let generation = ArtifactObjectGeneration::new([7; 32]);
        let mut artifact = Artifact::new_upload(key.clone());
        artifact
            .apply_materialized(ArtifactEvent::UploadStored, metadata)
            .expect("stored");
        if state != ArtifactState::Stored {
            artifact
                .apply(ArtifactEvent::ScanStarted)
                .expect("scan started");
            artifact
                .apply(
                    match state {
                        ArtifactState::Available => Some(ArtifactEvent::ScanPassed),
                        ArtifactState::Quarantined => Some(ArtifactEvent::ScanQuarantined),
                        ArtifactState::Rejected => Some(ArtifactEvent::ScanRejected),
                        _ => None,
                    }
                    .expect("supported test state"),
                )
                .expect("scan verdict");
        }
        session.artifacts.insert(
            id.clone(),
            ArtifactRecord {
                publication: if state == ArtifactState::Available {
                    Some(
                        self.worker
                            .new_artifact_publication(
                                key.clone(),
                                self.created.fence.clone(),
                                artifact
                                    .content_metadata()
                                    .expect("materialized metadata")
                                    .clone(),
                                generation,
                                Some(ArtifactScanVerdict::Clean),
                                filename
                                    .filter(|name| valid_artifact_display_filename(name))
                                    .map(ToOwned::to_owned),
                                Some({
                                    let metadata = artifact.content_metadata().expect("metadata");
                                    let receipt = ArtifactStoreReceipt::new(
                                        key.clone(),
                                        metadata.size_bytes(),
                                        *metadata.checksum(),
                                        metadata.content_type(),
                                        generation,
                                        ArtifactScanVerdict::Clean,
                                    )
                                    .expect("fixture receipt");
                                    artifact_scan_evidence::attest_test_receipt(
                                        receipt,
                                        &self.created.fence,
                                        self.worker.clock.now().expect("clock").get(),
                                    )
                                    .expect("fixture scan evidence")
                                    .scan_attestation()
                                    .expect("attestation")
                                    .clone()
                                }),
                            )
                            .expect("publication"),
                    )
                } else {
                    None
                },
                artifact,
                object_generation: generation,
                display_filename: filename.map(ToOwned::to_owned),
            },
        );
        self.store.objects.lock().expect("objects").insert(
            key,
            ReadPlan {
                generation,
                chunks: bytes.chunks(2).map(|chunk| Ok(chunk.to_vec())).collect(),
            },
        );
        id
    }

    fn execute(&self, ids: &[ArtifactId]) -> ActionExecutionResult {
        self.worker.execute_file_attachments(
            &self.created.session_id,
            &self.created.primary_page_id,
            &self.created.fence,
            "node-input",
            ids,
            Instant::now() + Duration::from_secs(2),
            &self.executor,
        )
    }

    fn assert_no_dispatch(&self, outcome: ActionExecutionResult) {
        assert!(
            matches!(outcome, ActionExecutionResult::FailedKnown(_)),
            "{outcome:?}"
        );
        assert!(self.driver.calls.lock().expect("dispatches").is_empty());
    }
}

#[test]
fn file_attachments_dispatch_exact_verified_bytes_names_and_owned_metadata() {
    let f = Fixture::ready();
    let first = f.insert(b"hello", Some("한글 input.txt"), ArtifactState::Available);
    let second = f.insert(b"world!", None, ArtifactState::Available);
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(
        f.worker.execute_file_attachments(
            &f.created.session_id,
            &f.created.primary_page_id,
            &f.created.fence,
            "node-input",
            &[first.clone(), second.clone()],
            deadline,
            &f.executor
        ),
        ActionExecutionResult::Succeeded(b"attached".to_vec())
    );
    let calls = f.driver.calls.lock().expect("dispatches");
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.session, f.created.session_id);
    assert_eq!(call.page, f.created.primary_page_id);
    assert_eq!(call.fence, f.created.fence);
    assert_eq!(call.node_ref, "node-input");
    assert_eq!(call.deadline, deadline);
    assert_eq!(call.files.len(), 2);
    let reads = f.store.requests.lock().expect("reads");
    assert_eq!(reads.len(), 2);
    for (index, (id, bytes)) in [
        (first, b"hello".as_slice()),
        (second.clone(), b"world!".as_slice()),
    ]
    .iter()
    .enumerate()
    {
        let file = &call.files[index];
        assert_eq!(file.key(), reads[index].key());
        assert_eq!(file.key().artifact_id(), id);
        assert_eq!(file.fence(), &f.created.fence);
        assert_eq!(reads[index].fence(), &f.created.fence);
        assert_eq!(file.generation(), reads[index].generation());
        assert_eq!(file.generation(), ArtifactObjectGeneration::new([7; 32]));
        assert_eq!(
            file.checksum(),
            &ArtifactChecksum::new(Sha256::digest(bytes).into())
        );
        assert_eq!(file.bytes(), *bytes);
        assert!((1..=64 * 1024).contains(&reads[index].limits().max_chunk_bytes()));
    }
    assert_eq!(call.files[0].display_filename(), "한글 input.txt");
    assert_eq!(call.files[1].display_filename(), format!("{second}.bin"));
}

#[test]
fn file_attachments_accept_empty_files_and_preserve_driver_outcome() {
    for outcome in [
        ActionExecutionResult::OutcomeUnknown,
        ActionExecutionResult::FailedKnown("node_stale".to_owned()),
        ActionExecutionResult::Succeeded(Vec::new()),
    ] {
        let f = Fixture::new(outcome.clone(), WorkerArtifactLimits::default());
        let id = f.insert(b"", Some("empty.txt"), ArtifactState::Available);
        assert_eq!(f.execute(&[id]), outcome);
        let calls = f.driver.calls.lock().expect("dispatches");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].files[0].bytes().is_empty());
        assert_eq!(
            calls[0].files[0].checksum(),
            &ArtifactChecksum::new(Sha256::digest(b"").into())
        );
    }
}

#[test]
fn file_attachments_reject_empty_duplicate_and_over_limit_ids_before_io() {
    for count in [0, 2, 129] {
        let f = Fixture::ready();
        let id = f.insert(b"a", None, ArtifactState::Available);
        let ids = if count == 129 {
            (0..129).map(|_| ArtifactId::new()).collect()
        } else {
            vec![id; count]
        };
        f.assert_no_dispatch(f.execute(&ids));
        assert!(f.store.requests.lock().expect("reads").is_empty());
    }
}

#[test]
fn file_attachments_accept_the_bounded_maximum_of_128_empty_files() {
    let f = Fixture::ready();
    let ids: Vec<_> = (0..128)
        .map(|_| f.insert(b"", None, ArtifactState::Available))
        .collect();
    assert!(matches!(
        f.execute(&ids),
        ActionExecutionResult::Succeeded(_)
    ));
    assert_eq!(
        f.driver.calls.lock().expect("dispatches")[0].files.len(),
        128
    );
}

#[test]
fn file_attachments_reject_file_and_aggregate_size_claims_before_io() {
    for (limits, sizes) in [
        (WorkerArtifactLimits::default(), vec![8 * 1024 * 1024 + 1]),
        (
            WorkerArtifactLimits::default(),
            vec![4 * 1024 * 1024, 4 * 1024 * 1024 + 1],
        ),
        (WorkerArtifactLimits::new(2, 8, 4).expect("limits"), vec![3]),
        (
            WorkerArtifactLimits::new(3, 8, 4).expect("limits"),
            vec![3, 2],
        ),
    ] {
        let f = Fixture::new(ActionExecutionResult::OutcomeUnknown, limits);
        let ids: Vec<_> = sizes
            .into_iter()
            .map(|size| f.insert_declared(b"", size, None, ArtifactState::Available))
            .collect();
        f.assert_no_dispatch(f.execute(&ids));
        assert!(f.store.requests.lock().expect("reads").is_empty());
    }
}

#[test]
fn file_attachments_reject_unavailable_missing_and_foreign_artifacts_before_io() {
    for state in [
        ArtifactState::Stored,
        ArtifactState::Quarantined,
        ArtifactState::Rejected,
    ] {
        let f = Fixture::ready();
        let id = f.insert(b"a", None, state);
        f.assert_no_dispatch(f.execute(&[id]));
        assert!(f.store.requests.lock().expect("reads").is_empty());
    }
    let f = Fixture::ready();
    f.assert_no_dispatch(f.execute(&[ArtifactId::new()]));
    assert!(f.store.requests.lock().expect("reads").is_empty());
    for wrong_tenant in [true, false] {
        let f = Fixture::ready();
        let id = f.insert(b"a", None, ArtifactState::Available);
        let mut session = f.executor.state.lock().expect("state");
        let old = session
            .artifacts
            .get(&id)
            .expect("record")
            .artifact
            .content_metadata()
            .expect("metadata")
            .clone();
        let key = ArtifactKey::new(
            if wrong_tenant {
                TenantId::new()
            } else {
                session.tenant_id.clone()
            },
            if wrong_tenant {
                f.created.session_id.clone()
            } else {
                SessionId::new()
            },
            id.clone(),
        );
        let mut artifact = Artifact::new_upload(key);
        artifact
            .apply_materialized(ArtifactEvent::UploadStored, old)
            .expect("stored");
        artifact.apply(ArtifactEvent::ScanStarted).expect("scan");
        artifact.apply(ArtifactEvent::ScanPassed).expect("clean");
        session.artifacts.get_mut(&id).expect("record").artifact = artifact;
        drop(session);
        f.assert_no_dispatch(f.execute(&[id]));
        assert!(f.store.requests.lock().expect("reads").is_empty());
    }
}

#[test]
fn file_attachments_reject_unsafe_display_names_before_io() {
    let oversized = "x".repeat(256);
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "dir/file.txt",
        "C:\\outside",
        "bad\0name",
        "line\nname",
        oversized.as_str(),
    ] {
        let f = Fixture::ready();
        let id = f.insert(b"a", Some(name), ArtifactState::Available);
        f.assert_no_dispatch(f.execute(&[id]));
        assert!(f.store.requests.lock().expect("reads").is_empty());
    }
}

#[test]
fn file_attachments_reject_missing_or_wrong_generations() {
    for generation in [
        ArtifactObjectGeneration::new([0; 32]),
        ArtifactObjectGeneration::new([8; 32]),
    ] {
        let f = Fixture::ready();
        let id = f.insert(b"a", None, ArtifactState::Available);
        f.executor
            .state
            .lock()
            .expect("state")
            .artifacts
            .get_mut(&id)
            .expect("record")
            .object_generation = generation;
        f.assert_no_dispatch(f.execute(&[id]));
    }
}

#[test]
fn file_attachments_reject_short_extra_corrupted_failed_and_empty_chunks() {
    for chunks in [
        vec![Ok(b"ab".to_vec())],
        vec![Ok(b"abcd".to_vec())],
        vec![Ok(b"abd".to_vec())],
        vec![Err(DependencyError::Unavailable)],
        vec![Ok(Vec::new())],
    ] {
        let f = Fixture::ready();
        let id = f.insert(b"abc", None, ArtifactState::Available);
        f.store
            .objects
            .lock()
            .expect("objects")
            .values_mut()
            .next()
            .expect("object")
            .chunks = chunks;
        f.assert_no_dispatch(f.execute(&[id]));
    }
    let f = Fixture::ready();
    let bytes = vec![1; 64 * 1024 + 1];
    let id = f.insert(&bytes, None, ArtifactState::Available);
    f.store
        .objects
        .lock()
        .expect("objects")
        .values_mut()
        .next()
        .expect("object")
        .chunks = vec![Ok(bytes)];
    f.assert_no_dispatch(f.execute(&[id]));
}

#[test]
fn file_attachments_recheck_deadline_after_reads_and_reject_initial_expiry() {
    let f = Fixture::ready();
    let id = f.insert(b"abc", None, ArtifactState::Available);
    assert_eq!(
        f.worker.execute_file_attachments(
            &f.created.session_id,
            &f.created.primary_page_id,
            &f.created.fence,
            "node-input",
            std::slice::from_ref(&id),
            Instant::now(),
            &f.executor
        ),
        ActionExecutionResult::FailedKnown("action_timeout".to_owned())
    );
    assert!(f.store.requests.lock().expect("reads").is_empty());
    *f.store.hook.lock().expect("hook") =
        Some(Arc::new(|| std::thread::sleep(Duration::from_millis(70))));
    assert_eq!(
        f.worker.execute_file_attachments(
            &f.created.session_id,
            &f.created.primary_page_id,
            &f.created.fence,
            "node-input",
            &[id],
            Instant::now() + Duration::from_millis(50),
            &f.executor
        ),
        ActionExecutionResult::FailedKnown("action_timeout".to_owned())
    );
    assert!(f.driver.calls.lock().expect("dispatches").is_empty());
    assert_eq!(f.store.requests.lock().expect("reads").len(), 1);
}

#[test]
fn file_attachments_release_state_for_io_and_keep_cleanup_owned_through_driver_dispatch() {
    let f = Fixture::ready();
    let id = f.insert(b"abc", None, ArtifactState::Available);
    let executor = Arc::downgrade(&f.executor);
    let observations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = observations.clone();
    let hook: ReadHook = Arc::new(move || {
        let executor = executor.upgrade().expect("executor");
        assert!(
            executor.state.try_lock().is_ok(),
            "state cannot be held across I/O or driver dispatch"
        );
        assert!(
            executor.cleanup_owner.try_lock().is_err(),
            "cleanup owns preparation and dispatch"
        );
        observed.fetch_add(1, Ordering::SeqCst);
    });
    *f.store.open_hook.lock().expect("open hook") = Some(hook.clone());
    *f.store.hook.lock().expect("read hook") = Some(hook.clone());
    *f.driver.hook.lock().expect("driver hook") = Some(hook);
    assert!(matches!(
        f.execute(&[id]),
        ActionExecutionResult::Succeeded(_)
    ));
    assert_eq!(observations.load(Ordering::SeqCst), 3);
    assert!(
        f.executor.cleanup_owner.try_lock().is_ok(),
        "cleanup ownership is released on return"
    );
}

#[test]
fn file_attachments_do_not_hold_state_during_io_and_reject_snapshot_drift_before_dispatch() {
    for change in 0..4 {
        let f = Fixture::ready();
        let id = f.insert(b"abc", Some("input.txt"), ArtifactState::Available);
        let executor = Arc::downgrade(&f.executor);
        let changed_id = id.clone();
        let page = f.created.primary_page_id.clone();
        *f.store.hook.lock().expect("hook") = Some(Arc::new(move || {
            let executor = executor.upgrade().expect("executor");
            let mut state = executor
                .state
                .try_lock()
                .expect("state must be available while reading");
            match change {
                0 => {
                    state
                        .artifacts
                        .get_mut(&changed_id)
                        .expect("record")
                        .object_generation = ArtifactObjectGeneration::new([9; 32])
                }
                1 => {
                    state
                        .artifacts
                        .get_mut(&changed_id)
                        .expect("record")
                        .artifact
                        .apply(ArtifactEvent::DeleteRequested)
                        .expect("deleting");
                }
                2 => {
                    state
                        .artifacts
                        .get_mut(&changed_id)
                        .expect("record")
                        .display_filename = Some("changed.txt".to_owned())
                }
                _ => {
                    state.closing_pages.insert(page.clone());
                }
            }
        }));
        f.assert_no_dispatch(f.execute(&[id]));
    }
}

#[test]
fn file_attachments_reject_foreign_fence_session_page_or_node_before_io() {
    for choice in 0..4 {
        let f = Fixture::ready();
        let id = f.insert(b"abc", None, ArtifactState::Available);
        let session = if choice == 0 {
            SessionId::new()
        } else {
            f.created.session_id.clone()
        };
        let page = if choice == 1 {
            PageId::new()
        } else {
            f.created.primary_page_id.clone()
        };
        let fence = if choice == 2 {
            OwnershipFence::new(f.created.fence.worker_id().clone(), 4, 1, 1)
        } else {
            f.created.fence.clone()
        };
        let node_ref = if choice == 3 { "" } else { "node-input" };
        f.assert_no_dispatch(f.worker.execute_file_attachments(
            &session,
            &page,
            &fence,
            node_ref,
            &[id],
            Instant::now() + Duration::from_secs(2),
            &f.executor,
        ));
        assert!(f.store.requests.lock().expect("reads").is_empty());
    }
}

fn assert_public_set_files_is_durable_and_never_replayed(outcome: ActionExecutionResult) {
    let f = Fixture::new(outcome.clone(), WorkerArtifactLimits::default());
    let artifact = f.insert(
        b"owned input contents",
        Some("input.txt"),
        ArtifactState::Available,
    );
    let command = WorkerActionCommand::SetFiles {
        node_ref: "node-input".to_owned(),
        artifact_ids: vec![artifact.clone()],
    };
    assert!(command.is_valid());
    let payload = serde_json::to_vec(&command).expect("set_files command");
    let request_hash: [u8; 32] = Sha256::digest(&payload).into();
    let principal = PrincipalId::new();
    let submit = |now| {
        f.worker.submit_action(
            &f.peer,
            principal.clone(),
            &f.created.session_id,
            &f.created.fence,
            "public-set-files",
            request_hash,
            ActionKind::Mutating,
            Some(BuiltinFeature::CoreInput),
            Some(f.created.primary_page_id.clone()),
            payload.clone(),
            None,
            SessionTime::new(now),
        )
    };
    let action = submit(1).expect("public action admission");
    let journal_path = f
        .worker
        .config
        .action_journal
        .session_path(&f.created.session_id);
    let accepted_journal = std::fs::read(&journal_path).expect("accepted durable journal");
    assert_eq!(submit(1).expect("duplicate queued admission"), action);
    assert_eq!(
        std::fs::read(&journal_path).expect("journal"),
        accepted_journal
    );
    let queued = f
        .worker
        .get_action(&f.peer, &f.created.session_id, &action, &f.created.fence)
        .expect("durable queued action");
    assert_eq!(queued.status, ActionStatus::Queued);
    assert!(f.driver.calls.lock().expect("dispatches").is_empty());
    let completed = f
        .worker
        .run_next_action(
            &f.peer,
            &f.created.session_id,
            &f.created.fence,
            SessionTime::new(2),
        )
        .expect("public queued action execution")
        .expect("one action");
    let (status, state, result, terminal) = match outcome {
        ActionExecutionResult::Succeeded(result) => Some((
            ActionStatus::Succeeded,
            ActionState::Succeeded,
            Some(result.clone()),
            TerminalDetail::Succeeded(ResultDigest::new(Sha256::digest(&result).into())),
        )),
        ActionExecutionResult::OutcomeUnknown => Some((
            ActionStatus::OutcomeUnknown,
            ActionState::OutcomeUnknown,
            None,
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::AmbiguousTransportLoss),
        )),
        ActionExecutionResult::FailedKnown(_) => None,
    }
    .expect("public regression covers success and unknown");
    assert_eq!(completed.action_id, action);
    assert_eq!(completed.status, status);
    assert_eq!(completed.result, result);
    let durable = f
        .worker
        .get_action(&f.peer, &f.created.session_id, &action, &f.created.fence)
        .expect("durable terminal action");
    assert_eq!(durable.status, status);
    assert_eq!(durable.result, result);
    assert_eq!(durable.terminal_detail, Some(terminal));
    {
        let calls = f.driver.calls.lock().expect("dispatches");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].node_ref, "node-input");
        assert_eq!(calls[0].session, f.created.session_id);
        assert_eq!(calls[0].page, f.created.primary_page_id);
        assert_eq!(calls[0].fence, f.created.fence);
        assert_eq!(calls[0].files.len(), 1);
        assert_eq!(calls[0].files[0].key().artifact_id(), &artifact);
        assert_eq!(calls[0].files[0].bytes(), b"owned input contents");
        assert_eq!(calls[0].files[0].display_filename(), "input.txt");
    }
    assert_eq!(
        f.driver.generic_calls.load(Ordering::SeqCst),
        0,
        "SetFiles uses prepared artifact dispatch"
    );
    assert_eq!(f.store.requests.lock().expect("reads").len(), 1);
    let terminal_journal = std::fs::read(&journal_path).expect("terminal durable journal");
    assert_eq!(submit(3).expect("duplicate terminal admission"), action);
    assert!(
        f.worker
            .run_next_action(
                &f.peer,
                &f.created.session_id,
                &f.created.fence,
                SessionTime::new(3)
            )
            .expect("no automatic replay")
            .is_none()
    );
    assert_eq!(f.driver.calls.lock().expect("dispatches").len(), 1);
    assert_eq!(f.store.requests.lock().expect("reads").len(), 1);
    assert_eq!(f.driver.generic_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(&journal_path).expect("journal"),
        terminal_journal
    );
    let tenant = f
        .executor
        .state
        .lock()
        .expect("session state")
        .tenant_id
        .clone();
    let journal_limits = f.worker.config.action_journal.limits;
    drop(f.worker);
    drop(f.executor);
    let reopened = Arc::new(
        FileActionJournal::open(&journal_path, journal_limits)
            .expect("reopen the actual persisted action journal"),
    );
    let ledger = ActionLedger::recover(
        LedgerSession::new(
            tenant,
            f.created.session_id.clone(),
            f.created.fence.as_placement_fence(),
        ),
        reopened,
    )
    .expect("recover durable action facts");
    let recovered = ledger
        .snapshot(f.created.fence.as_placement_fence(), &action)
        .expect("recovered action");
    assert_eq!(recovered.state(), state);
    assert_eq!(recovered.request().kind(), ActionKind::Mutating);
    assert_eq!(recovered.terminal_detail(), Some(terminal));
    assert!(!recovered.automatic_replay_allowed());
    assert_eq!(f.driver.calls.lock().expect("dispatches").len(), 1);
}

#[test]
fn public_set_files_admission_dispatches_prepared_bytes_once_and_recovers_durable_success() {
    assert_public_set_files_is_durable_and_never_replayed(ActionExecutionResult::Succeeded(
        b"attached".to_vec(),
    ));
}

#[test]
fn public_set_files_preserves_unknown_and_never_replays_after_duplicate_or_journal_recovery() {
    assert_public_set_files_is_durable_and_never_replayed(ActionExecutionResult::OutcomeUnknown);
}

#[test]
fn expired_publication_is_rejected_before_file_read_or_driver_dispatch() {
    let f = Fixture::ready();
    let id = f.insert(b"old", Some("old.txt"), ArtifactState::Available);
    {
        let mut session = f.executor.state.lock().expect("state");
        let record = session.artifacts.get_mut(&id).expect("record");
        let old = record.publication.as_ref().expect("publication");
        let mut observation = old
            .scan_attestation()
            .expect("scan evidence")
            .observation()
            .clone();
        observation.database_built_at_unix_millis = 1;
        observation.observed_before_unix_millis = 1;
        observation.observed_after_unix_millis = 1;
        let attestation = ArtifactScanAttestation::new(
            old.key(),
            old.original_fence(),
            old.metadata().source(),
            old.object_generation(),
            old.metadata().size_bytes(),
            *old.metadata().checksum(),
            observation,
        )
        .expect("historical evidence");
        record.publication = Some(
            ArtifactPublication::new_with_scan_attestation(
                old.key().clone(),
                old.original_fence().clone(),
                old.metadata().clone(),
                old.object_generation(),
                old.scan_verdict(),
                old.display_filename().map(ToOwned::to_owned),
                1,
                2,
                Some(attestation),
            )
            .expect("expired publication"),
        );
    }
    f.assert_no_dispatch(f.execute(&[id]));
}
