#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::*;
use browserd_chromium::{ChromiumArtifactIdentity, Sha256Digest};
use browserd_policy::{
    ActionApprovalGrant, ActionApprovalOutcome, ActionApprovalPolicy, ApprovalActionKind,
    ApprovalContextScope, ApprovalNodeBinding,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, AtomicUsize};

const VALUE: &str = "private-only-typed-approval-value";
const ORIGIN: &str = "https://typed.example.test:8443";
type Hook = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::Acquire)))
    }
}

struct Resolver {
    provider: Mutex<FileSecretResolver>,
    reads: AtomicUsize,
}
impl SecretResolver for Resolver {
    fn authorize(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        reference: &str,
        origin: &Origin,
        deadline: Instant,
    ) -> Result<SecretGrant, SecretFillError> {
        self.provider
            .lock()
            .expect("provider")
            .authorize(tenant, principal, reference, origin, deadline)
    }
    fn resolve(
        &self,
        grant: &SecretGrant,
        deadline: Instant,
    ) -> Result<ResolvedSecret, SecretFillError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.provider
            .lock()
            .expect("provider")
            .resolve(grant, deadline)
    }
}

#[derive(Default)]
struct Store {
    objects: Mutex<HashMap<ArtifactKey, (ArtifactObjectGeneration, Vec<u8>)>>,
    opens: AtomicUsize,
}
struct Reader(Option<Vec<u8>>);
impl ArtifactReadStream for Reader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
        Ok(self.0.take())
    }
}
impl SandboxClient for Store {
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
        self.opens.fetch_add(1, Ordering::SeqCst);
        let objects = self.objects.lock().expect("objects");
        let (generation, bytes) = objects
            .get(request.key())
            .ok_or(DependencyError::Rejected)?;
        if generation != &request.generation() {
            return Err(DependencyError::Rejected);
        }
        Ok(Box::new(Reader(Some(bytes.clone()))))
    }
}

#[derive(Default)]
struct Checkpoints {
    saves: AtomicUsize,
    discards: AtomicUsize,
}
impl CheckpointStore for Checkpoints {
    fn save(
        &self,
        _: &TenantId,
        session: &SessionId,
        _: &OwnershipFence,
        _: &ActionId,
        snapshot: CheckpointSnapshot,
        _: u64,
        _: Instant,
    ) -> Result<CheckpointRestoreReceipt, CheckpointError> {
        snapshot.validate()?;
        self.saves.fetch_add(1, Ordering::SeqCst);
        Ok(CheckpointRestoreReceipt {
            checkpoint_ref: uuid::Uuid::new_v4().to_string(),
            source_session_id: session.clone(),
        })
    }
    fn load(
        &self,
        _: &TenantId,
        _: &str,
        _: u64,
        _: Instant,
    ) -> Result<LoadedCheckpoint, CheckpointError> {
        Err(CheckpointError::Rejected)
    }
    fn cleanup_expired(&self, _: u64) -> Result<usize, CheckpointError> {
        Ok(0)
    }
    fn discard(
        &self,
        _: &TenantId,
        _: &SessionId,
        _: &OwnershipFence,
        _: &ActionId,
        _: &str,
    ) -> Result<(), CheckpointError> {
        self.discards.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn identity() -> ChromiumArtifactIdentity {
    let digest = Sha256Digest::from_hex(&"17".repeat(32)).expect("digest");
    ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "Chrome/143.0.0.0".to_owned(),
        chromium_revision: "typed-approval-test".to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    }
}

#[derive(Default)]
struct Driver {
    effects: AtomicUsize,
    generic: AtomicUsize,
    cancel_calls: AtomicUsize,
    cancel_signal: (Mutex<bool>, std::sync::Condvar),
    drift: AtomicUsize,
    fail_after_commit: AtomicBool,
    confirm_cancel: AtomicBool,
    before_commit: Mutex<Option<Hook>>,
    after_commit: Mutex<Option<Hook>>,
    file_names: Mutex<Vec<String>>,
}
impl Driver {
    fn commit(
        &self,
        expected: &TypedApprovalObservation,
        callback: &mut dyn FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>,
    ) -> Result<(), ApprovedActionError> {
        if let Some(hook) = self.before_commit.lock().expect("hook").take() {
            hook();
        }
        let mut current = expected.clone();
        match self.drift.load(Ordering::Acquire) {
            1 => current.target_binding_sha256 = [99; 32],
            2 => current.build_identity_sha256 = [99; 32],
            3 => {
                if let Some(node) = &mut current.node_binding {
                    node.binding_sha256 = [99; 32]
                }
            }
            _ => {}
        }
        callback(&current)?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.after_commit.lock().expect("hook").take() {
            hook();
        }
        Ok(())
    }
    fn result(&self) -> ActionExecutionResult {
        if self.fail_after_commit.load(Ordering::Acquire) {
            ActionExecutionResult::FailedKnown("failure after admission".to_owned())
        } else {
            ActionExecutionResult::Succeeded(b"{\"ok\":true}".to_vec())
        }
    }
}
impl ChromiumDriver for Driver {
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
        self.generic.fetch_add(1, Ordering::SeqCst);
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
        self.cancel_calls.fetch_add(1, Ordering::Release);
        *self.cancel_signal.0.lock().expect("cancel signal") = true;
        self.cancel_signal.1.notify_all();
        Ok(self.confirm_cancel.load(Ordering::Acquire))
    }
    fn inspect_typed_approval_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: Option<&PageId>,
        fence: &OwnershipFence,
        command: &WorkerActionCommand,
        _: Instant,
    ) -> Result<TypedApprovalObservation, ApprovedActionError> {
        let checkpoint = matches!(command, WorkerActionCommand::Checkpoint { .. });
        let node = match command {
            WorkerActionCommand::FillSecret { node_ref, .. }
            | WorkerActionCommand::SetFiles { node_ref, .. }
            | WorkerActionCommand::Click { node_ref } => Some(node_ref.clone()),
            _ => None,
        };
        let origin = if checkpoint {
            Origin::browser_context_scope()
        } else {
            Origin::parse(ORIGIN).expect("origin")
        };
        Ok(TypedApprovalObservation {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            page_id: page.cloned(),
            fence: fence.clone(),
            context_scope: if checkpoint {
                ApprovalContextScope::BrowserContext
            } else {
                ApprovalContextScope::HttpOrigin {
                    origin: ORIGIN.to_owned(),
                }
            },
            target_binding_sha256: [13; 32],
            node_binding: node.as_ref().map(|reference| ApprovalNodeBinding {
                node_ref: reference.clone(),
                binding_sha256: [17; 32],
                role: None,
                name: None,
            }),
            build_identity_sha256: Sha256::digest(
                serde_json::to_vec(&identity()).expect("identity"),
            )
            .into(),
            live: LiveApprovalContext {
                target_incarnation: 1,
                frame_document_epoch: 2,
                current_origin: origin,
                url_revision: 3,
                node_ref: node.map(|reference| NodeReference::new(reference).expect("node")),
                node_valid: true,
                resolved_ips: vec![],
                credential_refs: match command {
                    WorkerActionCommand::FillSecret { secret_ref, .. } => vec![secret_ref.clone()],
                    _ => vec![],
                },
                chromium_build: "trusted-build".to_owned(),
                effective_isolation: if self.drift.load(Ordering::Acquire) == 4 {
                    IsolationProfile::DedicatedProcess
                } else {
                    IsolationProfile::SharedContext
                },
            },
        })
    }
    fn execute_typed_browser_until(
        &self,
        expected: &TypedApprovalObservation,
        _: &[u8],
        _: Instant,
        callback: &mut dyn FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        self.commit(expected, callback)?;
        Ok(self.result())
    }
    fn execute_typed_secret_until(
        &self,
        expected: &TypedApprovalObservation,
        secret: ResolvedSecret,
        _: Instant,
        callback: &mut dyn FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        self.commit(expected, callback)?;
        assert_eq!(secret.value(), VALUE);
        Ok(self.result())
    }
    fn execute_typed_files_until(
        &self,
        expected: &TypedApprovalObservation,
        files: Vec<BrowserFileAttachment>,
        _: Instant,
        callback: &mut dyn FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        self.commit(expected, callback)?;
        assert!(files.iter().all(|file| file.fence() == &expected.fence));
        *self.file_names.lock().expect("names") = files
            .iter()
            .map(|file| file.display_filename().to_owned())
            .collect();
        Ok(self.result())
    }
    fn capture_typed_checkpoint_until(
        &self,
        expected: &TypedApprovalObservation,
        origins: &[String],
        _: Instant,
        callback: &mut dyn FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>,
    ) -> Result<CheckpointSnapshot, ApprovedActionError> {
        self.commit(expected, callback)?;
        if self.fail_after_commit.load(Ordering::Acquire) {
            return Err(ApprovedActionError::OutcomeUncertain);
        }
        Ok(CheckpointSnapshot {
            artifact_identity: identity(),
            cookies: vec![],
            origins: origins
                .iter()
                .map(|origin| CheckpointOriginStorage {
                    origin: origin.clone(),
                    local_storage: vec![CheckpointStorageEntry {
                        name: "private-key".to_owned(),
                        value: "private-checkpoint-state".to_owned(),
                    }],
                })
                .collect(),
        })
    }
}

struct Fixture {
    worker: Arc<WorkerControlPlane<Driver, Store>>,
    driver: Arc<Driver>,
    store: Arc<Store>,
    resolver: Arc<Resolver>,
    checkpoints: Arc<Checkpoints>,
    clock: Arc<Clock>,
    emergency: Arc<EmergencyPolicy>,
    audit: Option<Arc<AuditWal>>,
    created: CreateSessionOutcome,
    peer: AuthenticatedPeer,
    principal: PrincipalId,
    tenant: TenantId,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new(audit: bool, auto_click: bool) -> Self {
        Self::new_with_runtime(audit, auto_click, None)
    }
    fn new_with_runtime(
        audit: bool,
        auto_click: bool,
        runtime: Option<Arc<browserd_core::RuntimeSafetyCache>>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("fixture");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private dir");
        let tenant = TenantId::new();
        let principal = PrincipalId::new();
        let config_path = directory.path().join("secret.json");
        std::fs::write(&config_path,serde_json::to_vec(&serde_json::json!({"schema_version":1,"grants":[{
            "tenant_id":tenant,"principal_ids":[principal],"secret_ref":"credential-ref","allowed_origins":[ORIGIN],"value_file":"value"}]})).expect("config")).expect("private config");
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .expect("mode");
        let value_path = directory.path().join("value");
        std::fs::write(&value_path, VALUE).expect("test value");
        std::fs::set_permissions(&value_path, std::fs::Permissions::from_mode(0o600))
            .expect("mode");
        let resolver = Arc::new(Resolver {
            provider: Mutex::new(FileSecretResolver::open(&config_path).expect("provider")),
            reads: AtomicUsize::new(0),
        });
        let driver = Arc::new(Driver::default());
        let store = Arc::new(Store::default());
        let clock = Arc::new(Clock::default());
        let emergency = Arc::new(EmergencyPolicy::default());
        let checkpoints = Arc::new(Checkpoints::default());
        let peer = AuthenticatedPeer::new("typed-approval-gateway").expect("peer");
        let journal_directory = directory.path().join("actions");
        std::fs::create_dir(&journal_directory).expect("action journal directory");
        std::fs::set_permissions(&journal_directory, std::fs::Permissions::from_mode(0o700))
            .expect("private action journal directory");
        let config = WorkerConfig::new(
            WorkerId::new("typed-approval-worker").expect("worker"),
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
            ActionJournalConfig::with_default_limits(journal_directory).expect("journal"),
        )
        .expect("config");
        let policy = ActionApprovalPolicy::new(if auto_click {
            vec![ActionApprovalGrant {
                tenant_id: tenant.clone(),
                principal_id: principal.clone(),
                action: ApprovalActionKind::Click,
                context_scope: ApprovalContextScope::HttpOrigin {
                    origin: ORIGIN.to_owned(),
                },
                navigation_destination: None,
                outcome: ActionApprovalOutcome::Allow,
                require_four_eyes: true,
            }]
        } else {
            vec![]
        })
        .expect("policy");
        let mut worker = WorkerControlPlane::new_with_emergency_policy_and_clock(
            config,
            driver.clone(),
            store.clone(),
            emergency.clone(),
            clock.clone(),
        )
        .with_action_approval_policy(policy)
        .with_secret_resolver(resolver.clone())
        .with_checkpoint_store(checkpoints.clone());
        let audit = audit.then(|| {
            Arc::new(
                AuditWal::open(
                    directory.path().join("audit.wal"),
                    browserd_observability::AuditWalPolicy::new(256 * 1024, 4096)
                        .expect("audit policy"),
                )
                .expect("audit"),
            )
        });
        if let Some(wal) = &audit {
            worker = worker.with_audit_wal(wal.clone());
        }
        if let Some(runtime) = runtime {
            worker = worker
                .with_runtime_safety_cache(runtime, "17".repeat(32))
                .expect("runtime binding");
        }
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: tenant.clone(),
                    idempotency_key: "create-typed".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(0),
            )
            .expect("create");
        Self {
            worker: Arc::new(worker),
            driver,
            store,
            resolver,
            checkpoints,
            clock,
            emergency,
            audit,
            created,
            peer,
            principal,
            tenant,
            directory,
        }
    }
    fn submit(&self, command: WorkerActionCommand) -> ActionId {
        let payload = serde_json::to_vec(&command).expect("command");
        let page = (!matches!(command, WorkerActionCommand::Checkpoint { .. }))
            .then(|| self.created.primary_page_id.clone());
        self.worker
            .submit_action(
                &self.peer,
                self.principal.clone(),
                &self.created.session_id,
                &self.created.fence,
                "typed-action",
                Sha256::digest(&payload).into(),
                command.kind(),
                None,
                page,
                payload,
                None,
                SessionTime::new(1),
            )
            .expect("submit")
    }
    fn run(&self) -> Result<Option<WorkerActionSnapshot>, WorkerError> {
        self.worker.run_next_action(
            &self.peer,
            &self.created.session_id,
            &self.created.fence,
            SessionTime::new(4),
        )
    }
    fn prepare(&self, command: WorkerActionCommand) -> (ActionId, ApprovalId) {
        let id = self.submit(command);
        assert!(self.run().expect("prepare").is_none());
        assert_eq!(self.action(&id).status, ActionStatus::PendingApproval);
        let approval = self
            .worker
            .approval_for_action(
                &self.peer,
                &self.created.session_id,
                &id,
                &self.created.fence,
            )
            .expect("approval");
        let snapshot = self
            .worker
            .get_approval(
                &self.peer,
                &self.created.session_id,
                &approval,
                &self.created.fence,
            )
            .expect("proposal");
        assert_eq!(snapshot.proposal.schema_version(), 2);
        assert_eq!(
            snapshot
                .proposal
                .typed_binding()
                .expect("binding")
                .action_id,
            id
        );
        assert_eq!(self.driver.effects.load(Ordering::Acquire), 0);
        (id, approval)
    }
    fn approve(&self, approval: &ApprovalId) {
        self.worker
            .decide_approval(
                &self.peer,
                &self.created.session_id,
                approval,
                &self.created.fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(4),
            )
            .expect("approve");
    }
    fn action(&self, id: &ActionId) -> WorkerActionSnapshot {
        self.worker
            .get_action(
                &self.peer,
                &self.created.session_id,
                id,
                &self.created.fence,
            )
            .expect("receipt")
    }
    fn secret() -> WorkerActionCommand {
        WorkerActionCommand::FillSecret {
            node_ref: "secret-node".to_owned(),
            secret_ref: "credential-ref".to_owned(),
        }
    }
    fn checkpoint(origins: Vec<String>) -> WorkerActionCommand {
        WorkerActionCommand::Checkpoint { origins }
    }
    fn insert_artifact(&self, bytes: &[u8], filename: &str, generation: u8) -> ArtifactId {
        let id = ArtifactId::new();
        self.replace_artifact(&id, bytes, filename, generation, None);
        id
    }
    fn replace_artifact(
        &self,
        id: &ArtifactId,
        bytes: &[u8],
        filename: &str,
        generation: u8,
        expiry: Option<u64>,
    ) {
        let key = ArtifactKey::new(
            self.tenant.clone(),
            self.created.session_id.clone(),
            id.clone(),
        );
        let object_generation = ArtifactObjectGeneration::new([generation; 32]);
        let metadata = ArtifactContentMetadata::new(
            bytes.len() as u64,
            ArtifactChecksum::new(Sha256::digest(bytes).into()),
            "application/octet-stream",
            ArtifactContentSource::ClientUpload,
            "browserd-worker-upload",
        )
        .expect("metadata");
        let receipt = ArtifactStoreReceipt::new(
            key.clone(),
            metadata.size_bytes(),
            *metadata.checksum(),
            metadata.content_type(),
            object_generation,
            ArtifactScanVerdict::Clean,
        )
        .expect("receipt");
        let receipt = artifact_scan_evidence::attest_test_receipt(
            receipt,
            &self.created.fence,
            self.clock.now().expect("clock").get(),
        )
        .expect("attestation");
        let now = self.clock.now().expect("clock").get();
        let publication = ArtifactPublication::new_with_scan_attestation(
            key.clone(),
            self.created.fence.clone(),
            metadata.clone(),
            object_generation,
            Some(ArtifactScanVerdict::Clean),
            Some(filename.to_owned()),
            now,
            expiry.unwrap_or(now + ARTIFACT_PUBLICATION_TTL_MILLIS),
            receipt.scan_attestation().cloned(),
        )
        .expect("publication");
        let mut artifact = Artifact::new_upload(key.clone());
        artifact
            .apply_materialized(ArtifactEvent::UploadStored, metadata)
            .expect("stored");
        artifact.apply(ArtifactEvent::ScanStarted).expect("scan");
        artifact.apply(ArtifactEvent::ScanPassed).expect("clean");
        let executor = self
            .worker
            .session(&self.created.session_id)
            .expect("executor");
        executor.state.lock().expect("state").artifacts.insert(
            id.clone(),
            ArtifactRecord {
                artifact,
                object_generation,
                display_filename: Some(filename.to_owned()),
                publication: Some(publication),
            },
        );
        self.store
            .objects
            .lock()
            .expect("objects")
            .insert(key, (object_generation, bytes.to_vec()));
    }
    fn files(ids: Vec<ArtifactId>) -> WorkerActionCommand {
        WorkerActionCommand::SetFiles {
            node_ref: "file-node".to_owned(),
            artifact_ids: ids,
        }
    }
    fn exhaust_audit(&self) {
        let wal = self.audit.as_ref().expect("audit");
        for size in [3500, 128, 1] {
            for i in 0..4096 {
                if wal
                    .append(AuditEvent::new(
                        AuditEventId::new(format!("occupy-{size}-{i}")).expect("id"),
                        "occupied",
                        vec![b'x'; size],
                        true,
                    ))
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    fn assert_no_effects(&self) {
        assert_eq!(self.driver.effects.load(Ordering::Acquire), 0);
        assert_eq!(self.driver.generic.load(Ordering::Acquire), 0);
    }
}

#[test]
fn manual_secret_ref_only_proposal_approves_once_and_keeps_values_out_of_audit_wal() {
    let f = Fixture::new(true, false);
    let (id, approval) = f.prepare(Fixture::secret());
    assert_eq!(f.resolver.reads.load(Ordering::Acquire), 0);
    f.approve(&approval);
    let result = f.run().expect("run").expect("receipt");
    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(f.resolver.reads.load(Ordering::Acquire), 1);
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
    assert_eq!(result.result.as_deref(), Some(b"{\"ok\":true}".as_slice()));
    assert!(f.run().expect("no replay").is_none());
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
    assert_eq!(f.action(&id).status, ActionStatus::Succeeded);
    for event in f.audit.as_ref().expect("audit").pending().expect("events") {
        assert!(
            !event
                .event()
                .payload()
                .windows(VALUE.len())
                .any(|window| window == VALUE.as_bytes())
        );
    }
    for path in std::fs::read_dir(f.directory.path().join("actions")).expect("journals") {
        let path = path.expect("entry").path();
        if path.is_file() {
            let bytes = std::fs::read(path).expect("WAL");
            assert!(
                !bytes
                    .windows(VALUE.len())
                    .any(|window| window == VALUE.as_bytes())
            );
        }
    }
}

#[test]
fn changed_grant_metadata_or_revocation_before_resolve_never_reads_value() {
    for mode in 0..2 {
        let f = Fixture::new(true, false);
        let (_id, approval) = f.prepare(Fixture::secret());
        f.approve(&approval);
        if mode == 0 {
            *f.resolver.provider.lock().expect("provider") =
                FileSecretResolver::open(&f.directory.path().join("secret.json"))
                    .expect("replacement provider");
        } else {
            f.emergency.revoke_secret("credential-ref").expect("revoke");
        }
        assert_eq!(
            f.run().expect("run").expect("receipt").status,
            ActionStatus::FailedKnown
        );
        assert_eq!(f.resolver.reads.load(Ordering::Acquire), 0);
        f.assert_no_effects();
    }
}

#[test]
fn manual_set_files_binds_ordered_generation_scan_evidence_and_effective_names() {
    let f = Fixture::new(true, false);
    let first = f.insert_artifact(b"first", "first.txt", 7);
    let second = f.insert_artifact(b"second", "second.txt", 8);
    let (_id, approval) = f.prepare(Fixture::files(vec![second.clone(), first.clone()]));
    let snapshot = f
        .worker
        .get_approval(&f.peer, &f.created.session_id, &approval, &f.created.fence)
        .expect("approval");
    let browserd_policy::TypedActionPayload::SetFiles { files, .. } =
        &snapshot.proposal.typed_binding().expect("binding").payload
    else {
        panic!("file binding");
    };
    assert_eq!(
        files
            .iter()
            .map(|f| f.artifact_id.clone())
            .collect::<Vec<_>>(),
        vec![second, first]
    );
    assert!(files.iter().all(|file| file.scan_evidence_sha256.is_some()));
    f.approve(&approval);
    assert_eq!(
        f.run().expect("run").expect("receipt").status,
        ActionStatus::Succeeded
    );
    assert_eq!(
        *f.driver.file_names.lock().expect("names"),
        vec!["second.txt", "first.txt"]
    );
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
}

#[test]
fn file_replacement_or_expiry_after_approval_prevents_dispatch() {
    for expiry in [false, true] {
        let f = Fixture::new(true, false);
        let id = f.insert_artifact(b"same bytes", "selected.txt", 7);
        let (_action, approval) = f.prepare(Fixture::files(vec![id.clone()]));
        f.approve(&approval);
        if expiry {
            f.replace_artifact(&id, b"same bytes", "selected.txt", 7, Some(5));
            f.clock.0.store(6, Ordering::Release);
        } else {
            f.replace_artifact(&id, b"same bytes", "selected.txt", 9, None);
        }
        assert_eq!(
            f.run().expect("run").expect("receipt").status,
            ActionStatus::FailedKnown
        );
        f.assert_no_effects();
    }
}

#[test]
fn cookie_only_and_explicit_origins_checkpoint_approvals_have_context_authority() {
    for origins in [
        vec![],
        vec!["https://b.test".to_owned(), "https://a.test".to_owned()],
    ] {
        let f = Fixture::new(true, false);
        let (_id, approval) = f.prepare(Fixture::checkpoint(origins.clone()));
        let snapshot = f
            .worker
            .get_approval(&f.peer, &f.created.session_id, &approval, &f.created.fence)
            .expect("approval");
        assert!(
            snapshot
                .proposal
                .current_origin()
                .is_browser_context_scope()
        );
        assert!(Origin::parse(snapshot.proposal.current_origin().as_str()).is_err());
        let browserd_policy::TypedActionPayload::Checkpoint { origins: bound, .. } =
            &snapshot.proposal.typed_binding().expect("binding").payload
        else {
            panic!("checkpoint binding");
        };
        assert_eq!(bound, &origins);
        f.approve(&approval);
        let result = f.run().expect("run").expect("receipt");
        assert_eq!(result.status, ActionStatus::Succeeded);
        assert_eq!(f.checkpoints.saves.load(Ordering::Acquire), 1);
        assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
        assert!(
            !result
                .result
                .expect("ref")
                .windows(24)
                .any(|window| window == b"private-checkpoint-state")
        );
    }
}

#[test]
fn changed_checkpoint_origins_or_build_and_node_realm_drift_are_stale_before_effect() {
    for mode in 0..3 {
        let f = Fixture::new(true, false);
        let command = if mode == 2 {
            WorkerActionCommand::Click {
                node_ref: "click-node".to_owned(),
            }
        } else {
            Fixture::checkpoint(vec![
                "https://a.test".to_owned(),
                "https://b.test".to_owned(),
            ])
        };
        let (id, approval) = f.prepare(command);
        f.approve(&approval);
        if mode == 0 {
            let executor = f.worker.session(&f.created.session_id).expect("executor");
            let mut state = executor.state.lock().expect("state");
            state.actions.get_mut(&id).expect("action").payload =
                serde_json::to_vec(&Fixture::checkpoint(vec![
                    "https://b.test".to_owned(),
                    "https://a.test".to_owned(),
                ]))
                .expect("reordered payload");
        } else {
            f.driver
                .drift
                .store(if mode == 1 { 2 } else { 3 }, Ordering::Release);
        }
        assert_eq!(
            f.run().expect("run").expect("receipt").status,
            ActionStatus::FailedKnown
        );
        f.assert_no_effects();
        assert_eq!(f.checkpoints.saves.load(Ordering::Acquire), 0);
    }
}

#[test]
fn missing_or_full_audit_blocks_proposal_or_dispatch_before_secret_read() {
    let no_audit = Fixture::new(false, false);
    no_audit.submit(Fixture::secret());
    assert_eq!(
        no_audit.run().expect("run").expect("receipt").status,
        ActionStatus::FailedKnown
    );
    assert_eq!(no_audit.resolver.reads.load(Ordering::Acquire), 0);
    no_audit.assert_no_effects();
    let full = Fixture::new(true, false);
    let (_id, approval) = full.prepare(Fixture::secret());
    full.approve(&approval);
    full.exhaust_audit();
    assert_eq!(
        full.run().expect("run").expect("receipt").status,
        ActionStatus::FailedKnown
    );
    assert_eq!(full.resolver.reads.load(Ordering::Acquire), 0);
    full.assert_no_effects();
}

#[test]
fn cancellation_at_driver_callback_never_dispatches_or_replays() {
    let f = Fixture::new(true, false);
    let (id, approval) = f.prepare(WorkerActionCommand::Click {
        node_ref: "click-node".to_owned(),
    });
    f.approve(&approval);
    f.driver.confirm_cancel.store(true, Ordering::Release);
    let joined = Arc::new(Mutex::new(None));
    let result = Arc::new(Mutex::new(None));
    let worker = f.worker.clone();
    let peer = f.peer.clone();
    let session = f.created.session_id.clone();
    let fence = f.created.fence.clone();
    let action = id.clone();
    let driver = Arc::downgrade(&f.driver);
    let thread_slot = joined.clone();
    let cancel_result = result.clone();
    *f.driver.before_commit.lock().expect("hook") = Some(Arc::new(move || {
        let worker = worker.clone();
        let peer = peer.clone();
        let session = session.clone();
        let fence = fence.clone();
        let action = action.clone();
        let result = cancel_result.clone();
        *thread_slot.lock().expect("thread") = Some(std::thread::spawn(move || {
            *result.lock().expect("result") =
                Some(worker.cancel_action(&peer, &session, &action, &fence, SessionTime::new(5)));
        }));
        let driver = driver.upgrade().expect("driver");
        let signal = driver.cancel_signal.0.lock().expect("signal");
        let (signal, _) = driver
            .cancel_signal
            .1
            .wait_timeout_while(signal, Duration::from_secs(2), |entered| !*entered)
            .expect("cancel wait");
        assert!(*signal, "positive driver cleanup precedes callback");
    }));
    let execution = f.run();
    joined
        .lock()
        .expect("thread")
        .take()
        .expect("spawned")
        .join()
        .expect("cancel join");
    let cancelled = result
        .lock()
        .expect("result")
        .take()
        .expect("cancel result")
        .expect("confirmed cleanup or already completed known rejection");
    let terminal = f.action(&id);
    // The rejected callback and confirmed cleanup race to write the terminal receipt. Both
    // winners prove no effect; neither may leave the action running or mark it unknown.
    assert!(matches!(
        terminal.status,
        ActionStatus::CancelledConfirmed | ActionStatus::FailedKnown
    ));
    assert_eq!(cancelled.status, terminal.status);
    match execution {
        Ok(Some(receipt)) => assert_eq!(receipt.status, ActionStatus::FailedKnown),
        Err(WorkerError::InvalidActionTransition) => {
            assert_eq!(terminal.status, ActionStatus::CancelledConfirmed)
        }
        other => panic!("unexpected pre-effect completion: {other:?}"),
    }
    assert_eq!(f.driver.cancel_calls.load(Ordering::Acquire), 1);
    f.assert_no_effects();
    assert!(f.run().expect("no replay").is_none());
}

#[test]
fn failure_after_callback_is_unknown_and_an_idempotent_retry_never_replays() {
    for kind in 0..3 {
        let f = Fixture::new(true, false);
        let command = match kind {
            0 => Fixture::secret(),
            1 => {
                let id = f.insert_artifact(b"file", "file.txt", 7);
                Fixture::files(vec![id])
            }
            _ => Fixture::checkpoint(vec![]),
        };
        let (id, approval) = f.prepare(command.clone());
        f.approve(&approval);
        f.driver.fail_after_commit.store(true, Ordering::Release);
        assert_eq!(
            f.run().expect("run").expect("receipt").status,
            ActionStatus::OutcomeUnknown
        );
        assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
        assert_eq!(f.submit(command), id);
        assert!(f.run().expect("no replay").is_none());
        assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
    }
}

#[test]
fn auto_allow_action_cannot_claim_confirmed_cancellation_after_commit() {
    let f = Fixture::new(true, true);
    let id = f.submit(WorkerActionCommand::Click {
        node_ref: "click-node".to_owned(),
    });
    f.driver.confirm_cancel.store(true, Ordering::Release);
    f.driver.fail_after_commit.store(true, Ordering::Release);
    let joined = Arc::new(Mutex::new(None));
    let result = Arc::new(Mutex::new(None));
    let worker = f.worker.clone();
    let peer = f.peer.clone();
    let session = f.created.session_id.clone();
    let fence = f.created.fence.clone();
    let action = id.clone();
    let driver = Arc::downgrade(&f.driver);
    let thread_slot = joined.clone();
    let cancel_result = result.clone();
    *f.driver.after_commit.lock().expect("hook") = Some(Arc::new(move || {
        let worker = worker.clone();
        let peer = peer.clone();
        let session = session.clone();
        let fence = fence.clone();
        let action = action.clone();
        let result = cancel_result.clone();
        *thread_slot.lock().expect("thread") = Some(std::thread::spawn(move || {
            *result.lock().expect("result") =
                Some(worker.cancel_action(&peer, &session, &action, &fence, SessionTime::new(5)));
        }));
        let driver = driver.upgrade().expect("driver");
        let signal = driver.cancel_signal.0.lock().expect("signal");
        let (signal, _) = driver
            .cancel_signal
            .1
            .wait_timeout_while(signal, Duration::from_secs(2), |entered| !*entered)
            .expect("cancel wait");
        assert!(*signal, "cancel entered driver");
    }));
    let terminal = f.run().expect("run").expect("receipt");
    assert_eq!(terminal.status, ActionStatus::OutcomeUnknown);
    joined
        .lock()
        .expect("thread")
        .take()
        .expect("spawned")
        .join()
        .expect("cancel join");
    let cancelled = result
        .lock()
        .expect("result")
        .take()
        .expect("cancel result");
    assert!(!matches!(
        cancelled,
        Ok(WorkerActionSnapshot {
            status: ActionStatus::CancelledConfirmed,
            ..
        })
    ));
    assert_eq!(f.action(&id).status, ActionStatus::OutcomeUnknown);
    assert_eq!(f.driver.effects.load(Ordering::Acquire), 1);
}

#[test]
fn observed_isolation_must_equal_the_session_actual_placement_before_proposal() {
    let f = Fixture::new(true, false);
    f.driver.drift.store(4, Ordering::Release);
    let id = f.submit(Fixture::secret());
    let outcome = f.run();
    assert!(
        outcome.is_err()
            || outcome.as_ref().is_ok_and(|v| v
                .as_ref()
                .is_some_and(|v| v.status == ActionStatus::FailedKnown))
    );
    assert_ne!(f.action(&id).status, ActionStatus::PendingApproval);
    assert!(
        f.worker
            .approval_for_action(&f.peer, &f.created.session_id, &id, &f.created.fence)
            .is_err()
    );
    assert_eq!(f.resolver.reads.load(Ordering::SeqCst), 0);
    f.assert_no_effects();
}

#[path = "typed_approval_tests/runtime_safety_tests.rs"]
mod runtime_safety_tests;
