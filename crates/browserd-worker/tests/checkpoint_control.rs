#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use browserd_actions::ActionKind;
use browserd_chromium::{ChromiumArtifactIdentity, Sha256Digest};
use browserd_core::{ActionId, PageId, PrincipalId, SessionId, TenantId, WorkerId};
use browserd_features::BuiltinFeature;
use browserd_observability::{AuditWal, AuditWalPolicy};
use browserd_policy::{CanonicalActionProposal, EmergencyPolicy};
use browserd_sandbox::CleanupReason;
use browserd_session::{
    LeasePolicy, OwnershipFence, SessionLifecycle, SessionTime, SessionTimeoutPolicy,
};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ActionStatus, ApprovedActionError,
    ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer, CheckpointCookie,
    CheckpointError, CheckpointOriginStorage, CheckpointRestoreReceipt, CheckpointSnapshot,
    CheckpointStorageEntry, CheckpointStore, ChromiumDriver, CreateSessionCommand,
    CreateSessionOutcome, DependencyError, InternalEndpoint, LiveApprovalContext, LoadedCheckpoint,
    SandboxClient, WorkerActionCommand, WorkerActionSnapshot, WorkerClock, WorkerConfig,
    WorkerControlPlane, WorkerError, WorkerIsolationProfile, WorkerSessionOptionsV1,
    WorkerViewport,
};

const RAW_STATE: &str = "checkpoint-private-cookie-and-storage-value";
const REFERENCE: &str = "opaque-checkpoint-control-fixture";
type Hook = Arc<dyn Fn() + Send + Sync>;
type Worker = WorkerControlPlane<FakeDriver, FakeSandbox>;

fn snapshot(origins: &[String]) -> CheckpointSnapshot {
    let digest = Sha256Digest::from_hex(&"11".repeat(32)).expect("digest");
    CheckpointSnapshot {
        artifact_identity: ChromiumArtifactIdentity {
            binary_digest: digest,
            product_version: "153.0.8010.12".to_owned(),
            chromium_revision: "checkpoint-control-fixture".to_owned(),
            browser_protocol_schema_digest: digest,
            js_protocol_schema_digest: digest,
            launch_profile_digest: digest,
            extension_bundle_digest: digest,
            font_bundle_digest: digest,
            certificate_runtime_bundle_digest: digest,
        },
        cookies: vec![CheckpointCookie {
            name: "session".to_owned(),
            value: RAW_STATE.to_owned(),
            domain: "example.test".to_owned(),
            path: "/".to_owned(),
            expires: None,
            http_only: true,
            secure: true,
            same_site: Some("Lax".to_owned()),
            priority: "Medium".to_owned(),
            source_scheme: "Secure".to_owned(),
            source_port: 443,
        }],
        origins: origins
            .iter()
            .map(|origin| CheckpointOriginStorage {
                origin: origin.clone(),
                local_storage: vec![CheckpointStorageEntry {
                    name: "credential".to_owned(),
                    value: RAW_STATE.to_owned(),
                }],
            })
            .collect(),
    }
}

#[derive(Default)]
struct Clock(AtomicU64);

impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextBinding {
    tenant: TenantId,
    session: SessionId,
    fence: OwnershipFence,
    options: Option<WorkerSessionOptionsV1>,
}

#[derive(Default)]
struct FakeDriver {
    created: Mutex<Vec<ContextBinding>>,
    restored: Mutex<Vec<(TenantId, SessionId, PageId, OwnershipFence)>>,
    closed: Mutex<Vec<(SessionId, OwnershipFence)>>,
    captures: AtomicUsize,
    generic_calls: AtomicUsize,
    unexpected_origin: AtomicBool,
    fail_restore: AtomicBool,
    fail_cleanup: AtomicBool,
    capture_hook: Mutex<Option<Hook>>,
    restore_hook: Mutex<Option<Hook>>,
}

impl ChromiumDriver for FakeDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_owned(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        self.created.lock().expect("creates").push(ContextBinding {
            tenant: tenant.clone(),
            session: session.clone(),
            fence: fence.clone(),
            options: None,
        });
        Ok(PageId::new())
    }

    fn create_context_owned_with_options(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        assert!(options.is_valid());
        self.created.lock().expect("creates").push(ContextBinding {
            tenant: tenant.clone(),
            session: session.clone(),
            fence: fence.clone(),
            options: Some(options.clone()),
        });
        Ok(PageId::new())
    }

    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn close_context_fenced(
        &self,
        session: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.closed
            .lock()
            .expect("closes")
            .push((session.clone(), fence.clone()));
        if self.fail_cleanup.load(Ordering::SeqCst) {
            Err(DependencyError::OutcomeUncertain)
        } else {
            Ok(())
        }
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
        Ok(true)
    }

    fn capture_checkpoint_until(
        &self,
        _: &TenantId,
        _: &SessionId,
        _: &OwnershipFence,
        origins: &[String],
        deadline: Instant,
    ) -> Result<CheckpointSnapshot, CheckpointError> {
        assert!(Instant::now() < deadline);
        self.captures.fetch_add(1, Ordering::SeqCst);
        let hook = self.capture_hook.lock().expect("capture hook").take();
        if let Some(hook) = hook {
            hook();
        }
        if self.unexpected_origin.load(Ordering::SeqCst) {
            Ok(snapshot(&["https://unrequested.example.test".to_owned()]))
        } else {
            Ok(snapshot(origins))
        }
    }

    fn restore_checkpoint_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: &PageId,
        fence: &OwnershipFence,
        state: CheckpointSnapshot,
        deadline: Instant,
    ) -> Result<(), CheckpointError> {
        assert!(Instant::now() < deadline);
        assert_eq!(state.cookies[0].value, RAW_STATE);
        self.restored.lock().expect("restores").push((
            tenant.clone(),
            session.clone(),
            page.clone(),
            fence.clone(),
        ));
        let hook = self.restore_hook.lock().expect("restore hook").take();
        if let Some(hook) = hook {
            hook();
        }
        if self.fail_restore.load(Ordering::SeqCst) {
            Err(CheckpointError::OutcomeUncertain)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct FakeSandbox {
    provisions: AtomicUsize,
    cleaned: Mutex<Vec<SessionId>>,
}

impl SandboxClient for FakeSandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.provisions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn cleanup(&self, session: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        self.cleaned.lock().expect("cleanup").push(session.clone());
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredBinding {
    tenant: TenantId,
    session: SessionId,
    fence: OwnershipFence,
    action: ActionId,
    reference: String,
}

struct FakeStore {
    tenant: TenantId,
    source: Mutex<SessionId>,
    origins: Mutex<Vec<String>>,
    saves: AtomicUsize,
    loads: AtomicUsize,
    load_mode: AtomicUsize,
    wrong_source: AtomicBool,
    fail_discard: AtomicBool,
    saved: Mutex<Vec<StoredBinding>>,
    discarded: Mutex<Vec<StoredBinding>>,
    save_hook: Mutex<Option<Hook>>,
}

impl FakeStore {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            source: Mutex::new(SessionId::new()),
            origins: Mutex::new(Vec::new()),
            saves: AtomicUsize::new(0),
            loads: AtomicUsize::new(0),
            load_mode: AtomicUsize::new(0),
            wrong_source: AtomicBool::new(false),
            fail_discard: AtomicBool::new(false),
            saved: Mutex::new(Vec::new()),
            discarded: Mutex::new(Vec::new()),
            save_hook: Mutex::new(None),
        }
    }
}

impl CheckpointStore for FakeStore {
    fn save(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        action: &ActionId,
        state: CheckpointSnapshot,
        _: u64,
        deadline: Instant,
    ) -> Result<CheckpointRestoreReceipt, CheckpointError> {
        assert!(Instant::now() < deadline);
        assert_eq!(tenant, &self.tenant);
        state.validate()?;
        assert_eq!(state.cookies[0].value, RAW_STATE);
        self.saves.fetch_add(1, Ordering::SeqCst);
        *self.source.lock().expect("source") = session.clone();
        *self.origins.lock().expect("origins") = state
            .origins
            .iter()
            .map(|entry| entry.origin.clone())
            .collect();
        self.saved.lock().expect("saved").push(StoredBinding {
            tenant: tenant.clone(),
            session: session.clone(),
            fence: fence.clone(),
            action: action.clone(),
            reference: REFERENCE.to_owned(),
        });
        let hook = self.save_hook.lock().expect("save hook").take();
        if let Some(hook) = hook {
            hook();
        }
        Ok(CheckpointRestoreReceipt {
            checkpoint_ref: REFERENCE.to_owned(),
            source_session_id: if self.wrong_source.load(Ordering::SeqCst) {
                SessionId::new()
            } else {
                session.clone()
            },
        })
    }

    fn load(
        &self,
        tenant: &TenantId,
        reference: &str,
        _: u64,
        deadline: Instant,
    ) -> Result<LoadedCheckpoint, CheckpointError> {
        assert!(Instant::now() < deadline);
        self.loads.fetch_add(1, Ordering::SeqCst);
        if tenant != &self.tenant
            || reference != REFERENCE
            || self.load_mode.load(Ordering::SeqCst) == 1
        {
            return Err(CheckpointError::Rejected);
        }
        Ok(LoadedCheckpoint {
            receipt: CheckpointRestoreReceipt {
                checkpoint_ref: if self.load_mode.load(Ordering::SeqCst) == 2 {
                    "different-checkpoint-reference".to_owned()
                } else {
                    reference.to_owned()
                },
                source_session_id: self.source.lock().expect("source").clone(),
            },
            snapshot: snapshot(&self.origins.lock().expect("origins")),
        })
    }

    fn cleanup_expired(&self, _: u64) -> Result<usize, CheckpointError> {
        Ok(0)
    }

    fn discard(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        action: &ActionId,
        reference: &str,
    ) -> Result<(), CheckpointError> {
        self.discarded
            .lock()
            .expect("discarded")
            .push(StoredBinding {
                tenant: tenant.clone(),
                session: session.clone(),
                fence: fence.clone(),
                action: action.clone(),
                reference: reference.to_owned(),
            });
        if self.fail_discard.load(Ordering::SeqCst) {
            Err(CheckpointError::Unavailable)
        } else {
            Ok(())
        }
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    worker: Arc<Worker>,
    driver: Arc<FakeDriver>,
    sandbox: Arc<FakeSandbox>,
    store: Arc<FakeStore>,
    clock: Arc<Clock>,
    audit: Option<Arc<AuditWal>>,
    peer: AuthenticatedPeer,
    tenant: TenantId,
    principal: PrincipalId,
    source: CreateSessionOutcome,
}

impl Fixture {
    fn new(audit_record_bytes: Option<usize>) -> Self {
        Self::new_with_runtime(audit_record_bytes, None)
    }
    fn new_with_runtime(
        audit_record_bytes: Option<usize>,
        runtime: Option<Arc<browserd_core::RuntimeSafetyCache>>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("journal directory");
        let peer = AuthenticatedPeer::new("checkpoint-gateway").expect("peer");
        let tenant = TenantId::new();
        let driver = Arc::new(FakeDriver::default());
        let sandbox = Arc::new(FakeSandbox::default());
        let store = Arc::new(FakeStore::new(tenant.clone()));
        let clock = Arc::new(Clock::default());
        let config = WorkerConfig::new(
            WorkerId::new("checkpoint-worker").expect("worker"),
            3,
            InternalEndpoint::loopback("127.0.0.1:9102".parse().expect("address"))
                .expect("endpoint"),
            peer.clone(),
            4,
            16,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).expect("lease"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
                .expect("timeouts"),
            Duration::from_secs(5),
            ActionJournalConfig::with_default_limits(directory.path()).expect("journal config"),
        )
        .expect("worker config");
        let mut worker = WorkerControlPlane::new_with_emergency_policy_and_clock(
            config,
            driver.clone(),
            sandbox.clone(),
            Arc::new(EmergencyPolicy::default()),
            clock.clone(),
        )
        .with_checkpoint_store(store.clone());
        let audit = audit_record_bytes.map(|limit| {
            Arc::new(
                AuditWal::open(
                    directory.path().join("audit.wal"),
                    AuditWalPolicy::new(64 * 1024, limit).expect("audit policy"),
                )
                .expect("audit WAL"),
            )
        });
        if let Some(audit) = &audit {
            worker = worker.with_audit_wal(audit.clone());
        }
        if let Some(runtime) = runtime {
            worker = worker
                .with_runtime_safety_cache(runtime, "17".repeat(32))
                .expect("runtime");
        }
        let worker = Arc::new(worker);
        let source = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: tenant.clone(),
                    idempotency_key: "source".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(0),
            )
            .expect("source session");
        Self {
            directory,
            worker,
            driver,
            sandbox,
            store,
            clock,
            audit,
            peer,
            tenant,
            principal: PrincipalId::new(),
            source,
        }
    }

    fn submit(&self, origins: Vec<String>) -> ActionId {
        self.worker
            .submit_action(
                &self.peer,
                self.principal.clone(),
                &self.source.session_id,
                &self.source.fence,
                "checkpoint-action",
                [2; 32],
                ActionKind::ReadOnly,
                Some(BuiltinFeature::Checkpoint),
                Some(self.source.primary_page_id.clone()),
                serde_json::to_vec(&WorkerActionCommand::Checkpoint { origins }).expect("payload"),
                None,
                SessionTime::new(1),
            )
            .expect("submit checkpoint")
    }

    fn run(&self) -> Result<Option<WorkerActionSnapshot>, WorkerError> {
        self.worker.run_next_action(
            &self.peer,
            &self.source.session_id,
            &self.source.fence,
            SessionTime::new(2),
        )
    }

    fn action(&self, action: &ActionId) -> WorkerActionSnapshot {
        self.worker
            .get_action(
                &self.peer,
                &self.source.session_id,
                action,
                &self.source.fence,
            )
            .expect("durable action snapshot")
    }

    fn restore_command(&self, tenant: TenantId, key: &str) -> CreateSessionCommand {
        CreateSessionCommand {
            tenant_id: tenant,
            idempotency_key: key.to_owned(),
            canonical_request_hash: restore_options()
                .canonical_request_hash(WorkerIsolationProfile::SharedContext),
            placement_version: 1,
            session_incarnation: 1,
        }
    }

    fn restore(&self) -> Result<CreateSessionOutcome, WorkerError> {
        self.worker.create_session_with_options(
            &self.peer,
            self.restore_command(self.tenant.clone(), "restore"),
            &restore_options(),
            SessionTime::new(3),
        )
    }

    fn assert_no_plaintext(&self, action: &ActionId) {
        let public = self.action(action);
        assert!(!format!("{public:?}").contains(RAW_STATE));
        for path in [
            self.directory
                .path()
                .join(format!("{}.wal", self.source.session_id)),
            self.directory.path().join("audit.wal"),
        ] {
            if path.exists() {
                let bytes = std::fs::read(path).expect("durable file");
                assert!(
                    !bytes
                        .windows(RAW_STATE.len())
                        .any(|window| window == RAW_STATE.as_bytes())
                );
            }
        }
        assert_eq!(self.driver.generic_calls.load(Ordering::SeqCst), 0);
    }

    fn cancellation(&self, action: ActionId) -> Hook {
        let worker = Arc::downgrade(&self.worker);
        let peer = self.peer.clone();
        let source = self.source.clone();
        Arc::new(move || {
            let cancelled = worker
                .upgrade()
                .expect("live worker")
                .cancel_action(
                    &peer,
                    &source.session_id,
                    &action,
                    &source.fence,
                    SessionTime::new(3),
                )
                .expect("cancel running capture");
            assert_eq!(cancelled.status, ActionStatus::CancelledConfirmed);
        })
    }
}

fn restore_options() -> WorkerSessionOptionsV1 {
    WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "en-US".to_owned(),
        timezone: "UTC".to_owned(),
        user_agent: None,
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: Some(REFERENCE.to_owned()),
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 60,
        idle_timeout_seconds: 30,
        metadata: BTreeMap::from([("caller".to_owned(), "preserved".to_owned())]),
    }
}

#[test]
fn audit_is_required_before_capture_or_restore_load() {
    for audit in [None, Some(64)] {
        let fixture = Fixture::new(audit);
        let action = fixture.submit(Vec::new());
        let _ = fixture.run();
        assert_eq!(fixture.action(&action).status, ActionStatus::FailedKnown);
        assert_eq!(fixture.driver.captures.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.store.saves.load(Ordering::SeqCst), 0);
        assert!(fixture.restore().is_err());
        assert_eq!(fixture.store.loads.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.driver.created.lock().expect("creates").len(), 1);
        assert_eq!(fixture.sandbox.provisions.load(Ordering::SeqCst), 1);
        fixture.assert_no_plaintext(&action);
    }
}

#[test]
fn checkpoint_specific_audit_failure_blocks_capture_after_generic_intent() {
    let fixture = Fixture::new(Some(512));
    let origins = (0..16)
        .map(|index| format!("https://site-{index}.example.test"))
        .collect();
    let action = fixture.submit(origins);
    let _ = fixture.run();
    let pending = fixture
        .audit
        .as_ref()
        .expect("audit")
        .pending()
        .expect("events");
    assert!(
        pending
            .iter()
            .any(|event| event.event().kind() == "action.dispatch")
    );
    assert!(
        !pending
            .iter()
            .any(|event| event.event().kind() == "checkpoint.create.intent")
    );
    assert_eq!(fixture.action(&action).status, ActionStatus::FailedKnown);
    assert_eq!(fixture.driver.captures.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.saves.load(Ordering::SeqCst), 0);
}

#[test]
fn success_is_reference_only_idempotent_and_restores_a_new_session() {
    let fixture = Fixture::new(Some(4096));
    let origins = vec!["https://example.test".to_owned()];
    let action = fixture.submit(origins.clone());
    let completed = fixture.run().expect("run").expect("checkpoint result");
    assert_eq!(completed.status, ActionStatus::Succeeded);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(completed.result.as_ref().expect("result"))
            .expect("JSON"),
        serde_json::json!({"checkpoint_ref": REFERENCE}),
    );
    assert_eq!(fixture.submit(origins), action);
    assert!(fixture.run().expect("idempotent run").is_none());
    assert_eq!(fixture.driver.captures.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.saves.load(Ordering::SeqCst), 1);
    let original_options = restore_options();
    let command = fixture.restore_command(fixture.tenant.clone(), "restore");
    let restored = fixture
        .worker
        .create_session_with_options(
            &fixture.peer,
            command.clone(),
            &original_options,
            SessionTime::new(3),
        )
        .expect("restore");
    assert_ne!(restored.session_id, fixture.source.session_id);
    assert_ne!(restored.primary_page_id, fixture.source.primary_page_id);
    assert_eq!(
        restored.restored_checkpoint,
        Some(CheckpointRestoreReceipt {
            checkpoint_ref: REFERENCE.to_owned(),
            source_session_id: fixture.source.session_id.clone(),
        })
    );
    let mut browser_options = original_options.clone();
    browser_options.checkpoint_ref = None;
    assert_eq!(
        fixture.driver.created.lock().expect("creates")[1].options,
        Some(browser_options)
    );
    assert_eq!(original_options, restore_options());
    let retry = fixture
        .worker
        .create_session_with_options(
            &fixture.peer,
            command.clone(),
            &original_options,
            SessionTime::new(4),
        )
        .expect("idempotent restore");
    assert!(retry.existing);
    assert_eq!(retry.session_id, restored.session_id);
    assert_eq!(fixture.store.loads.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.driver.restored.lock().expect("restores").len(), 1);
    let mut conflict = command;
    conflict.canonical_request_hash = [9; 32];
    assert_eq!(
        fixture
            .worker
            .create_session_with_options(
                &fixture.peer,
                conflict,
                &original_options,
                SessionTime::new(5),
            )
            .err(),
        Some(WorkerError::IdempotencyConflict)
    );
    assert_eq!(
        fixture
            .worker
            .get_session(&fixture.peer, &restored.session_id, &restored.fence,)
            .expect("restored session")
            .lifecycle,
        SessionLifecycle::Ready
    );
    fixture.assert_no_plaintext(&action);
}

#[test]
fn rejected_loads_wrong_tenants_and_wrong_receipts_never_allocate_contexts() {
    for mode in 0..3 {
        let fixture = Fixture::new(Some(4096));
        fixture.store.load_mode.store(mode, Ordering::SeqCst);
        let tenant = if mode == 0 {
            TenantId::new()
        } else {
            fixture.tenant.clone()
        };
        assert!(
            fixture
                .worker
                .create_session_with_options(
                    &fixture.peer,
                    fixture.restore_command(tenant, "restore-rejected"),
                    &restore_options(),
                    SessionTime::new(1),
                )
                .is_err()
        );
        assert_eq!(fixture.store.loads.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.driver.created.lock().expect("creates").len(), 1);
        assert!(fixture.driver.restored.lock().expect("restores").is_empty());
        assert!(fixture.driver.closed.lock().expect("closes").is_empty());
        assert_eq!(fixture.sandbox.provisions.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn partial_restore_failure_cleans_exact_new_context_and_failed_cleanup_blocks_capacity() {
    for cleanup_fails in [false, true] {
        let fixture = Fixture::new(Some(4096));
        fixture.driver.fail_restore.store(true, Ordering::SeqCst);
        fixture
            .driver
            .fail_cleanup
            .store(cleanup_fails, Ordering::SeqCst);
        assert_eq!(
            fixture.restore().err(),
            Some(if cleanup_fails {
                WorkerError::CleanupFailed
            } else {
                WorkerError::DependencyUnavailable
            })
        );
        let created = fixture.driver.created.lock().expect("creates")[1].clone();
        assert_ne!(created.session, fixture.source.session_id);
        assert_eq!(
            fixture.driver.closed.lock().expect("closes").as_slice(),
            &[(created.session.clone(), created.fence.clone())]
        );
        assert_eq!(
            fixture.sandbox.cleaned.lock().expect("cleanup").as_slice(),
            std::slice::from_ref(&created.session)
        );
        assert!(
            fixture
                .worker
                .get_session(&fixture.peer, &created.session, &created.fence)
                .is_err()
        );
        assert_eq!(fixture.worker.is_ready(), !cleanup_fails);
        if cleanup_fails {
            assert_eq!(
                fixture
                    .worker
                    .create_session(
                        &fixture.peer,
                        CreateSessionCommand {
                            tenant_id: fixture.tenant.clone(),
                            idempotency_key: "after-uncertain-cleanup".to_owned(),
                            canonical_request_hash: [7; 32],
                            placement_version: 1,
                            session_incarnation: 1,
                        },
                        SessionTime::new(2)
                    )
                    .err(),
                Some(WorkerError::NotReady)
            );
            assert_eq!(fixture.driver.created.lock().expect("creates").len(), 2);
            assert_eq!(fixture.sandbox.provisions.load(Ordering::SeqCst), 2);
        }
    }
}

#[test]
fn successful_restore_after_initial_lease_expiry_is_cleaned_without_publishing_ready() {
    let fixture = Fixture::new(Some(4096));
    let clock = fixture.clock.clone();
    *fixture.driver.restore_hook.lock().expect("restore hook") = Some(Arc::new(move || {
        clock.0.store(60_000, Ordering::SeqCst);
    }));
    assert_eq!(
        fixture.restore().err(),
        Some(WorkerError::DependencyUnavailable)
    );
    assert_eq!(fixture.driver.restored.lock().expect("restores").len(), 1);
    assert_eq!(fixture.driver.created.lock().expect("creates").len(), 2);
    let created = fixture.driver.created.lock().expect("creates")[1].clone();
    assert_ne!(created.session, fixture.source.session_id);
    assert_eq!(
        fixture.driver.closed.lock().expect("closes").as_slice(),
        &[(created.session.clone(), created.fence.clone())]
    );
    assert_eq!(
        fixture.sandbox.cleaned.lock().expect("cleanup").as_slice(),
        std::slice::from_ref(&created.session)
    );
    assert!(
        fixture
            .worker
            .get_session(&fixture.peer, &created.session, &created.fence)
            .is_err()
    );
    assert!(
        !fixture
            .directory
            .path()
            .join(format!("{}.wal", created.session))
            .exists()
    );
    assert_eq!(fixture.driver.generic_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_or_expiry_during_capture_prevents_storage_and_plaintext_publication() {
    for cancel in [false, true] {
        let fixture = Fixture::new(Some(4096));
        let action = fixture.submit(Vec::new());
        let hook = if cancel {
            fixture.cancellation(action.clone())
        } else {
            let clock = fixture.clock.clone();
            Arc::new(move || {
                clock.0.store(60_000, Ordering::SeqCst);
            }) as Hook
        };
        *fixture.driver.capture_hook.lock().expect("hook") = Some(hook);
        let _ = fixture.run();
        let completed = fixture.action(&action);
        assert_eq!(
            completed.status,
            if cancel {
                ActionStatus::CancelledConfirmed
            } else {
                ActionStatus::FailedKnown
            }
        );
        assert!(completed.result.is_none());
        assert_eq!(fixture.driver.captures.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.store.saves.load(Ordering::SeqCst), 0);
        fixture.assert_no_plaintext(&action);
    }
}

#[test]
fn unexpected_origins_and_foreign_save_receipts_fail_closed() {
    for wrong_receipt in [false, true] {
        let fixture = Fixture::new(Some(4096));
        fixture
            .driver
            .unexpected_origin
            .store(!wrong_receipt, Ordering::SeqCst);
        fixture
            .store
            .wrong_source
            .store(wrong_receipt, Ordering::SeqCst);
        let action = fixture.submit(Vec::new());
        let _ = fixture.run();
        let completed = fixture.action(&action);
        assert_eq!(
            completed.status,
            if wrong_receipt {
                ActionStatus::OutcomeUnknown
            } else {
                ActionStatus::FailedKnown
            }
        );
        assert!(completed.result.is_none());
        assert_eq!(
            fixture.store.saves.load(Ordering::SeqCst),
            usize::from(wrong_receipt)
        );
        fixture.assert_no_plaintext(&action);
    }
}

#[test]
fn cancellation_during_save_discards_the_exact_unpublished_checkpoint() {
    let fixture = Fixture::new(Some(4096));
    let action = fixture.submit(Vec::new());
    *fixture.store.save_hook.lock().expect("hook") = Some(fixture.cancellation(action.clone()));
    let _ = fixture.run();
    let completed = fixture.action(&action);
    assert_eq!(completed.status, ActionStatus::CancelledConfirmed);
    assert!(completed.result.is_none());
    assert_eq!(fixture.store.saves.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.store.discarded.lock().expect("discarded"),
        *fixture.store.saved.lock().expect("saved")
    );
    assert_eq!(fixture.store.discarded.lock().expect("discarded").len(), 1);
    fixture.assert_no_plaintext(&action);
}

#[test]
fn failed_discard_of_unpublished_checkpoint_blocks_readiness_and_new_allocations() {
    let fixture = Fixture::new(Some(4096));
    let action = fixture.submit(Vec::new());
    fixture.store.fail_discard.store(true, Ordering::SeqCst);
    *fixture.store.save_hook.lock().expect("hook") = Some(fixture.cancellation(action.clone()));
    let _ = fixture.run();
    let completed = fixture.action(&action);
    assert_eq!(completed.status, ActionStatus::CancelledConfirmed);
    assert!(completed.result.is_none());
    assert_eq!(fixture.store.saves.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.store.discarded.lock().expect("discarded"),
        *fixture.store.saved.lock().expect("saved")
    );
    assert_eq!(fixture.store.discarded.lock().expect("discarded").len(), 1);
    assert!(!fixture.worker.is_ready());
    assert_eq!(
        fixture
            .worker
            .create_session(
                &fixture.peer,
                CreateSessionCommand {
                    tenant_id: fixture.tenant.clone(),
                    idempotency_key: "after-unpublished-checkpoint-cleanup-failure".to_owned(),
                    canonical_request_hash: [8; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(4),
            )
            .err(),
        Some(WorkerError::NotReady)
    );
    assert_eq!(fixture.driver.created.lock().expect("creates").len(), 1);
    assert_eq!(fixture.sandbox.provisions.load(Ordering::SeqCst), 1);
    fixture.assert_no_plaintext(&action);
}

#[test]
fn runtime_checkpoint_disable_blocks_restore_before_sensitive_store_load_or_new_context() {
    use browserd_core::{RuntimeSafetyCache, SafetySwitchMutation, SafetySwitchSnapshot};
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = uuid::Uuid::new_v4();
    let initial = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("intent")
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("density");
    cache
        .install(namespace, initial.clone(), Duration::from_secs(30))
        .expect("authority");
    let fixture = Fixture::new_with_runtime(Some(4096), Some(cache.clone()));
    cache
        .install(
            namespace,
            initial
                .apply(&SafetySwitchMutation::DisableCheckpoint(true))
                .expect("disable"),
            Duration::from_secs(30),
        )
        .expect("update");
    assert!(fixture.restore().is_err());
    assert_eq!(fixture.store.loads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.driver.created.lock().expect("creates").len(), 1);
    assert!(
        fixture
            .driver
            .restored
            .lock()
            .expect("restore effects")
            .is_empty()
    );
}
