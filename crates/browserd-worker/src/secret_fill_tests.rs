#![allow(clippy::expect_used)]

use super::*;
use crate::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::time::Duration;

const TEST_VALUE: &str = "only-in-private-value-file-한글";

fn private_write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("private fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("private mode");
}

struct CatalogFixture {
    directory: tempfile::TempDir,
    tenant: TenantId,
    principal: PrincipalId,
    origin: Origin,
}

impl CatalogFixture {
    fn new() -> Self {
        let fixture = Self {
            directory: tempfile::tempdir().expect("private directory"),
            tenant: TenantId::new(),
            principal: PrincipalId::new(),
            origin: Origin::parse("https://login.example.test:8443").expect("origin"),
        };
        std::fs::set_permissions(
            fixture.directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("private directory mode");
        fixture.write_catalog("credential.value", vec![fixture.origin.as_str().to_owned()]);
        private_write(
            &fixture.directory.path().join("credential.value"),
            TEST_VALUE.as_bytes(),
        );
        fixture
    }

    fn write_catalog(&self, filename: &str, origins: Vec<String>) {
        let catalog = serde_json::json!({
            "schema_version": 1,
            "grants": [{ "tenant_id": self.tenant, "principal_ids": [self.principal],
                "secret_ref": "credential-ref", "allowed_origins": origins, "value_file": filename }]
        });
        private_write(
            &self.config(),
            &serde_json::to_vec(&catalog).expect("catalog JSON"),
        );
    }

    fn config(&self) -> std::path::PathBuf {
        self.directory.path().join("secrets.json")
    }

    fn resolver(&self) -> FileSecretResolver {
        FileSecretResolver::open(&self.config()).expect("provider")
    }

    fn grant(&self, provider: &FileSecretResolver) -> SecretGrant {
        provider
            .authorize(
                &self.tenant,
                &self.principal,
                "credential-ref",
                &self.origin,
                Instant::now() + Duration::from_secs(2),
            )
            .expect("grant")
    }
}

#[test]
fn provider_authorizes_exact_tenant_principal_origin_and_port_without_reading_values() {
    let fixture = CatalogFixture::new();
    let provider = fixture.resolver();
    std::fs::remove_file(fixture.directory.path().join("credential.value")).expect("remove value");
    let deadline = Instant::now() + Duration::from_secs(2);
    let grant = fixture.grant(&provider);
    assert_eq!(
        provider.resolve(&grant, deadline).err(),
        Some(SecretFillError::Unavailable)
    );
    for (tenant, principal, origin) in [
        (
            TenantId::new(),
            fixture.principal.clone(),
            fixture.origin.clone(),
        ),
        (
            fixture.tenant.clone(),
            PrincipalId::new(),
            fixture.origin.clone(),
        ),
        (
            fixture.tenant.clone(),
            fixture.principal.clone(),
            Origin::parse("https://login.example.test").expect("origin"),
        ),
        (
            fixture.tenant.clone(),
            fixture.principal.clone(),
            Origin::parse("http://login.example.test:8443").expect("origin"),
        ),
        (
            fixture.tenant.clone(),
            fixture.principal.clone(),
            Origin::parse("https://other.example.test:8443").expect("origin"),
        ),
    ] {
        assert_eq!(
            provider
                .authorize(&tenant, &principal, "credential-ref", &origin, deadline)
                .err(),
            Some(SecretFillError::Rejected)
        );
    }
    assert_eq!(
        provider
            .authorize(
                &fixture.tenant,
                &fixture.principal,
                "unknown-ref",
                &fixture.origin,
                deadline
            )
            .err(),
        Some(SecretFillError::Rejected)
    );
}

#[test]
fn provider_preserves_unicode_and_empty_values_and_redacts_debug() {
    let fixture = CatalogFixture::new();
    let provider = fixture.resolver();
    let grant = fixture.grant(&provider);
    let value = provider
        .resolve(&grant, Instant::now() + Duration::from_secs(2))
        .expect("value");
    assert_eq!(value.value(), TEST_VALUE);
    assert_eq!(value.grant(), &grant);
    assert_eq!(format!("{value:?}"), "ResolvedSecret([REDACTED])");
    assert!(!format!("{grant:?}").contains("credential-ref"));
    private_write(&fixture.directory.path().join("credential.value"), b"");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .expect("empty")
            .value(),
        ""
    );
}

#[test]
fn provider_rejects_foreign_provider_grants_and_expired_deadlines() {
    let fixture = CatalogFixture::new();
    let provider = fixture.resolver();
    let other_provider = fixture.resolver();
    let grant = fixture.grant(&provider);
    assert_eq!(
        other_provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(SecretFillError::Rejected)
    );
    assert_eq!(
        provider.resolve(&grant, Instant::now()).err(),
        Some(SecretFillError::DeadlineBeforeDispatch)
    );
    assert_eq!(
        provider
            .authorize(
                &fixture.tenant,
                &fixture.principal,
                "credential-ref",
                &fixture.origin,
                Instant::now()
            )
            .err(),
        Some(SecretFillError::DeadlineBeforeDispatch)
    );
}

#[test]
fn provider_bounds_bytes_and_rejects_non_utf8_without_reflecting_values() {
    let fixture = CatalogFixture::new();
    let provider = fixture.resolver();
    let grant = fixture.grant(&provider);
    private_write(
        &fixture.directory.path().join("credential.value"),
        &vec![b'x'; MAX_SECRET_BYTES],
    );
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .expect("exact bound")
            .value()
            .len(),
        MAX_SECRET_BYTES
    );
    for bytes in [vec![b'x'; MAX_SECRET_BYTES + 1], vec![0xff, 0xfe]] {
        private_write(&fixture.directory.path().join("credential.value"), &bytes);
        assert_eq!(
            provider
                .resolve(&grant, Instant::now() + Duration::from_secs(2))
                .err(),
            Some(SecretFillError::Rejected)
        );
    }
}

#[test]
fn bounded_reads_reserve_the_full_limit_to_prevent_secret_allocation_reuse_on_growth() {
    let fixture = CatalogFixture::new();
    let mut file = private_file(
        &open_private_directory(fixture.directory.path(), nix::unistd::geteuid().as_raw())
            .expect("directory"),
        "credential.value",
        nix::unistd::geteuid().as_raw(),
    )
    .expect("file");
    let bytes = read_bounded(
        &mut file,
        MAX_SECRET_BYTES,
        Instant::now() + Duration::from_secs(2),
    )
    .expect("bounded read");
    assert_eq!(bytes.as_slice(), TEST_VALUE.as_bytes());
    assert!(bytes.capacity() >= MAX_SECRET_BYTES);
}

#[test]
fn provider_rejects_unsafe_names_origin_aliases_and_invalid_catalogs() {
    let fixture = CatalogFixture::new();
    for filename in [
        "../credential.value",
        "/credential.value",
        "nested/value",
        "a\\b",
        ".",
        "..",
        "secrets.json",
    ] {
        fixture.write_catalog(filename, vec![fixture.origin.as_str().to_owned()]);
        assert!(FileSecretResolver::open(&fixture.config()).is_err());
    }
    for origin in [
        "https://login.example.test:8443/",
        "https://login.example.test:8443/path",
        "https://login.example.test:8443?q=x",
        "https://u:p@login.example.test:8443",
        "https://login.example.test:443",
        "https://LOGIN.example.test:8443",
        "null",
        "file:///tmp/x",
    ] {
        fixture.write_catalog("credential.value", vec![origin.to_owned()]);
        assert!(FileSecretResolver::open(&fixture.config()).is_err());
    }
    fixture.write_catalog(
        "credential.value",
        vec![fixture.origin.as_str().to_owned(); 2],
    );
    assert!(FileSecretResolver::open(&fixture.config()).is_err());
    let duplicate = serde_json::json!({"schema_version":1, "grants": [
        {"tenant_id": fixture.tenant, "principal_ids":[fixture.principal], "secret_ref":"credential-ref", "allowed_origins":[fixture.origin.as_str()],"value_file":"credential.value"},
        {"tenant_id": fixture.tenant, "principal_ids":[fixture.principal], "secret_ref":"credential-ref", "allowed_origins":[fixture.origin.as_str()],"value_file":"credential.value"}
    ]});
    private_write(
        &fixture.config(),
        &serde_json::to_vec(&duplicate).expect("duplicate catalog"),
    );
    assert!(FileSecretResolver::open(&fixture.config()).is_err());
    private_write(&fixture.config(), &vec![b' '; MAX_CATALOG_BYTES + 1]);
    assert!(FileSecretResolver::open(&fixture.config()).is_err());
    private_write(&fixture.config(), br#"{"schema_version":2,"grants":[]}"#);
    assert!(FileSecretResolver::open(&fixture.config()).is_err());
    private_write(
        &fixture.config(),
        br#"{"schema_version":1,"grants":[],"value":"must-never-be-inline"}"#,
    );
    assert!(FileSecretResolver::open(&fixture.config()).is_err());
}

#[test]
fn provider_rejects_symlinks_hardlinks_fifo_directory_and_broad_permissions() {
    let fixture = CatalogFixture::new();
    let provider = fixture.resolver();
    let grant = fixture.grant(&provider);
    let value_path = fixture.directory.path().join("credential.value");
    std::fs::hard_link(&value_path, fixture.directory.path().join("extra-link")).expect("hardlink");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(SecretFillError::Rejected)
    );
    std::fs::remove_file(fixture.directory.path().join("extra-link")).expect("remove hardlink");
    std::fs::set_permissions(&value_path, std::fs::Permissions::from_mode(0o644))
        .expect("broad mode");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(SecretFillError::Rejected)
    );
    std::fs::remove_file(&value_path).expect("remove value");
    symlink(fixture.config(), &value_path).expect("symlink");
    assert!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .is_err()
    );
    std::fs::remove_file(&value_path).expect("remove symlink");
    nix::unistd::mkfifo(&value_path, Mode::S_IRUSR | Mode::S_IWUSR).expect("fifo");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(SecretFillError::Rejected)
    );
    std::fs::remove_file(&value_path).expect("remove fifo");
    std::fs::create_dir(&value_path).expect("directory value");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(SecretFillError::Rejected)
    );
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("broad directory");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .err(),
        Some(SecretFillError::Rejected)
    );
    assert!(FileSecretResolver::open(&fixture.config()).is_err());
}

#[test]
fn provider_pins_directory_fd_and_supports_operator_atomic_value_rotation() {
    let fixture = CatalogFixture::new();
    let provider = fixture.resolver();
    let grant = fixture.grant(&provider);
    let directory = fixture.directory.path();
    private_write(&directory.join("new.value"), b"rotated-fixture-value");
    std::fs::rename(
        directory.join("new.value"),
        directory.join("credential.value"),
    )
    .expect("atomic rotation");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .expect("rotation")
            .value(),
        "rotated-fixture-value"
    );
    let outside = tempfile::tempdir().expect("replacement root");
    std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private replacement");
    let retained = outside.path().join("retained");
    std::fs::rename(directory, &retained).expect("move pinned directory");
    std::fs::create_dir(directory).expect("replacement pathname");
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
        .expect("private replacement");
    private_write(&directory.join("credential.value"), b"wrong-pathname-value");
    assert_eq!(
        provider
            .resolve(&grant, Instant::now() + Duration::from_secs(2))
            .expect("pinned directory")
            .value(),
        "rotated-fixture-value"
    );
}

type Hook = Arc<dyn Fn() + Send + Sync>;

struct CountingResolver {
    provider: FileSecretResolver,
    authorizations: AtomicUsize,
    reads: AtomicUsize,
    authorize_hook: Mutex<Option<Hook>>,
    read_hook: Mutex<Option<Hook>>,
}

impl SecretResolver for CountingResolver {
    fn authorize(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        reference: &str,
        origin: &Origin,
        deadline: Instant,
    ) -> Result<SecretGrant, SecretFillError> {
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        let hook = self.authorize_hook.lock().expect("authorize hook").clone();
        if let Some(hook) = hook {
            hook();
        }
        self.provider
            .authorize(tenant, principal, reference, origin, deadline)
    }
    fn resolve(
        &self,
        grant: &SecretGrant,
        deadline: Instant,
    ) -> Result<ResolvedSecret, SecretFillError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let hook = self.read_hook.lock().expect("hook").clone();
        if let Some(hook) = hook {
            hook();
        }
        self.provider.resolve(grant, deadline)
    }
}

#[derive(Default)]
struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::Acquire)))
    }
}

struct SecretDriver {
    origin: Origin,
    observed: Mutex<Option<SecretFillTarget>>,
    observations: AtomicUsize,
    calls: AtomicUsize,
    effects: AtomicUsize,
    generic_calls: AtomicUsize,
    values: Mutex<Vec<String>>,
    outcome: ActionExecutionResult,
    effect_hook: Mutex<Option<Hook>>,
    drift: Mutex<Option<SecretFillTarget>>,
}

impl ChromiumDriver for SecretDriver {
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
    fn inspect_secret_fill_target_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        _: Instant,
    ) -> Result<SecretFillTarget, SecretFillError> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        let target = SecretFillTarget {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            page_id: page.clone(),
            fence: fence.clone(),
            node_ref: node_ref.to_owned(),
            target_incarnation: 2,
            frame_document_epoch: 3,
            url_revision: 4,
            origin: self.origin.clone(),
        };
        *self.observed.lock().expect("observed") = Some(target.clone());
        Ok(target)
    }
    fn execute_secret_fill_until(
        &self,
        target: &SecretFillTarget,
        value: ResolvedSecret,
        _: Instant,
        commit: &mut dyn FnMut(&SecretFillTarget) -> Result<(), SecretFillError>,
    ) -> Result<ActionExecutionResult, SecretFillError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let hook = self.effect_hook.lock().expect("effect hook").clone();
        if let Some(hook) = hook {
            hook();
        }
        let drift = self.drift.lock().expect("drift").clone();
        commit(drift.as_ref().unwrap_or(target))?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        self.values
            .lock()
            .expect("values")
            .push(value.value().to_owned());
        Ok(self.outcome.clone())
    }
}

#[derive(Default)]
struct Sandbox;
impl SandboxClient for Sandbox {
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
}

struct Fixture {
    worker: WorkerControlPlane<SecretDriver, Sandbox>,
    catalog: CatalogFixture,
    provider: Arc<CountingResolver>,
    driver: Arc<SecretDriver>,
    policy: Arc<EmergencyPolicy>,
    clock: Arc<Clock>,
    created: CreateSessionOutcome,
    peer: AuthenticatedPeer,
    audit: Option<Arc<AuditWal>>,
    _journal: tempfile::TempDir,
}

impl Fixture {
    fn new(outcome: ActionExecutionResult, audit_bytes: Option<u64>) -> Self {
        let catalog = CatalogFixture::new();
        let provider = Arc::new(CountingResolver {
            provider: catalog.resolver(),
            authorizations: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            authorize_hook: Mutex::new(None),
            read_hook: Mutex::new(None),
        });
        let driver = Arc::new(SecretDriver {
            origin: catalog.origin.clone(),
            observed: Mutex::new(None),
            observations: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            generic_calls: AtomicUsize::new(0),
            values: Mutex::new(Vec::new()),
            outcome,
            effect_hook: Mutex::new(None),
            drift: Mutex::new(None),
        });
        let journal = tempfile::tempdir().expect("journal");
        let peer = AuthenticatedPeer::new("secret-gateway").expect("peer");
        let config = WorkerConfig::new(
            WorkerId::new("secret-worker").expect("worker"),
            3,
            InternalEndpoint::loopback("127.0.0.1:9101".parse().expect("address"))
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
        .expect("worker config");
        let clock = Arc::new(Clock::default());
        let policy = Arc::new(EmergencyPolicy::default());
        let mut worker = WorkerControlPlane::new_with_emergency_policy_and_clock(
            config,
            driver.clone(),
            Arc::new(Sandbox),
            policy.clone(),
            clock.clone(),
        )
        .with_secret_resolver(provider.clone());
        let audit = audit_bytes.map(|limit| {
            Arc::new(
                AuditWal::open(
                    journal.path().join("audit.wal"),
                    browserd_observability::AuditWalPolicy::new(limit, limit.min(4096) as usize)
                        .expect("audit policy"),
                )
                .expect("audit"),
            )
        });
        if let Some(wal) = &audit {
            worker = worker.with_audit_wal(wal.clone());
        }
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: catalog.tenant.clone(),
                    idempotency_key: "secret-create".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(0),
            )
            .expect("create");
        Self {
            worker,
            catalog,
            provider,
            driver,
            policy,
            clock,
            created,
            peer,
            audit,
            _journal: journal,
        }
    }

    fn submit(&self, principal: PrincipalId) -> ActionId {
        let payload = serde_json::to_vec(&WorkerActionCommand::FillSecret {
            node_ref: "credential-node".to_owned(),
            secret_ref: "credential-ref".to_owned(),
        })
        .expect("ref-only payload");
        self.worker
            .submit_action(
                &self.peer,
                principal,
                &self.created.session_id,
                &self.created.fence,
                "credential-action",
                Sha256::digest(&payload).into(),
                ActionKind::Mutating,
                Some(BuiltinFeature::CoreInput),
                Some(self.created.primary_page_id.clone()),
                payload,
                None,
                SessionTime::new(1),
            )
            .expect("submit")
    }

    fn run(&self) -> WorkerActionSnapshot {
        self.worker
            .run_next_action(
                &self.peer,
                &self.created.session_id,
                &self.created.fence,
                SessionTime::new(2),
            )
            .expect("run")
            .expect("action")
    }
}

#[test]
fn worker_requires_metadata_permission_and_mandatory_audit_before_value_read() {
    let no_audit = Fixture::new(
        ActionExecutionResult::Succeeded(TEST_VALUE.as_bytes().to_vec()),
        None,
    );
    no_audit.submit(no_audit.catalog.principal.clone());
    assert_eq!(no_audit.run().status, ActionStatus::FailedKnown);
    assert_eq!(no_audit.provider.reads.load(Ordering::SeqCst), 0);
    assert_eq!(no_audit.driver.effects.load(Ordering::SeqCst), 0);
    let wrong_principal = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    wrong_principal.submit(PrincipalId::new());
    assert_eq!(wrong_principal.run().status, ActionStatus::FailedKnown);
    assert_eq!(wrong_principal.provider.reads.load(Ordering::SeqCst), 0);
    assert_eq!(wrong_principal.driver.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn worker_audit_full_and_revoked_secret_fail_closed_without_value_reads() {
    let full = Fixture::new(ActionExecutionResult::Succeeded(Vec::new()), Some(512));
    let wal = full.audit.as_ref().expect("audit");
    wal.append(AuditEvent::new(
        AuditEventId::new("occupy").expect("id"),
        "occupied",
        vec![b'x'; 430],
        true,
    ))
    .expect("fill WAL");
    full.submit(full.catalog.principal.clone());
    assert_eq!(full.run().status, ActionStatus::FailedKnown);
    assert_eq!(full.provider.reads.load(Ordering::SeqCst), 0);
    let revoked = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    revoked
        .policy
        .revoke_secret("credential-ref")
        .expect("revoke");
    revoked.submit(revoked.catalog.principal.clone());
    assert_eq!(revoked.run().status, ActionStatus::FailedKnown);
    assert_eq!(revoked.provider.reads.load(Ordering::SeqCst), 0);
    assert_eq!(revoked.driver.effects.load(Ordering::SeqCst), 0);
}

#[test]
fn worker_specific_credential_audit_failure_blocks_value_read_after_generic_audit_succeeds() {
    let fixture = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    let wal = fixture.audit.as_ref().expect("audit").clone();
    *fixture.provider.authorize_hook.lock().expect("hook") = Some(Arc::new(move || {
        for index in 0..100 {
            let result = wal.append(AuditEvent::new(
                AuditEventId::new(format!("fill-{index}")).expect("id"),
                "fill",
                vec![b'x'; 3800],
                true,
            ));
            if result.is_err() {
                break;
            }
        }
        // Consume the remaining tail without admitting the larger credential event.
        for index in 0..100 {
            let result = wal.append(AuditEvent::new(
                AuditEventId::new(format!("tail-{index}")).expect("id"),
                "tail",
                vec![b'x'; 64],
                true,
            ));
            if result.is_err() {
                break;
            }
        }
    }));
    fixture.submit(fixture.catalog.principal.clone());
    assert_eq!(fixture.run().status, ActionStatus::FailedKnown);
    assert_eq!(fixture.provider.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.provider.reads.load(Ordering::SeqCst), 0);
    let events = fixture
        .audit
        .as_ref()
        .expect("audit")
        .pending()
        .expect("events");
    assert!(
        events
            .iter()
            .any(|pending| pending.event().kind() == "action.dispatch")
    );
    assert!(
        !events
            .iter()
            .any(|pending| pending.event().kind() == "credential.inject.intent")
    );
    assert_eq!(fixture.driver.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn public_cancel_during_secret_resolution_prevents_commit_without_holding_session_state() {
    use std::sync::mpsc;
    let fixture = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    let action = fixture.submit(fixture.catalog.principal.clone());
    let (reading_tx, reading_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    *fixture.provider.read_hook.lock().expect("hook") = Some(Arc::new(move || {
        reading_tx.send(()).expect("reading signal");
        release_rx
            .lock()
            .expect("release lock")
            .recv_timeout(Duration::from_secs(5))
            .expect("release");
    }));
    let worker = Arc::new(fixture.worker);
    let running_worker = worker.clone();
    let running_session = fixture.created.session_id.clone();
    let running_fence = fixture.created.fence.clone();
    let running_peer = fixture.peer.clone();
    let running = std::thread::spawn(move || {
        running_worker.run_next_action(
            &running_peer,
            &running_session,
            &running_fence,
            SessionTime::new(2),
        )
    });
    reading_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("value resolution entered");
    let cancelled = worker
        .cancel_action(
            &fixture.peer,
            &fixture.created.session_id,
            &action,
            &fixture.created.fence,
            SessionTime::new(2),
        )
        .expect("cancel before commit");
    assert_eq!(cancelled.status, ActionStatus::CancelledConfirmed);
    release_tx.send(()).expect("release resolution");
    assert_eq!(
        running.join().expect("worker thread").err(),
        Some(WorkerError::InvalidActionTransition)
    );
    let terminal = worker
        .get_action(
            &fixture.peer,
            &fixture.created.session_id,
            &action,
            &fixture.created.fence,
        )
        .expect("terminal action");
    assert_eq!(terminal.status, ActionStatus::CancelledConfirmed);
    assert_eq!(fixture.driver.effects.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.driver.calls.load(Ordering::SeqCst), 0);
    assert!(fixture.driver.values.lock().expect("no values").is_empty());
}

#[test]
fn worker_rechecks_revoke_and_target_drift_at_effect_commit() {
    let revoke = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    let policy = revoke.policy.clone();
    *revoke.driver.effect_hook.lock().expect("hook") = Some(Arc::new(move || {
        policy.revoke_secret("credential-ref").expect("revoke");
    }));
    revoke.submit(revoke.catalog.principal.clone());
    assert_eq!(revoke.run().status, ActionStatus::FailedKnown);
    assert_eq!(revoke.provider.reads.load(Ordering::SeqCst), 1);
    assert_eq!(revoke.driver.effects.load(Ordering::SeqCst), 0);

    for drift in [
        "origin", "document", "url", "target", "page", "fence", "node", "tenant",
    ] {
        let fixture = Fixture::new(
            ActionExecutionResult::Succeeded(Vec::new()),
            Some(64 * 1024),
        );
        let mut target = SecretFillTarget {
            tenant_id: fixture.catalog.tenant.clone(),
            session_id: fixture.created.session_id.clone(),
            page_id: fixture.created.primary_page_id.clone(),
            fence: fixture.created.fence.clone(),
            node_ref: "credential-node".to_owned(),
            target_incarnation: 2,
            frame_document_epoch: 3,
            url_revision: 4,
            origin: fixture.catalog.origin.clone(),
        };
        match drift {
            "origin" => {
                target.origin = Origin::parse("https://login.example.test").expect("other port")
            }
            "document" => target.frame_document_epoch += 1,
            "url" => target.url_revision += 1,
            "target" => target.target_incarnation += 1,
            "page" => target.page_id = PageId::new(),
            "fence" => {
                target.fence =
                    OwnershipFence::new(fixture.created.fence.worker_id().clone(), 99, 1, 1)
            }
            "node" => target.node_ref = "other-node".to_owned(),
            "tenant" => target.tenant_id = TenantId::new(),
            _ => unreachable!("enumerated drift"),
        }
        *fixture.driver.drift.lock().expect("drift") = Some(target);
        fixture.submit(fixture.catalog.principal.clone());
        assert_eq!(fixture.run().status, ActionStatus::FailedKnown);
        assert_eq!(fixture.driver.effects.load(Ordering::SeqCst), 0, "{drift}");
    }
}

#[test]
fn worker_rechecks_lease_and_cancellation_before_effect_commit() {
    let expired = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    let clock = expired.clock.clone();
    *expired.driver.effect_hook.lock().expect("hook") = Some(Arc::new(move || {
        clock.0.store(60_000, Ordering::Release);
    }));
    expired.submit(expired.catalog.principal.clone());
    assert_eq!(expired.run().status, ActionStatus::FailedKnown);
    assert_eq!(expired.driver.effects.load(Ordering::SeqCst), 0);
    let cancelled = Fixture::new(
        ActionExecutionResult::Succeeded(Vec::new()),
        Some(64 * 1024),
    );
    let executor = cancelled
        .worker
        .session(&cancelled.created.session_id)
        .expect("executor");
    *cancelled.driver.effect_hook.lock().expect("hook") = Some(Arc::new(move || {
        assert_eq!(
            stop_or_observe_approved_dispatch(&executor),
            APPROVED_DISPATCH_REVOKE_REQUESTED
        );
    }));
    cancelled.submit(cancelled.catalog.principal.clone());
    assert_eq!(cancelled.run().status, ActionStatus::FailedKnown);
    assert_eq!(cancelled.driver.effects.load(Ordering::SeqCst), 0);
}

#[test]
fn public_secret_action_success_and_unknown_are_not_replayed_and_never_persist_values() {
    for outcome in [
        ActionExecutionResult::Succeeded(TEST_VALUE.as_bytes().to_vec()),
        ActionExecutionResult::OutcomeUnknown,
    ] {
        let fixture = Fixture::new(outcome.clone(), Some(64 * 1024));
        let action = fixture.submit(fixture.catalog.principal.clone());
        let journal_path = fixture
            .worker
            .config
            .action_journal
            .session_path(&fixture.created.session_id);
        let accepted = std::fs::read(&journal_path).expect("accepted WAL");
        assert_eq!(fixture.submit(fixture.catalog.principal.clone()), action);
        assert_eq!(std::fs::read(&journal_path).expect("same WAL"), accepted);
        let completed = fixture.run();
        let (status, state) = if matches!(outcome, ActionExecutionResult::Succeeded(_)) {
            assert_eq!(
                completed.result.as_deref(),
                Some(b"{\"ok\":true}".as_slice())
            );
            (ActionStatus::Succeeded, ActionState::Succeeded)
        } else {
            assert!(completed.result.is_none());
            (ActionStatus::OutcomeUnknown, ActionState::OutcomeUnknown)
        };
        assert_eq!(completed.status, status);
        let finalized = std::fs::read(&journal_path).expect("terminal WAL");
        assert!(
            !finalized
                .windows(TEST_VALUE.len())
                .any(|bytes| bytes == TEST_VALUE.as_bytes())
        );
        assert_eq!(fixture.submit(fixture.catalog.principal.clone()), action);
        assert_eq!(
            std::fs::read(&journal_path).expect("no replay WAL"),
            finalized
        );
        assert!(
            fixture
                .worker
                .run_next_action(
                    &fixture.peer,
                    &fixture.created.session_id,
                    &fixture.created.fence,
                    SessionTime::new(3)
                )
                .expect("no queued replay")
                .is_none()
        );
        assert_eq!(fixture.provider.reads.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.driver.effects.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.driver.generic_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.driver.values.lock().expect("values").as_slice(),
            [TEST_VALUE]
        );
        let events = fixture
            .audit
            .as_ref()
            .expect("audit")
            .pending()
            .expect("pending audit");
        let injection = events
            .iter()
            .filter(|pending| pending.event().kind() == "credential.inject.intent")
            .collect::<Vec<_>>();
        assert_eq!(injection.len(), 1);
        for pending in &events {
            let payload = pending.event().payload();
            assert!(
                !payload
                    .windows(TEST_VALUE.len())
                    .any(|bytes| bytes == TEST_VALUE.as_bytes())
            );
            assert!(!String::from_utf8_lossy(payload).contains("credential-ref"));
        }
        let tenant = fixture.catalog.tenant.clone();
        let limits = fixture.worker.config.action_journal.limits;
        drop(fixture.worker);
        let journal = Arc::new(FileActionJournal::open(&journal_path, limits).expect("reopen WAL"));
        let recovered = ActionLedger::recover(
            LedgerSession::new(
                tenant,
                fixture.created.session_id.clone(),
                fixture.created.fence.as_placement_fence(),
            ),
            journal,
        )
        .expect("recover");
        let snapshot = recovered
            .snapshot(fixture.created.fence.as_placement_fence(), &action)
            .expect("recovered action");
        assert_eq!(snapshot.state(), state);
        assert!(!snapshot.automatic_replay_allowed());
    }
}
