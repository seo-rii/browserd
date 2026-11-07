use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browser_worker::{
    ArtifactQuarantineConfig, ArtifactRetentionConfig, ArtifactScanResult, ArtifactScanner,
    ArtifactStoreConfig, ProductionArtifactStore,
};
use browserd_artifacts::{ArtifactContentSource, ArtifactKey, ArtifactObjectGeneration};
use browserd_core::{
    ArtifactId, NotificationArtifactState, NotificationCommit, SessionId, TenantId, WorkerId,
    WorkerNotificationEvent,
};
use browserd_session::{OwnershipFence, SessionTime};
use browserd_worker::{
    ArtifactScanVerdict, ArtifactScannerObservation, ArtifactStoreRequest, DependencyError,
    WorkerClock, WorkerError,
};
use sha2::{Digest, Sha256};

pub const START: u64 = 1_000;
pub const DAY: u64 = 86_400_000;

pub struct Clock(AtomicU64);
impl Clock {
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
    pub fn millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.millis()))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Scan {
    Rejected,
    Quarantined,
    MissingObservation,
    WrongSize,
    WrongChecksum,
    WrongUid,
    Stale,
    Future,
    Failed,
}
struct Scanner {
    mode: Scan,
    clock: Arc<Clock>,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl ArtifactScanner for Scanner {
    async fn scan(&self, _: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        if matches!(self.mode, Scan::Failed) {
            return Err(DependencyError::Unavailable);
        }
        Ok(if matches!(self.mode, Scan::Quarantined) {
            ArtifactScanVerdict::Quarantined
        } else {
            ArtifactScanVerdict::Rejected
        })
    }
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let verdict = self.scan(bytes).await?;
        let now = self.clock.millis();
        let mut observation = ArtifactScannerObservation {
            schema_version: 1,
            program_version: "authenticated-quarantine-fixture".to_owned(),
            database_version: 1,
            database_built_at_unix_millis: now,
            observed_before_unix_millis: now,
            observed_after_unix_millis: now,
            expected_peer_uid: 1000,
            peer_uid: 1000,
            version_metadata_sha256: [7; 32],
            scanned_size_bytes: bytes.len() as u64,
            scanned_checksum_sha256: Sha256::digest(bytes).into(),
            max_database_age_millis: 500,
            max_future_skew_millis: 0,
        };
        match self.mode {
            Scan::WrongSize => observation.scanned_size_bytes += 1,
            Scan::WrongChecksum => observation.scanned_checksum_sha256 = [99; 32],
            Scan::WrongUid => observation.peer_uid += 1,
            Scan::Stale => observation.database_built_at_unix_millis = 1,
            Scan::Future => observation.observed_after_unix_millis = now + 1,
            _ => {}
        }
        Ok(ArtifactScanResult {
            verdict,
            observation: (!matches!(self.mode, Scan::MissingObservation)).then_some(observation),
        })
    }
}

pub struct Harness {
    pub root: tempfile::TempDir,
    pub runtime: tokio::runtime::Runtime,
    pub clock: Arc<Clock>,
    pub scanner_calls: Arc<AtomicUsize>,
}
impl Harness {
    pub fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().expect("private test root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        Self {
            root,
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("test runtime"),
            clock: Arc::new(Clock(AtomicU64::new(START))),
            scanner_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    pub fn config(&self) -> ArtifactStoreConfig {
        ArtifactStoreConfig {
            root: self.root.path().to_owned(),
            max_file_bytes: 8,
            max_worker_bytes: 16,
            max_worker_in_flight_bytes: 8,
            max_session_bytes: 12,
            max_session_in_flight_bytes: 8,
            max_retained_artifacts: 8,
            max_operations: 2,
            chunk_bytes: 3,
            operation_timeout: Duration::from_secs(2),
        }
    }
    pub fn open(
        &self,
        config: ArtifactStoreConfig,
        scanner: Option<Scan>,
        policy: Option<ArtifactQuarantineConfig>,
    ) -> Result<ProductionArtifactStore, DependencyError> {
        ProductionArtifactStore::open_with_quarantine(
            config,
            self.runtime.handle().clone(),
            scanner.map(|mode| {
                Arc::new(Scanner {
                    mode,
                    clock: Arc::clone(&self.clock),
                    calls: Arc::clone(&self.scanner_calls),
                }) as Arc<dyn ArtifactScanner>
            }),
            ArtifactRetentionConfig {
                orphan_grace: Duration::from_millis(100),
                cleaned_retry: Duration::from_millis(DAY),
                compact_at_bytes: 1,
            },
            self.clock.clone(),
            policy,
        )
    }
    pub fn payloads(&self, key: &ArtifactKey) -> Vec<PathBuf> {
        let directory = quarantine_key(self.root.path(), key);
        if !directory.exists() {
            return vec![];
        }
        let mut paths = std::fs::read_dir(directory)
            .expect("private artifact directory")
            .map(|entry| entry.expect("generation entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                    && path.join("data").exists()
            })
            .map(|path| path.join("data"))
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }
    pub fn all_payloads(&self) -> Vec<PathBuf> {
        fn visit(directory: &Path, payloads: &mut Vec<PathBuf>) {
            if !directory.exists() {
                return;
            }
            for entry in std::fs::read_dir(directory).expect("private tree") {
                let path = entry.expect("private entry").path();
                let metadata = std::fs::symlink_metadata(&path).expect("private metadata");
                if metadata.is_dir() {
                    visit(&path, payloads);
                } else if path.file_name().is_some_and(|name| name == "data") {
                    payloads.push(path);
                }
            }
        }
        let mut paths = vec![];
        visit(&self.root.path().join(".quarantine"), &mut paths);
        paths.sort();
        paths
    }
}

pub fn policy(file: u64, worker: u64, session: u64, count: usize) -> ArtifactQuarantineConfig {
    ArtifactQuarantineConfig::new(Duration::from_millis(100), file, worker, session, count)
        .expect("bounded opt-in policy")
}
pub fn request(
    tenant: TenantId,
    session: SessionId,
    bytes: &[u8],
    source: ArtifactContentSource,
) -> ArtifactStoreRequest {
    let fence = OwnershipFence::new(WorkerId::new("quarantine-test").expect("worker"), 7, 9, 11);
    match source {
        ArtifactContentSource::ClientUpload => ArtifactStoreRequest::new(
            tenant,
            session,
            ArtifactId::new(),
            fence,
            bytes.to_vec(),
            "text/plain",
            8,
        ),
        ArtifactContentSource::BrowserDownload => ArtifactStoreRequest::new_browser_download(
            tenant,
            session,
            ArtifactId::new(),
            fence,
            bytes.to_vec(),
            "text/plain",
            8,
        ),
        ArtifactContentSource::Generated => ArtifactStoreRequest::new_generated(
            tenant,
            session,
            ArtifactId::new(),
            fence,
            bytes.to_vec(),
            "text/plain",
            8,
            "quarantine-capacity-probe",
        ),
    }
    .expect("bounded attributed bytes")
}
pub fn quarantine_key(root: &Path, key: &ArtifactKey) -> PathBuf {
    root.join(".quarantine")
        .join(key.tenant_id().to_string())
        .join(key.session_id().to_string())
        .join(key.artifact_id().to_string())
}
pub fn generation(payload: &Path) -> ArtifactObjectGeneration {
    let name = payload
        .parent()
        .expect("generation directory")
        .file_name()
        .expect("generation")
        .to_str()
        .expect("canonical generation");
    let bytes: [u8; 32] = hex::decode(name)
        .expect("hex generation")
        .try_into()
        .expect("32-byte generation");
    assert_eq!(name, hex::encode(bytes), "canonical lowercase generation");
    assert_ne!(bytes, [0; 32]);
    ArtifactObjectGeneration::new(bytes)
}
pub fn commits(store: &ProductionArtifactStore) -> Vec<NotificationCommit> {
    let mut cursor = None;
    let mut commits = vec![];
    loop {
        let page = store
            .pending_notifications(cursor.as_deref(), 32, 8)
            .expect("bounded page");
        commits.extend(page.commits);
        if page.is_complete {
            return commits;
        }
        cursor = page.cursor;
    }
}
pub fn acknowledge_all(store: &ProductionArtifactStore) {
    loop {
        let pending = commits(store);
        if pending.is_empty() {
            return;
        }
        for commit in pending {
            store
                .acknowledge_notifications(&commit.ack())
                .expect("exact source head ACK");
        }
    }
}
pub fn assert_state(
    commit: &NotificationCommit,
    request: &ArtifactStoreRequest,
    state: NotificationArtifactState,
) {
    commit.validate().expect("valid atomic notification");
    assert_eq!(commit.descriptors().len(), 1);
    assert_eq!(
        commit.descriptors()[0].event(),
        &WorkerNotificationEvent::ArtifactStateChanged {
            artifact_id: request.key().artifact_id().clone(),
            state,
        }
    );
    assert_eq!(commit.scope().tenant_id(), request.key().tenant_id());
    assert_eq!(
        commit.scope().original_worker_id(),
        request.fence().worker_id()
    );
    assert_eq!(
        commit.descriptors()[0].session_scope().session_id(),
        request.key().session_id()
    );
    assert_eq!(
        commit.descriptors()[0].session_scope().fence(),
        browserd_core::PlacementFence::new(7, 9, 11)
    );
    assert!(
        !serde_json::to_string(commit)
            .expect("finite metadata")
            .contains("unsafe")
    );
}
pub fn no_public_success(store: &ProductionArtifactStore) {
    for commit in commits(store) {
        for descriptor in commit.descriptors() {
            assert!(!matches!(
                descriptor.event(),
                WorkerNotificationEvent::DownloadCompleted { .. }
                    | WorkerNotificationEvent::ArtifactStateChanged {
                        state: NotificationArtifactState::Available,
                        ..
                    }
            ));
        }
    }
}
pub fn settle(store: &ProductionArtifactStore, limit: usize) {
    for _ in 0..16 {
        let report = store.maintain(limit).expect("bounded maintenance");
        assert!(report.scanned <= limit);
    }
}
