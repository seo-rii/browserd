#![allow(clippy::expect_used)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use async_trait::async_trait;
use browser_worker::ArtifactScanResult;
use browser_worker::{
    ArtifactScanner, ArtifactStoreConfig, ProductionArtifactStore, RoutedArtifactStore,
};
use browserd_artifacts::{
    ArtifactContentMetadata, ArtifactContentSource, ArtifactMultipartStore,
    ArtifactObjectGeneration, FilesystemArtifactStore,
};
use browserd_core::{ArtifactId, SessionId, TenantId, WorkerId};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ArtifactReadRequest, ArtifactScanVerdict, ArtifactStoreRequest, DependencyError,
    GeneratedArtifactRequest,
};
use browserd_worker::{ArtifactScannerObservation, SystemWorkerClock, WorkerClock};
use sha2::{Digest, Sha256};

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private artifact root");
    root
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn config(root: &std::path::Path) -> ArtifactStoreConfig {
    ArtifactStoreConfig {
        root: root.to_owned(),
        max_file_bytes: 8,
        max_worker_bytes: 16,
        max_worker_in_flight_bytes: 8,
        max_session_bytes: 12,
        max_session_in_flight_bytes: 8,
        max_retained_artifacts: 4,
        max_operations: 2,
        chunk_bytes: 3,
        operation_timeout: Duration::from_secs(2),
    }
}

fn request(session: SessionId, bytes: &[u8], generated: bool) -> ArtifactStoreRequest {
    let tenant = TenantId::new();
    request_for(tenant, session, bytes, generated)
}

fn request_for(
    tenant: TenantId,
    session: SessionId,
    bytes: &[u8],
    generated: bool,
) -> ArtifactStoreRequest {
    let fence = OwnershipFence::new(WorkerId::new("artifact-test").expect("worker"), 1, 1, 1);
    if generated {
        ArtifactStoreRequest::new_generated(
            tenant,
            session,
            ArtifactId::new(),
            fence,
            bytes.to_vec(),
            "application/octet-stream",
            8,
            "browserd-test-capture",
        )
        .expect("generated request")
    } else {
        ArtifactStoreRequest::new(
            tenant,
            session,
            ArtifactId::new(),
            fence,
            bytes.to_vec(),
            "application/octet-stream",
            8,
        )
        .expect("upload request")
    }
}

#[test]
fn generated_artifact_round_trips_verified_bounded_chunks_without_scan_verdict() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    let request = request(SessionId::new(), b"example", true);
    let receipt = store.store(&request).expect("store generated");
    assert_eq!(receipt.source(), ArtifactContentSource::Generated);
    assert_eq!(receipt.scan_verdict(), None);
    let metadata = ArtifactContentMetadata::new(
        receipt.size_bytes(),
        *receipt.checksum(),
        receipt.detected_content_type(),
        receipt.source(),
        request.origin(),
    )
    .expect("metadata");
    let read = ArtifactReadRequest::new(
        request.key().clone(),
        request.fence().clone(),
        metadata,
        receipt.object_generation(),
        2,
    )
    .expect("read request");
    let mut reader = store.open_read(&read).expect("verified read");
    let mut bytes = Vec::new();
    while let Some(chunk) = reader.next_chunk().expect("read chunk") {
        assert!(chunk.len() <= 2);
        bytes.extend(chunk);
    }
    assert_eq!(bytes, b"example");
}

#[test]
fn upload_without_scanner_or_with_nonclean_result_never_publishes() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    assert!(
        store
            .store(&request(SessionId::new(), b"unsafe", false))
            .is_err()
    );
    assert!(
        store
            .store(&request(SessionId::new(), b"safe", true))
            .is_ok()
    );
    drop(store);
    let store = ProductionArtifactStore::open(
        config(root.path()),
        runtime.handle().clone(),
        Some(Arc::new(VerdictScanner(ArtifactScanVerdict::Quarantined))),
    )
    .expect("store");
    assert!(
        store
            .store(&request(SessionId::new(), b"unsafe", false))
            .is_err()
    );
    assert!(
        store
            .store(&request(SessionId::new(), b"safe", true))
            .is_ok()
    );
}

fn observation(bytes: &[u8], now: u64) -> ArtifactScannerObservation {
    ArtifactScannerObservation {
        schema_version: 1,
        program_version: "fixture-1".into(),
        database_version: 1,
        database_built_at_unix_millis: now,
        observed_before_unix_millis: now,
        observed_after_unix_millis: now,
        expected_peer_uid: 1000,
        peer_uid: 1000,
        version_metadata_sha256: [7; 32],
        scanned_size_bytes: bytes.len() as u64,
        scanned_checksum_sha256: Sha256::digest(bytes).into(),
        max_database_age_millis: 86_400_000,
        max_future_skew_millis: 0,
    }
}
fn observed_result(
    verdict: ArtifactScanVerdict,
    bytes: &[u8],
    fixed_now: Option<u64>,
) -> ArtifactScanResult {
    ArtifactScanResult {
        verdict,
        observation: (verdict == ArtifactScanVerdict::Clean).then(|| {
            observation(
                bytes,
                fixed_now.unwrap_or_else(|| SystemWorkerClock.now().expect("clock").get()),
            )
        }),
    }
}
struct VerdictScanner(ArtifactScanVerdict);

#[async_trait]
impl ArtifactScanner for VerdictScanner {
    async fn scan(&self, _bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        Ok(self.0)
    }
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        Ok(observed_result(self.scan(bytes).await?, bytes, None))
    }
}

#[test]
fn clean_scanner_is_required_for_available_client_upload_receipt() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(
        config(root.path()),
        runtime.handle().clone(),
        Some(Arc::new(VerdictScanner(ArtifactScanVerdict::Clean))),
    )
    .expect("store");
    let receipt = store
        .store(&request(SessionId::new(), b"safe", false))
        .expect("scanned upload");
    assert_eq!(receipt.source(), ArtifactContentSource::ClientUpload);
    assert_eq!(receipt.scan_verdict(), Some(ArtifactScanVerdict::Clean));
}

mod browser_download_storage {
    use super::*;
    use std::sync::Mutex;

    fn download(tenant: TenantId, session: SessionId, bytes: &[u8]) -> ArtifactStoreRequest {
        ArtifactStoreRequest::new_browser_download(
            tenant,
            session,
            ArtifactId::new(),
            OwnershipFence::new(WorkerId::new("download-owner").expect("worker"), 1, 1, 1),
            bytes.to_vec(),
            "text/html",
            8,
        )
        .expect("attributed browser download")
    }

    struct RecordingScanner {
        bytes: Arc<Mutex<Vec<Vec<u8>>>>,
        verdict: Result<ArtifactScanVerdict, DependencyError>,
        observed_clock: Option<Arc<dyn WorkerClock>>,
    }

    #[async_trait]
    impl ArtifactScanner for RecordingScanner {
        async fn scan(&self, bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
            self.bytes
                .lock()
                .expect("scan observations")
                .push(bytes.to_vec());
            self.verdict
        }
        async fn scan_with_observation(
            &self,
            bytes: &[u8],
        ) -> Result<ArtifactScanResult, DependencyError> {
            Ok(observed_result(
                self.scan(bytes).await?,
                bytes,
                self.observed_clock
                    .as_ref()
                    .map(|clock| clock.now().expect("clock").get()),
            ))
        }
    }

    #[test]
    fn browser_download_round_trips_scanned_bytes_with_exact_source_and_safe_content_type() {
        let root = private_root();
        let runtime = runtime();
        let scanned = Arc::new(Mutex::new(Vec::new()));
        let store = ProductionArtifactStore::open(
            config(root.path()),
            runtime.handle().clone(),
            Some(Arc::new(RecordingScanner {
                bytes: scanned.clone(),
                verdict: Ok(ArtifactScanVerdict::Clean),
                observed_clock: None,
            })),
        )
        .expect("store");
        let request = download(TenantId::new(), SessionId::new(), b"browser");
        assert_eq!(request.origin(), "browserd-worker-download");
        let receipt = store.store(&request).expect("scanned browser download");
        assert_eq!(receipt.key(), request.key());
        assert_eq!(receipt.source(), ArtifactContentSource::BrowserDownload);
        assert_eq!(receipt.scan_verdict(), Some(ArtifactScanVerdict::Clean));
        assert_eq!(receipt.size_bytes(), request.expected_size_bytes());
        assert_eq!(receipt.checksum(), request.expected_checksum());
        assert_eq!(receipt.detected_content_type(), "application/octet-stream");
        assert_eq!(
            *scanned.lock().expect("observations"),
            vec![b"browser".to_vec()]
        );
        let metadata = ArtifactContentMetadata::new(
            receipt.size_bytes(),
            *receipt.checksum(),
            receipt.detected_content_type(),
            receipt.source(),
            request.origin(),
        )
        .expect("download metadata");
        let read = ArtifactReadRequest::new(
            request.key().clone(),
            request.fence().clone(),
            metadata.clone(),
            receipt.object_generation(),
            2,
        )
        .expect("read request");
        let mut reader = store.open_read(&read).expect("verified download");
        let mut bytes = Vec::new();
        while let Some(chunk) = reader.next_chunk().expect("bounded read") {
            assert!(chunk.len() <= 2);
            bytes.extend(chunk);
        }
        assert_eq!(bytes, request.bytes());
        drop(reader);
        let wrong = ArtifactReadRequest::new(
            request.key().clone(),
            request.fence().clone(),
            metadata,
            ArtifactObjectGeneration::new([0; 32]),
            2,
        )
        .expect("wrong generation request");
        assert!(store.open_read(&wrong).is_err());
    }

    #[test]
    fn empty_browser_download_is_scanned_readable_and_consumes_one_retained_slot() {
        let root = private_root();
        let runtime = runtime();
        struct DownloadClock(std::sync::atomic::AtomicU64);
        impl browserd_worker::WorkerClock for DownloadClock {
            fn now(&self) -> Result<browserd_session::SessionTime, browserd_worker::WorkerError> {
                Ok(browserd_session::SessionTime::new(
                    self.0.load(std::sync::atomic::Ordering::SeqCst),
                ))
            }
        }
        let clock = Arc::new(DownloadClock(std::sync::atomic::AtomicU64::new(1_000)));
        let scanned = Arc::new(Mutex::new(Vec::new()));
        let mut limits = config(root.path());
        limits.max_retained_artifacts = 1;
        let store = ProductionArtifactStore::open_with_retention(
            limits,
            runtime.handle().clone(),
            Some(Arc::new(RecordingScanner {
                bytes: scanned.clone(),
                verdict: Ok(ArtifactScanVerdict::Clean),
                observed_clock: Some(clock.clone()),
            })),
            browser_worker::ArtifactRetentionConfig::default(),
            clock.clone(),
        )
        .expect("store");
        let request = download(TenantId::new(), SessionId::new(), b"");
        let receipt = store.store(&request).expect("scanned empty download");
        assert_eq!(receipt.size_bytes(), 0);
        assert_eq!(receipt.checksum(), request.expected_checksum());
        assert_eq!(receipt.source(), ArtifactContentSource::BrowserDownload);
        assert_eq!(receipt.scan_verdict(), Some(ArtifactScanVerdict::Clean));
        assert_eq!(receipt.detected_content_type(), "application/octet-stream");
        assert_eq!(
            *scanned.lock().expect("observations"),
            vec![Vec::<u8>::new()]
        );
        let metadata = ArtifactContentMetadata::new(
            0,
            *receipt.checksum(),
            receipt.detected_content_type(),
            receipt.source(),
            request.origin(),
        )
        .expect("empty metadata");
        let read = ArtifactReadRequest::new(
            request.key().clone(),
            request.fence().clone(),
            metadata,
            receipt.object_generation(),
            2,
        )
        .expect("empty read request");
        let mut reader = store.open_read(&read).expect("verified empty download");
        assert_eq!(reader.next_chunk().expect("empty stream"), None);
        drop(reader);
        assert!(
            store
                .store(&download(TenantId::new(), SessionId::new(), b""))
                .is_err()
        );
        assert_eq!(scanned.lock().expect("observations").len(), 1);
        store.discard(&receipt).expect("delete empty download");
        assert!(
            std::fs::read_to_string(root.path().join("quota.journal"))
                .expect("quota journal")
                .contains("release")
        );
        assert!(
            store
                .store(&download(TenantId::new(), SessionId::new(), b""))
                .is_err(),
            "exact cleanup receipt occupies the bounded registry until retirement"
        );
        assert_eq!(scanned.lock().expect("observations").len(), 1);
        clock
            .0
            .store(1_001 + 86_400_000, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            store.maintain(1).expect("retire confirmed cleanup").retired,
            1
        );
        store
            .store(&download(TenantId::new(), SessionId::new(), b""))
            .expect("confirmed empty deletion and retirement release retained slot");
    }

    #[test]
    fn browser_download_without_scanner_does_not_create_or_charge_an_object() {
        let root = private_root();
        let runtime = runtime();
        let store =
            ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
                .expect("store");
        let before = std::fs::read(root.path().join("quota.journal")).expect("journal");
        assert!(
            store
                .store(&download(TenantId::new(), SessionId::new(), b"unsafe"))
                .is_err()
        );
        assert_eq!(
            std::fs::read(root.path().join("quota.journal")).expect("journal"),
            before
        );
        assert_eq!(
            std::fs::read_dir(root.path().join("objects"))
                .expect("objects")
                .count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(root.path().join(".multipart"))
                .expect("partials")
                .count(),
            0
        );
    }

    #[test]
    fn browser_download_nonclean_or_failed_scans_never_write_and_release_the_charge() {
        for verdict in [
            Ok(ArtifactScanVerdict::Rejected),
            Ok(ArtifactScanVerdict::Quarantined),
            Err(DependencyError::Unavailable),
        ] {
            let root = private_root();
            let runtime = runtime();
            let mut limits = config(root.path());
            limits.max_worker_bytes = 8;
            let scanned = Arc::new(Mutex::new(Vec::new()));
            let store = ProductionArtifactStore::open(
                limits,
                runtime.handle().clone(),
                Some(Arc::new(RecordingScanner {
                    bytes: scanned.clone(),
                    verdict,
                    observed_clock: None,
                })),
            )
            .expect("store");
            assert!(
                store
                    .store(&download(TenantId::new(), SessionId::new(), b"untrustd"))
                    .is_err()
            );
            assert_eq!(
                *scanned.lock().expect("observations"),
                vec![b"untrustd".to_vec()]
            );
            assert_eq!(
                std::fs::read_dir(root.path().join("objects"))
                    .expect("objects")
                    .count(),
                0
            );
            assert_eq!(
                std::fs::read_dir(root.path().join(".multipart"))
                    .expect("partials")
                    .count(),
                0
            );
            store
                .store(&request(SessionId::new(), b"12345678", true))
                .expect("non-clean download charge was released");
        }
    }

    #[test]
    fn browser_download_size_bound_is_enforced_before_scanning() {
        let root = private_root();
        let runtime = runtime();
        let scanned = Arc::new(Mutex::new(Vec::new()));
        let mut limits = config(root.path());
        limits.max_file_bytes = 2;
        let store = ProductionArtifactStore::open(
            limits,
            runtime.handle().clone(),
            Some(Arc::new(RecordingScanner {
                bytes: scanned.clone(),
                verdict: Ok(ArtifactScanVerdict::Clean),
                observed_clock: None,
            })),
        )
        .expect("store");
        assert!(
            store
                .store(&download(TenantId::new(), SessionId::new(), b"big"))
                .is_err()
        );
        assert!(scanned.lock().expect("observations").is_empty());
        store
            .store(&download(TenantId::new(), SessionId::new(), b"ok"))
            .expect("bounded browser download");
    }

    #[test]
    fn browser_download_retained_usage_survives_restart_and_duplicate_keys_are_rejected() {
        let root = private_root();
        let runtime = runtime();
        let tenant = TenantId::new();
        let session = SessionId::new();
        let scanner = Arc::new(VerdictScanner(ArtifactScanVerdict::Clean));
        let store = ProductionArtifactStore::open(
            config(root.path()),
            runtime.handle().clone(),
            Some(scanner.clone()),
        )
        .expect("store");
        let first = download(tenant.clone(), session.clone(), b"12345678");
        let committed = store.store(&first).expect("download committed");
        assert!(
            store.store(&first).is_err(),
            "one artifact key cannot replace the committed generation"
        );
        drop(store);
        let store = ProductionArtifactStore::open(
            config(root.path()),
            runtime.handle().clone(),
            Some(scanner),
        )
        .expect("reopened");
        assert!(
            store.store(&download(tenant, session, b"12345")).is_err(),
            "session charge survived restart"
        );
        store
            .store(&download(TenantId::new(), SessionId::new(), b"12345678"))
            .expect("remaining worker quota");
        assert!(
            store
                .store(&download(TenantId::new(), SessionId::new(), b"x"))
                .is_err()
        );
        assert_eq!(committed.source(), ArtifactContentSource::BrowserDownload);
    }
}

#[test]
fn retained_worker_and_session_usage_survive_restart_and_root_is_exclusive() {
    let root = private_root();
    let runtime = runtime();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    assert!(
        ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None).is_err()
    );
    store
        .store(&request_for(
            tenant.clone(),
            session.clone(),
            b"12345678",
            true,
        ))
        .expect("first write");
    drop(store);
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("reopened");
    assert!(
        store
            .store(&request_for(tenant, session, b"12345", true))
            .is_err()
    );
    store
        .store(&request(SessionId::new(), b"12345678", true))
        .expect("other session");
    assert!(store.store(&request(SessionId::new(), b"x", true)).is_err());
}

#[test]
fn unaccounted_existing_payload_and_torn_journal_fail_startup_closed() {
    let root = private_root();
    let runtime = runtime();
    std::fs::write(root.path().join("unaccounted"), b"retained payload").expect("fixture");
    assert!(
        ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None).is_err()
    );
    std::fs::remove_file(root.path().join("unaccounted")).expect("cleanup fixture");
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    drop(store);
    let mut journal = std::fs::OpenOptions::new()
        .append(true)
        .open(root.path().join("quota.journal"))
        .expect("journal");
    journal
        .write_all(b"{incomplete")
        .expect("simulate torn write");
    assert!(
        ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None).is_err()
    );
}

#[test]
fn restart_removes_exact_abandoned_partial_and_releases_unused_reservations() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    drop(store);
    let partial = request(SessionId::new(), b"12345678", true);
    let unused = request(SessionId::new(), b"12345678", true);
    seed_crash_charge(root.path(), &partial);
    seed_crash_charge(root.path(), &unused);
    let filesystem = FilesystemArtifactStore::open(root.path()).expect("filesystem");
    let upload = runtime
        .block_on(filesystem.begin(partial.key()))
        .expect("partial upload");
    runtime
        .block_on(filesystem.append(&upload, bytes::Bytes::from_static(b"partial")))
        .expect("partial payload");
    drop(filesystem);
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("restart recovers abandoned writes");
    assert!(
        !root
            .path()
            .join(".multipart")
            .join(upload.as_str())
            .exists()
    );
    store.store(&partial).expect("partial reservation released");
    store.store(&unused).expect("unused reservation released");
}

#[test]
fn restart_cleanup_failure_preserves_charge_until_exact_retry_succeeds() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    drop(store);
    let partial = request(SessionId::new(), b"12345678", true);
    seed_crash_charge(root.path(), &partial);
    let filesystem = FilesystemArtifactStore::open(root.path()).expect("filesystem");
    let upload = runtime
        .block_on(filesystem.begin(partial.key()))
        .expect("partial upload");
    runtime
        .block_on(filesystem.append(&upload, bytes::Bytes::from_static(b"partial")))
        .expect("partial payload");
    drop(filesystem);
    let before = std::fs::read(root.path().join("quota.journal")).expect("journal");
    let multipart = root.path().join(".multipart");
    std::fs::set_permissions(&multipart, std::fs::Permissions::from_mode(0o500))
        .expect("deny partial removal");
    let failed = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None);
    std::fs::set_permissions(&multipart, std::fs::Permissions::from_mode(0o700))
        .expect("restore cleanup permission");
    assert!(
        failed.is_err(),
        "unconfirmed cleanup cannot release its charge"
    );
    assert_eq!(
        std::fs::read(root.path().join("quota.journal")).expect("journal"),
        before
    );
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("exact cleanup retry");
    store
        .store(&partial)
        .expect("reservation released after cleanup");
}

fn seed_crash_charge(root: &std::path::Path, request: &ArtifactStoreRequest) {
    let key = request.key();
    let record = serde_json::json!({
        "op": "charge", "tenant": key.tenant_id(), "session": key.session_id(),
        "artifact": key.artifact_id(), "bytes": 8
    });
    let mut journal = std::fs::OpenOptions::new()
        .append(true)
        .open(root.join("quota.journal"))
        .expect("journal");
    writeln!(journal, "{record}").expect("crash reservation");
    journal.sync_all().expect("durable reservation");
}

#[test]
fn readback_rejects_wrong_generation_and_corrupted_object() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    let request = request(SessionId::new(), b"original", true);
    let receipt = store.store(&request).expect("write");
    let metadata = ArtifactContentMetadata::new(
        receipt.size_bytes(),
        *receipt.checksum(),
        receipt.detected_content_type(),
        receipt.source(),
        request.origin(),
    )
    .expect("metadata");
    let wrong = ArtifactReadRequest::new(
        request.key().clone(),
        request.fence().clone(),
        metadata.clone(),
        ArtifactObjectGeneration::new([0; 32]),
        3,
    )
    .expect("read");
    assert!(store.open_read(&wrong).is_err());
    let path = root
        .path()
        .join("objects")
        .join(request.key().tenant_id().to_string())
        .join(request.key().session_id().to_string())
        .join(request.key().artifact_id().to_string())
        .join("data");
    std::fs::write(path, b"modified").expect("corruption fixture");
    let read = ArtifactReadRequest::new(
        request.key().clone(),
        request.fence().clone(),
        metadata,
        receipt.object_generation(),
        3,
    )
    .expect("read");
    assert!(store.open_read(&read).is_err());
}

struct BlockingScanner {
    started: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[async_trait]
impl ArtifactScanner for BlockingScanner {
    async fn scan(&self, _bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        self.started.wait();
        self.release.wait();
        Ok(ArtifactScanVerdict::Clean)
    }
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        Ok(observed_result(self.scan(bytes).await?, bytes, None))
    }
}

#[test]
fn worker_in_flight_reservation_precedes_scan_and_blocks_another_session() {
    let root = private_root();
    let runtime = runtime();
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let scanner = Arc::new(BlockingScanner {
        started: started.clone(),
        release: release.clone(),
    });
    let store = Arc::new(
        ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), Some(scanner))
            .expect("store"),
    );
    let first_store = store.clone();
    let first =
        std::thread::spawn(move || first_store.store(&request(SessionId::new(), b"123456", false)));
    started.wait();
    assert!(
        store
            .store(&request(SessionId::new(), b"123", true))
            .is_err()
    );
    release.wait();
    first.join().expect("upload thread").expect("first store");
    assert!(
        store
            .store(&request(SessionId::new(), b"123", true))
            .is_ok()
    );
}

#[test]
fn empty_artifacts_still_consume_retained_object_capacity() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    for _ in 0..4 {
        store
            .store(&request(SessionId::new(), b"", true))
            .expect("empty object");
    }
    assert!(store.store(&request(SessionId::new(), b"", true)).is_err());
}

#[test]
fn generated_sink_streams_bounded_chunks_and_releases_unused_reservation() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 8;
    let store =
        ProductionArtifactStore::open(limits, runtime.handle().clone(), None).expect("store");
    let source = request(SessionId::new(), b"", true);
    let request = GeneratedArtifactRequest::new(
        source.key().clone(),
        source.fence().clone(),
        "application/pdf",
        "browserd-print",
        8,
    )
    .expect("stream request");
    let mut sink = store.begin_generated(&request).expect("reserved sink");
    assert_eq!(sink.max_chunk_bytes(), 3);
    runtime.block_on(async {
        sink.write_chunk(b"pdf").await.expect("bounded first chunk");
        sink.write_chunk(b"!").await.expect("bounded last chunk");
        let receipt = sink.finish().await.expect("finish");
        assert_eq!(receipt.size_bytes(), 4);
        assert_eq!(receipt.source(), ArtifactContentSource::Generated);
        assert_eq!(receipt.scan_verdict(), None);
        assert_eq!(sink.finish().await.expect("idempotent finish"), receipt);
        assert!(sink.write_chunk(b"x").await.is_err());
    });
    assert!(
        store
            .store(&request_for(
                TenantId::new(),
                SessionId::new(),
                b"rest",
                true
            ))
            .is_ok()
    );
}

#[test]
fn dropping_partial_sink_keeps_charge_until_exact_cleanup() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    let source = request(SessionId::new(), b"", true);
    let request = GeneratedArtifactRequest::new(
        source.key().clone(),
        source.fence().clone(),
        "application/pdf",
        "browserd-print",
        8,
    )
    .expect("stream request");
    let mut sink = store.begin_generated(&request).expect("sink");
    runtime.block_on(sink.write_chunk(b"pdf")).expect("chunk");
    drop(sink);
    assert_eq!(store.reconcile_pending().expect("owned cleanup"), 1);
    assert!(
        store
            .store(&request_for(
                TenantId::new(),
                SessionId::new(),
                b"12345678",
                true
            ))
            .is_ok()
    );
}

#[test]
fn cancelled_append_retains_root_ownership_until_detached_io_settles() {
    let root = private_root();
    let runtime = runtime();
    let store = ProductionArtifactStore::open(config(root.path()), runtime.handle().clone(), None)
        .expect("store");
    let source = request(SessionId::new(), b"", true);
    let generated = GeneratedArtifactRequest::new(
        source.key().clone(),
        source.fence().clone(),
        "application/pdf",
        "capture",
        8,
    )
    .expect("request");
    let mut sink = store.begin_generated(&generated).expect("sink");
    let stage = std::fs::read_dir(root.path().join(".multipart"))
        .expect("stages")
        .next()
        .expect("stage")
        .expect("entry")
        .path();
    let upload_lock = std::fs::File::open(stage).expect("upload directory");
    upload_lock.lock().expect("hold append before data effects");
    let cancelled = runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(50), sink.write_chunk(b"pdf")).await
    });
    assert!(cancelled.is_err());
    drop(sink);
    drop(store);
    let root_probe = std::fs::File::open(root.path()).expect("root probe");
    let owned = root_probe.try_lock().is_err();
    drop(upload_lock);
    assert!(
        owned,
        "detached filesystem effects must retain exclusive root ownership"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if root_probe.try_lock().is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached append must settle"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn abort_after_finish_removes_only_the_finished_generation_and_releases_charge() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 4;
    let store =
        ProductionArtifactStore::open(limits, runtime.handle().clone(), None).expect("store");
    let source = request(SessionId::new(), b"", true);
    let generated = GeneratedArtifactRequest::new(
        source.key().clone(),
        source.fence().clone(),
        "application/pdf",
        "capture",
        4,
    )
    .expect("request");
    let mut sink = store.begin_generated(&generated).expect("sink");
    runtime.block_on(async {
        sink.write_chunk(b"pdf").await.expect("chunk");
        sink.finish().await.expect("finished");
        sink.abort()
            .await
            .expect("cancel before control-plane publication");
        assert!(sink.finish().await.is_err());
    });
    assert!(
        store
            .store(&request(SessionId::new(), b"next", true))
            .is_ok()
    );
}

#[test]
fn discard_is_idempotent_and_releases_committed_quota_after_exact_deletion() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 4;
    let store =
        ProductionArtifactStore::open(limits, runtime.handle().clone(), None).expect("store");
    let original = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&original).expect("committed object");
    store.discard(&receipt).expect("exact discard");
    store.discard(&receipt).expect("idempotent discard");
    store
        .store(&request(SessionId::new(), b"new!", true))
        .expect("confirmed deletion released quota");
}

#[test]
fn timed_out_discard_finishes_later_and_exact_retry_survives_restart_without_releasing_replacement()
{
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 4;
    limits.operation_timeout = Duration::from_millis(300);
    let store = ProductionArtifactStore::open(limits.clone(), runtime.handle().clone(), None)
        .expect("store");
    let original = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&original).expect("committed object");
    let lock_directory = root
        .path()
        .join(".deleted")
        .join(original.key().tenant_id().to_string())
        .join(original.key().session_id().to_string())
        .join(original.key().artifact_id().to_string());
    let held_lock = std::fs::File::open(&lock_directory).expect("artifact lock directory");
    held_lock.lock().expect("hold exact deletion lock");
    let journal_path = root.path().join("quota.journal");
    let before = std::fs::read(&journal_path).expect("journal");
    assert_eq!(
        store.discard(&receipt),
        Err(DependencyError::OutcomeUncertain)
    );
    assert_eq!(std::fs::read(&journal_path).expect("journal"), before);
    assert_eq!(store.discard(&receipt), Err(DependencyError::Rejected));
    assert!(
        store.store(&original).is_err(),
        "replacement remains excluded while deletion owns the key"
    );
    drop(held_lock);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let journal = std::fs::read_to_string(&journal_path).expect("journal");
        if journal.lines().skip(1).any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .is_ok_and(|entry| entry["op"] == "release")
        }) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached deletion and durable release must settle"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    loop {
        match store.discard(&receipt) {
            Ok(()) => break,
            // Release bytes become visible before fsync returns and before the
            // background owner drops its ledger/key guard. The nonblocking
            // admission path reports that mutex contention as Unavailable.
            Err(DependencyError::Rejected | DependencyError::Unavailable) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "completed discard ownership must settle"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            other => {
                assert!(
                    other.is_ok(),
                    "exact tombstone retry should succeed: {other:?}"
                );
                break;
            }
        }
    }
    let released = std::fs::read(&journal_path).expect("released journal");
    let release_count = std::str::from_utf8(&released)
        .expect("journal text")
        .lines()
        .skip(1)
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .is_ok_and(|entry| entry["op"] == "release")
        })
        .count();
    assert_eq!(
        release_count, 1,
        "late completion and exact retries release quota once"
    );
    drop(store);
    let store = ProductionArtifactStore::open(limits, runtime.handle().clone(), None)
        .expect("reopen after late deletion");
    store
        .discard(&receipt)
        .expect("durable exact tombstone retry");
    assert_eq!(std::fs::read(&journal_path).expect("journal"), released);
    let replacement = ArtifactStoreRequest::new_generated(
        original.key().tenant_id().clone(),
        original.key().session_id().clone(),
        original.key().artifact_id().clone(),
        original.fence().clone(),
        b"new!".to_vec(),
        "application/octet-stream",
        8,
        "browserd-test-capture",
    )
    .expect("replacement request");
    let new = store.store(&replacement).expect("replacement generation");
    assert_ne!(new.object_generation(), receipt.object_generation());
    let charged = std::fs::read(&journal_path).expect("replacement journal");
    assert!(
        store.discard(&receipt).is_err(),
        "late retry cannot delete a newer generation"
    );
    assert_eq!(std::fs::read(&journal_path).expect("journal"), charged);
    assert!(
        store.store(&request(SessionId::new(), b"x", true)).is_err(),
        "new generation charge remains"
    );
    store
        .discard(&new)
        .expect("new generation owns its own deletion");
}

#[test]
fn stale_discard_never_deletes_a_replacement_or_releases_its_charge() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 4;
    let store =
        ProductionArtifactStore::open(limits, runtime.handle().clone(), None).expect("store");
    let original = request(SessionId::new(), b"old!", true);
    let old = store.store(&original).expect("old generation");
    store.discard(&old).expect("delete old generation");
    let replacement = ArtifactStoreRequest::new_generated(
        original.key().tenant_id().clone(),
        original.key().session_id().clone(),
        original.key().artifact_id().clone(),
        original.fence().clone(),
        b"new!".to_vec(),
        "application/octet-stream",
        8,
        "browserd-test-capture",
    )
    .expect("replacement request");
    let new = store.store(&replacement).expect("replacement generation");
    assert_ne!(old.object_generation(), new.object_generation());
    assert!(
        store.discard(&old).is_err(),
        "stale receipt cannot delete replacement"
    );
    assert!(
        store.store(&request(SessionId::new(), b"x", true)).is_err(),
        "replacement charge remains"
    );
    let metadata = ArtifactContentMetadata::new(
        new.size_bytes(),
        *new.checksum(),
        new.detected_content_type(),
        new.source(),
        replacement.origin(),
    )
    .expect("replacement metadata");
    let read = ArtifactReadRequest::new(
        replacement.key().clone(),
        replacement.fence().clone(),
        metadata,
        new.object_generation(),
        3,
    )
    .expect("replacement read");
    let mut reader = store.open_read(&read).expect("replacement preserved");
    let mut bytes = Vec::new();
    while let Some(chunk) = reader.next_chunk().expect("replacement chunk") {
        bytes.extend(chunk);
    }
    assert_eq!(bytes, b"new!");
}

#[test]
fn failed_discard_retains_durable_charge_until_exact_retry() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 4;
    let store =
        ProductionArtifactStore::open(limits, runtime.handle().clone(), None).expect("store");
    let original = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&original).expect("committed object");
    let parent = root
        .path()
        .join("objects")
        .join(original.key().tenant_id().to_string())
        .join(original.key().session_id().to_string());
    let before = std::fs::read(root.path().join("quota.journal")).expect("journal");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).expect("deny rename");
    let failed = store.discard(&receipt);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("restore rename");
    assert!(
        failed.is_err(),
        "unconfirmed deletion cannot release charge"
    );
    assert_eq!(
        std::fs::read(root.path().join("quota.journal")).expect("journal"),
        before
    );
    assert!(store.store(&request(SessionId::new(), b"x", true)).is_err());
    store.discard(&receipt).expect("exact retry");
    store
        .store(&request(SessionId::new(), b"new!", true))
        .expect("quota released after retry");
}

#[test]
fn cleanup_failure_remains_charged_until_owned_retry_succeeds() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_worker_bytes = 8;
    let store =
        ProductionArtifactStore::open(limits, runtime.handle().clone(), None).expect("store");
    let source = request(SessionId::new(), b"", true);
    let generated = GeneratedArtifactRequest::new(
        source.key().clone(),
        source.fence().clone(),
        "application/pdf",
        "capture",
        8,
    )
    .expect("request");
    let mut sink = store.begin_generated(&generated).expect("sink");
    runtime.block_on(sink.write_chunk(b"pdf")).expect("chunk");
    let multipart = root.path().join(".multipart");
    std::fs::set_permissions(&multipart, std::fs::Permissions::from_mode(0o500))
        .expect("deny cleanup fixture");
    let cleanup = runtime.block_on(sink.abort());
    drop(sink);
    let rejected = store
        .store(&request(SessionId::new(), b"12345678", true))
        .is_err();
    std::fs::set_permissions(&multipart, std::fs::Permissions::from_mode(0o700))
        .expect("restore fixture");
    assert!(cleanup.is_err());
    assert!(rejected);
    assert_eq!(store.reconcile_pending().expect("retry exact cleanup"), 1);
    assert!(
        store
            .store(&request(SessionId::new(), b"12345678", true))
            .is_ok()
    );
}

#[path = "support/artifact_publications.rs"]
mod artifact_publications;

#[path = "support/artifact_retention.rs"]
mod artifact_retention;

#[path = "support/artifact_scan_evidence.rs"]
mod artifact_scan_evidence;

#[path = "support/artifact_notifications.rs"]
mod artifact_notifications;
