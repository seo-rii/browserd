use super::*;
use browserd_worker::{ArtifactPublication, ArtifactStoreReceipt};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct Clock {
    now: AtomicU64,
    calls: AtomicUsize,
    age_after: AtomicUsize,
}
impl Clock {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(1_000),
            calls: AtomicUsize::new(0),
            age_after: AtomicUsize::new(usize::MAX),
        }
    }
    fn age_after_next_read(&self) {
        self.calls.store(0, Ordering::SeqCst);
        self.age_after.store(1, Ordering::SeqCst);
    }
}
impl WorkerClock for Clock {
    fn now(&self) -> Result<browserd_session::SessionTime, browserd_worker::WorkerError> {
        let value =
            if self.calls.fetch_add(1, Ordering::SeqCst) >= self.age_after.load(Ordering::SeqCst) {
                2_000
            } else {
                self.now.load(Ordering::SeqCst)
            };
        Ok(browserd_session::SessionTime::new(value))
    }
}
struct Scanner {
    result: ArtifactScanResult,
    calls: Arc<AtomicUsize>,
    age_during_finish: Option<Arc<Clock>>,
}
#[async_trait]
impl ArtifactScanner for Scanner {
    async fn scan(&self, _: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        Ok(self.result.verdict)
    }
    async fn scan_with_observation(&self, _: &[u8]) -> Result<ArtifactScanResult, DependencyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(clock) = &self.age_during_finish {
            clock.age_after_next_read();
        }
        Ok(self.result.clone())
    }
}
struct LegacyScanner;
#[async_trait]
impl ArtifactScanner for LegacyScanner {
    async fn scan(&self, _: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        Ok(ArtifactScanVerdict::Clean)
    }
}
fn open(
    root: &std::path::Path,
    runtime: &tokio::runtime::Runtime,
    clock: Arc<Clock>,
    scanner: Arc<dyn ArtifactScanner>,
) -> ProductionArtifactStore {
    ProductionArtifactStore::open_with_retention(
        config(root),
        runtime.handle().clone(),
        Some(scanner),
        browser_worker::ArtifactRetentionConfig::default(),
        clock,
    )
    .expect("store")
}
fn publication(
    request: &ArtifactStoreRequest,
    receipt: &ArtifactStoreReceipt,
) -> ArtifactPublication {
    ArtifactPublication::new_with_scan_attestation(
        receipt.key().clone(),
        request.fence().clone(),
        ArtifactContentMetadata::new(
            receipt.size_bytes(),
            *receipt.checksum(),
            receipt.detected_content_type(),
            receipt.source(),
            request.origin(),
        )
        .expect("metadata"),
        receipt.object_generation(),
        receipt.scan_verdict(),
        Some("safe.txt".into()),
        1_000,
        10_000,
        receipt.scan_attestation().cloned(),
    )
    .expect("attested publication")
}
fn result(bytes: &[u8]) -> ArtifactScanResult {
    let mut observation = observation(bytes, 1_000);
    observation.max_database_age_millis = 500;
    ArtifactScanResult {
        verdict: ArtifactScanVerdict::Clean,
        observation: Some(observation),
    }
}

#[test]
fn legacy_clean_verdict_does_not_allocate_or_publish_without_evidence() {
    let root = private_root();
    let runtime = runtime();
    let store = open(
        root.path(),
        &runtime,
        Arc::new(Clock::new()),
        Arc::new(LegacyScanner),
    );
    let request = request(SessionId::new(), b"scan", false);
    assert_eq!(store.store(&request), Err(DependencyError::Rejected));
    assert!(
        store
            .get_retained_artifact(request.key(), 1_000)
            .expect("hidden")
            .is_none()
    );
    assert_eq!(
        std::fs::read_dir(root.path().join(".multipart"))
            .expect("stages")
            .count(),
        0
    );
    assert!(
        std::fs::read_to_string(root.path().join("quota.journal"))
            .expect("quota")
            .contains("release")
    );
}

#[test]
fn scanner_observation_wrong_bytes_uid_future_or_staleness_denies_before_write() {
    for mode in 0..5 {
        let root = private_root();
        let runtime = runtime();
        let mut observed = result(b"scan");
        let evidence = observed.observation.as_mut().expect("observation");
        match mode {
            0 => evidence.scanned_size_bytes += 1,
            1 => evidence.scanned_checksum_sha256 = [99; 32],
            2 => evidence.peer_uid += 1,
            3 => evidence.observed_after_unix_millis = 1_001,
            _ => evidence.database_built_at_unix_millis = 1,
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let store = open(
            root.path(),
            &runtime,
            Arc::new(Clock::new()),
            Arc::new(Scanner {
                result: observed,
                calls: calls.clone(),
                age_during_finish: None,
            }),
        );
        assert!(
            store
                .store(&request(SessionId::new(), b"scan", false))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read_dir(root.path().join(".multipart"))
                .expect("stages")
                .count(),
            0
        );
    }
}

#[test]
fn evidence_aging_after_scan_before_finish_is_not_returned_and_cleanup_keeps_exact_accounting() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let store = open(
        root.path(),
        &runtime,
        clock.clone(),
        Arc::new(Scanner {
            result: result(b"scan"),
            calls: calls.clone(),
            age_during_finish: Some(clock),
        }),
    );
    let request = request(SessionId::new(), b"scan", false);
    assert!(store.store(&request).is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "never automatically rescan"
    );
    assert!(
        store
            .get_retained_artifact(request.key(), 2_000)
            .expect("no publication")
            .is_none()
    );
    store.reconcile_pending().expect("exact rollback");
    assert!(
        std::fs::read_to_string(root.path().join("quota.journal"))
            .expect("quota")
            .contains("release")
    );
}

#[test]
fn fresh_finish_is_rechecked_at_durable_publish_and_existing_evidence_survives_age_and_restart() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let store = open(
        root.path(),
        &runtime,
        clock.clone(),
        Arc::new(Scanner {
            result: result(b"scan"),
            calls: calls.clone(),
            age_during_finish: None,
        }),
    );
    let request = request(SessionId::new(), b"scan", false);
    let receipt = store.store(&request).expect("fresh bytes");
    let p = publication(&request, &receipt);
    let before = std::fs::read(root.path().join("publications.journal")).expect("journal");
    clock.age_after_next_read();
    assert!(
        store.publish_artifact(&p).is_err(),
        "freshness must be sampled inside durable publication"
    );
    assert_eq!(
        std::fs::read(root.path().join("publications.journal")).expect("unchanged"),
        before
    );
    clock.age_after.store(usize::MAX, Ordering::SeqCst);
    store
        .publish_artifact(&p)
        .expect("publish with still valid evidence");
    clock.now.store(2_000, Ordering::SeqCst);
    store
        .publish_artifact(&p)
        .expect("canonical published retry uses original admission");
    drop(store);
    let store = ProductionArtifactStore::open_with_retention(
        config(root.path()),
        runtime.handle().clone(),
        None,
        browser_worker::ArtifactRetentionConfig::default(),
        clock,
    )
    .expect("restart without rescan");
    assert_eq!(
        store
            .get_retained_artifact(p.key(), 2_000)
            .expect("retained"),
        Some(p)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn staged_provenance_rejects_a_different_valid_attestation_for_same_bytes() {
    let root = private_root();
    let runtime = runtime();
    let store = open(
        root.path(),
        &runtime,
        Arc::new(Clock::new()),
        Arc::new(Scanner {
            result: result(b"scan"),
            calls: Arc::new(AtomicUsize::new(0)),
            age_during_finish: None,
        }),
    );
    let request = request(SessionId::new(), b"scan", false);
    let receipt = store.store(&request).expect("bytes");
    let correct = publication(&request, &receipt);
    let mut changed = correct
        .scan_attestation()
        .expect("attestation")
        .observation()
        .clone();
    changed.database_version += 1;
    let evidence = browserd_worker::ArtifactScanAttestation::new(
        correct.key(),
        correct.original_fence(),
        correct.metadata().source(),
        correct.object_generation(),
        correct.metadata().size_bytes(),
        *correct.metadata().checksum(),
        changed,
    )
    .expect("structurally valid alternate evidence");
    let altered = ArtifactPublication::new_with_scan_attestation(
        correct.key().clone(),
        correct.original_fence().clone(),
        correct.metadata().clone(),
        correct.object_generation(),
        correct.scan_verdict(),
        Some("safe.txt".into()),
        1_000,
        10_000,
        Some(evidence),
    )
    .expect("valid public shape");
    assert!(store.publish_artifact(&altered).is_err());
    store
        .publish_artifact(&correct)
        .expect("actual scanner evidence accepted");
}
