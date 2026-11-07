use super::*;
use browser_worker::ArtifactRetentionConfig;
use browserd_artifacts::{ArtifactKey, ArtifactReadLimits};
use browserd_session::SessionTime;
use browserd_worker::{ArtifactPublication, ArtifactStoreReceipt, WorkerClock, WorkerError};
use std::sync::atomic::{AtomicU64, Ordering};

const DAY: u64 = 86_400_000;
struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}
impl Clock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
fn open(
    root: &std::path::Path,
    runtime: &tokio::runtime::Runtime,
    clock: &Arc<Clock>,
) -> ProductionArtifactStore {
    let mut limits = config(root);
    limits.max_worker_bytes = 4;
    ProductionArtifactStore::open_with_retention(
        limits,
        runtime.handle().clone(),
        None,
        ArtifactRetentionConfig {
            orphan_grace: Duration::from_millis(100),
            cleaned_retry: Duration::from_millis(DAY),
            compact_at_bytes: 1,
        },
        clock.clone(),
    )
    .expect("retention store")
}
fn publication(
    request: &ArtifactStoreRequest,
    receipt: &ArtifactStoreReceipt,
    now: u64,
) -> ArtifactPublication {
    ArtifactPublication::new(
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
        Some("file.bin".into()),
        now,
        now + 100,
    )
    .expect("publication")
}
fn exists(root: &std::path::Path, key: &ArtifactKey) -> bool {
    root.join("objects")
        .join(key.tenant_id().to_string())
        .join(key.session_id().to_string())
        .join(key.artifact_id().to_string())
        .join("data")
        .exists()
}
fn settle(store: &ProductionArtifactStore) {
    for _ in 0..8 {
        let _ = store.maintain(64);
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn new_capacity(store: &ProductionArtifactStore) -> bool {
    store
        .store(&request(SessionId::new(), b"new!", true))
        .is_ok()
}

#[test]
fn live_and_retained_readers_pin_full_object_quota_until_actual_fd_close() {
    for retained in [false, true] {
        let root = private_root();
        let runtime = runtime();
        let clock = Arc::new(Clock(AtomicU64::new(1_000)));
        let store = open(root.path(), &runtime, &clock);
        let request = request(SessionId::new(), b"old!", true);
        let receipt = store.store(&request).expect("bytes");
        let p = publication(&request, &receipt, 1_000);
        store.publish_artifact(&p).expect("publish");
        let mut reader = if retained {
            store
                .open_retained_artifact(&p, ArtifactReadLimits::new(1).expect("limits"), 1_000)
                .expect("reader")
        } else {
            store
                .open_read(
                    &ArtifactReadRequest::new(
                        p.key().clone(),
                        p.original_fence().clone(),
                        p.metadata().clone(),
                        p.object_generation(),
                        1,
                    )
                    .expect("read request"),
                )
                .expect("live reader")
        };
        assert_eq!(reader.next_chunk().expect("first"), Some(b"o".to_vec()));
        clock.set(1_101);
        settle(&store);
        assert!(exists(root.path(), p.key()), "open FD must prevent unlink");
        assert!(
            !new_capacity(&store),
            "entire old object remains charged, not just 1-byte chunk"
        );
        drop(reader);
        settle(&store);
        assert!(!exists(root.path(), p.key()));
        assert!(new_capacity(&store));
    }
}

#[test]
fn abandoned_completion_deadline_survives_restart_without_publication_or_reset() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("orphan bytes");
    drop(store);
    clock.set(1_050);
    let store = open(root.path(), &runtime, &clock);
    settle(&store);
    assert!(exists(root.path(), receipt.key()));
    assert!(
        store
            .get_retained_artifact(receipt.key(), 1_050)
            .expect("hidden")
            .is_none()
    );
    drop(store);
    clock.set(1_101);
    let store = open(root.path(), &runtime, &clock);
    settle(&store);
    assert!(!exists(root.path(), receipt.key()));
    assert!(new_capacity(&store));
}

#[test]
fn active_writer_never_becomes_orphan_until_finish_then_has_its_own_deadline() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let source = request(SessionId::new(), b"", true);
    let request = GeneratedArtifactRequest::new(
        source.key().clone(),
        source.fence().clone(),
        "application/pdf",
        "capture",
        4,
    )
    .expect("request");
    let mut sink = store.begin_generated(&request).expect("writer");
    runtime.block_on(sink.write_chunk(b"old")).expect("chunk");
    clock.set(10_000);
    settle(&store);
    assert!(!new_capacity(&store));
    let receipt = runtime
        .block_on(sink.finish())
        .expect("active writer survives sweep");
    drop(sink);
    settle(&store);
    assert!(exists(root.path(), receipt.key()));
    clock.set(10_101);
    settle(&store);
    assert!(!exists(root.path(), receipt.key()));
    assert!(new_capacity(&store));
}

#[test]
fn renamed_uncompacted_delete_recovery_removes_bytes_before_quota_release() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, 1_000);
    store.publish_artifact(&p).expect("publish");
    store.withdraw_artifact(&p).expect("durable intent");
    let object = root
        .path()
        .join("objects")
        .join(p.key().tenant_id().to_string())
        .join(p.key().session_id().to_string())
        .join(p.key().artifact_id().to_string());
    let marker = root
        .path()
        .join(".deleted")
        .join(p.key().tenant_id().to_string())
        .join(p.key().session_id().to_string())
        .join(p.key().artifact_id().to_string())
        .join(hex::encode(p.object_generation().as_bytes()));
    std::fs::rename(&object, &marker).expect("simulate persisted delete rename before compaction");
    assert!(marker.join("data").exists());
    drop(store);
    let store = open(root.path(), &runtime, &clock);
    assert!(
        !marker.join("data").exists(),
        "positive marker alone must not release quota while payload remains"
    );
    assert!(new_capacity(&store));
    assert!(
        store
            .get_retained_artifact(p.key(), 1_001)
            .expect("withdrawn")
            .is_none()
    );
}

#[test]
fn cleanup_failure_and_expired_deadline_preserve_bytes_and_charge() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("bytes");
    clock.set(1_101);
    assert!(
        store
            .maintain_with_deadline(64, std::time::Instant::now())
            .is_err()
    );
    assert!(exists(root.path(), receipt.key()));
    assert!(!new_capacity(&store));
    let marker = root
        .path()
        .join(".deleted")
        .join(receipt.key().tenant_id().to_string())
        .join(receipt.key().session_id().to_string())
        .join(receipt.key().artifact_id().to_string());
    let lock = std::fs::File::open(marker).expect("key lock");
    lock.lock().expect("stall delete");
    assert!(
        store
            .maintain_with_deadline(64, std::time::Instant::now() + Duration::from_millis(30))
            .is_err()
    );
    assert!(exists(root.path(), receipt.key()));
    assert!(!new_capacity(&store));
    drop(lock);
    // Unlink can become visible before the owned deletion has synced its quota
    // release. Observe one successful admission, not a fixed-duration sleep or
    // a successful probe followed by another allocation of the same capacity.
    let next = super::request(SessionId::new(), b"new!", true);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let maintenance = store.maintain_with_deadline(64, deadline);
        match store.store(&next) {
            Ok(next_receipt) => {
                assert_eq!(next_receipt.key(), next.key());
                assert!(!exists(root.path(), receipt.key()));
                break;
            }
            Err(DependencyError::Rejected | DependencyError::Unavailable)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(2));
            }
            result => {
                assert!(
                    result.is_ok(),
                    "exact deletion did not settle into available capacity: {result:?}; maintenance: {maintenance:?}"
                );
                break;
            }
        }
    }
}

#[test]
fn finite_retirement_reuses_capacity_and_bounds_journals_without_old_publication_replay() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let mut first = None;
    let tenant = TenantId::new();
    for cycle in 0..8u64 {
        let now = 1_000 + cycle * (DAY + 1_000);
        clock.set(now);
        let request = request_for(tenant.clone(), SessionId::new(), b"old!", true);
        let receipt = store.store(&request).expect("capacity reused");
        let p = publication(&request, &receipt, now);
        store.publish_artifact(&p).expect("publish");
        if first.is_none() {
            first = Some(p.clone());
        }
        clock.set(now + 101);
        settle(&store);
        loop {
            let pending = store
                .pending_notifications(None, 32, 8)
                .expect("committed cleanup metadata");
            if pending.commits.is_empty() {
                break;
            }
            for commit in pending.commits {
                store
                    .acknowledge_notifications(&commit.ack())
                    .expect("durable notification copy ACK before GC");
            }
        }
        clock.set(now + 101 + DAY);
        settle(&store);
        assert!(
            store
                .list_retained_artifacts(
                    p.key().tenant_id(),
                    p.key().session_id(),
                    None,
                    101,
                    now + 101 + DAY
                )
                .expect("retired empty")
                .is_empty()
        );
        assert!(store.publish_artifact(&p).is_err());
        assert!(
            std::fs::metadata(root.path().join("quota.journal"))
                .expect("quota journal")
                .len()
                < 1024
        );
        assert!(
            std::fs::metadata(root.path().join("publications.journal"))
                .expect("publication journal")
                .len()
                < 2048 // One permanent source/ACK checkpoint remains after payload metadata GC.
        );
        assert!(
            std::fs::metadata(root.path().join("retention.journal"))
                .expect("retention journal")
                .len()
                < 1024
        );
        assert_eq!(
            std::fs::read_dir(root.path().join(".deleted"))
                .expect("retired markers")
                .count(),
            0,
            "retirement must reclaim marker namespaces"
        );
    }
    drop(store);
    let store = open(root.path(), &runtime, &clock);
    assert!(store.publish_artifact(&first.expect("first")).is_err());
    assert!(new_capacity(&store));
}

#[test]
fn bounded_page_advances_past_pinned_candidate_and_namespace_is_preserved() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let mut limits = config(root.path());
    limits.max_worker_bytes = 8;
    let store = ProductionArtifactStore::open_with_retention(
        limits,
        runtime.handle().clone(),
        None,
        ArtifactRetentionConfig {
            orphan_grace: Duration::from_millis(100),
            ..Default::default()
        },
        clock.clone(),
    )
    .expect("store");
    let a = request(SessionId::new(), b"aaa", true);
    let ar = store.store(&a).expect("a");
    let p = publication(&a, &ar, 1_000);
    store.publish_artifact(&p).expect("publish a");
    let reader = store
        .open_retained_artifact(&p, ArtifactReadLimits::new(1).expect("limit"), 1_000)
        .expect("pin a");
    let b = request(SessionId::new(), b"bbb", true);
    let br = store.store(&b).expect("b");
    clock.set(1_101);
    for _ in 0..5 {
        let report = store.maintain(1).expect("bounded pass");
        assert!(report.scanned <= 1);
    }
    assert!(exists(root.path(), ar.key()));
    assert!(!exists(root.path(), br.key()));
    drop(reader);
}

#[test]
fn quota_tampering_is_not_repaired_by_compaction() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    store.store(&request).expect("bytes");
    let path = root.path().join("quota.journal");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("quota")
        .write_all(b"{}\n")
        .expect("tamper");
    let damaged = std::fs::read(&path).expect("damaged");
    assert!(store.maintain(1).is_err());
    assert_eq!(std::fs::read(path).expect("unchanged"), damaged);
    assert!(exists(root.path(), request.key()));
}

#[test]
fn interrupted_private_compaction_temp_is_discarded_only_after_valid_canonical_replay() {
    use std::os::unix::fs::OpenOptionsExt;
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("bytes");
    drop(store);
    for name in ["quota.tmp", "publications.tmp", "retention.tmp"] {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join(name))
            .expect("interrupted temp")
            .write_all(b"partial")
            .expect("partial snapshot");
    }
    let store = open(root.path(), &runtime, &clock);
    assert!(exists(root.path(), receipt.key()));
    for name in ["quota.tmp", "publications.tmp", "retention.tmp"] {
        assert!(!root.path().join(name).exists());
    }
    clock.set(1_101);
    settle(&store);
    assert!(new_capacity(&store));
}

#[test]
fn uncertain_orphan_record_commit_retains_bytes_and_charge_until_restart_reconciliation() {
    use std::os::unix::fs::OpenOptionsExt;
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    // An occupied replacement name simulates a failed/uncertain snapshot transaction.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.path().join("retention.tmp"))
        .expect("failed transaction temp");
    let request = request(SessionId::new(), b"old!", true);
    assert!(store.store(&request).is_err());
    assert!(exists(root.path(), request.key()));
    assert!(!new_capacity(&store));
    assert!(store.maintain(1).is_err());
    drop(store);
    let store = open(root.path(), &runtime, &clock);
    assert!(
        store
            .get_retained_artifact(request.key(), 1_000)
            .expect("not published")
            .is_none()
    );
    assert!(!new_capacity(&store));
    clock.set(1_101);
    settle(&store);
    assert!(!exists(root.path(), request.key()));
    assert!(new_capacity(&store));
}

#[test]
fn legacy_completed_bytes_receive_one_durable_first_seen_and_remain_unpublished() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    store.store(&request).expect("legacy bytes");
    drop(store);
    std::fs::remove_file(root.path().join("retention.journal"))
        .expect("simulate pre-retention schema");
    clock.set(5_000);
    let store = open(root.path(), &runtime, &clock);
    assert!(
        store
            .get_retained_artifact(request.key(), 5_000)
            .expect("hidden")
            .is_none()
    );
    drop(store);
    clock.set(5_050);
    let store = open(root.path(), &runtime, &clock);
    settle(&store);
    assert!(exists(root.path(), request.key()));
    drop(store);
    clock.set(5_101);
    let store = open(root.path(), &runtime, &clock);
    settle(&store);
    assert!(!exists(root.path(), request.key()));
    assert!(new_capacity(&store));
}

#[test]
fn publication_authority_uncertainty_blocks_orphan_deletion() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("bytes");
    let path = root.path().join("publications.journal");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("registry")
        .write_all(b"uncertain append\n")
        .expect("simulate uncertain authority");
    let original_quota = std::fs::read(root.path().join("quota.journal")).expect("quota");
    clock.set(1_101);
    assert!(store.maintain(64).is_err());
    assert!(exists(root.path(), receipt.key()));
    assert_eq!(
        std::fs::read(root.path().join("quota.journal")).expect("quota retained"),
        original_quota
    );
    assert!(!new_capacity(&store));
}

#[test]
fn old_withdraw_after_retirement_and_reuse_cannot_resurrect_or_poison_metadata() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("bytes");
    let old = publication(&request, &receipt, 1_000);
    store.publish_artifact(&old).expect("publish");
    clock.set(1_101);
    settle(&store);
    clock.set(1_101 + DAY);
    settle(&store);
    drop(store);
    let store = open(root.path(), &runtime, &clock);
    for replacement in [false, true] {
        let new = replacement.then(|| store.store(&request).expect("exact key reusable"));
        let registry = std::fs::read(root.path().join("publications.journal")).expect("registry");
        let retention = std::fs::read(root.path().join("retention.journal")).expect("retention");
        for _ in 0..4 {
            assert!(store.withdraw_artifact(&old).is_err());
            assert!(store.publish_artifact(&old).is_err());
        }
        assert_eq!(
            std::fs::read(root.path().join("publications.journal")).expect("unchanged"),
            registry
        );
        assert_eq!(
            std::fs::read(root.path().join("retention.journal")).expect("unchanged"),
            retention
        );
        if let Some(receipt) = new {
            assert_ne!(receipt.object_generation(), old.object_generation());
            let current = publication(&request, &receipt, 1_101 + DAY);
            store
                .publish_artifact(&current)
                .expect("old replay did not poison new generation");
        }
    }
}

#[test]
fn deferred_retirement_rejects_same_key_replacement_before_charge_or_write() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let receipt = store.store(&request).expect("bytes");
    clock.set(1_101);
    settle(&store);
    let marker = root
        .path()
        .join(".deleted")
        .join(receipt.key().tenant_id().to_string())
        .join(receipt.key().session_id().to_string())
        .join(receipt.key().artifact_id().to_string())
        .join(hex::encode(receipt.object_generation().as_bytes()));
    let unexpected = marker.join("unexpected");
    std::fs::write(&unexpected, b"stop prune").expect("fixture obstruction");
    clock.set(1_101 + DAY);
    let report = store.maintain(64).expect("deferred cleanup");
    assert_eq!(report.deferred, 1);
    let quota = std::fs::read(root.path().join("quota.journal")).expect("quota");
    assert!(store.store(&request).is_err());
    assert_eq!(
        std::fs::read(root.path().join("quota.journal")).expect("unchanged"),
        quota
    );
    assert!(!exists(root.path(), receipt.key()));
    std::fs::remove_file(unexpected).expect("remove only fixture obstruction");
    settle(&store);
    store
        .store(&request)
        .expect("replacement after durable retirement");
}

#[test]
fn timed_out_begin_keeps_operation_pin_then_periodic_maintenance_cleans_unobserved_writer() {
    let root = private_root();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let mut limits = config(root.path());
    limits.max_operations = 1;
    // The explicit blocking-pool gate induces timeout deterministically. Give
    // subsequent healthy fsync transactions the ordinary test I/O budget.
    limits.operation_timeout = Duration::from_secs(1);
    let store = ProductionArtifactStore::open_with_retention(
        limits,
        runtime.handle().clone(),
        None,
        ArtifactRetentionConfig::default(),
        clock,
    )
    .expect("store");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = runtime.spawn_blocking(move || {
        started_tx.send(()).expect("started");
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("release");
    });
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking queue held");
    let first = request(SessionId::new(), b"old!", true);
    assert!(matches!(
        store.store(&first),
        Err(DependencyError::OutcomeUncertain)
    ));
    assert!(
        store
            .store(&request(SessionId::new(), b"next", true))
            .is_err(),
        "unfinished begin retains max_operations even though caller timed out"
    );
    release_tx.send(()).expect("release blocking worker");
    runtime.block_on(blocker).expect("blocker complete");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let _ = store.maintain(1);
        let quota = std::fs::read_to_string(root.path().join("quota.journal")).expect("quota");
        if quota.contains("release") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "periodic cleanup must reconcile unobserved begin"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        std::fs::read_dir(root.path().join(".multipart"))
            .expect("stages")
            .count(),
        0
    );
    store
        .store(&request(SessionId::new(), b"next", true))
        .expect("operation capacity recovered");
}

#[test]
fn restart_completes_exact_new_generation_delete_and_retires_superseded_marker() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1_000)));
    let store = open(root.path(), &runtime, &clock);
    let request = request(SessionId::new(), b"old!", true);
    let first = store.store(&request).expect("first generation");
    store.discard(&first).expect("delete first");
    let second = store.store(&request).expect("replacement generation");
    let p = publication(&request, &second, 1_000);
    store.publish_artifact(&p).expect("publish replacement");
    store
        .withdraw_artifact(&p)
        .expect("durable replacement cleanup intent");
    drop(store);
    let key_directory = root
        .path()
        .join(".deleted")
        .join(p.key().tenant_id().to_string())
        .join(p.key().session_id().to_string())
        .join(p.key().artifact_id().to_string());
    let first_marker = key_directory.join(hex::encode(first.object_generation().as_bytes()));
    let second_marker = key_directory.join(hex::encode(second.object_generation().as_bytes()));
    let object = root
        .path()
        .join("objects")
        .join(p.key().tenant_id().to_string())
        .join(p.key().session_id().to_string())
        .join(p.key().artifact_id().to_string());
    assert!(first_marker.join("receipt").exists());
    std::fs::rename(object, &second_marker).expect("crash after replacement delete rename");
    let store = open(root.path(), &runtime, &clock);
    assert!(!second_marker.join("data").exists());
    assert!(
        !first_marker.exists(),
        "superseded positive receipt must be reconciled"
    );
    assert!(new_capacity(&store));
}
