use super::*;
use browserd_artifacts::ArtifactReadLimits;
use browserd_worker::{ArtifactPublication, ArtifactStoreReceipt};
use std::fs::OpenOptions;

struct PublicationClock;
impl browserd_worker::WorkerClock for PublicationClock {
    fn now(&self) -> Result<browserd_session::SessionTime, browserd_worker::WorkerError> {
        Ok(browserd_session::SessionTime::new(1001))
    }
}
fn open_store(
    config: ArtifactStoreConfig,
    runtime: tokio::runtime::Handle,
    scanner: Option<Arc<dyn ArtifactScanner>>,
) -> Result<ProductionArtifactStore, DependencyError> {
    ProductionArtifactStore::open_with_retention(
        config,
        runtime,
        scanner,
        browser_worker::ArtifactRetentionConfig::default(),
        Arc::new(PublicationClock),
    )
}

struct FixedScanner;
#[async_trait]
impl ArtifactScanner for FixedScanner {
    async fn scan(&self, _bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        Ok(ArtifactScanVerdict::Clean)
    }
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        Ok(observed_result(
            ArtifactScanVerdict::Clean,
            bytes,
            Some(1_000),
        ))
    }
}
fn publication(
    request: &ArtifactStoreRequest,
    receipt: &ArtifactStoreReceipt,
    name: Option<&str>,
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
        name.map(str::to_owned),
        1_000,
        100_000,
        receipt.scan_attestation().cloned(),
    )
    .expect("publication")
}
fn read_all(store: &ProductionArtifactStore, publication: &ArtifactPublication) -> Vec<u8> {
    let mut reader = store
        .open_retained_artifact(
            publication,
            ArtifactReadLimits::new(2).expect("limits"),
            1_001,
        )
        .expect("retained read");
    let mut bytes = Vec::new();
    while let Some(chunk) = reader.next_chunk().expect("chunk") {
        assert!(chunk.len() <= 2);
        bytes.extend(chunk);
    }
    bytes
}
fn rebind(
    p: &ArtifactPublication,
    fence: OwnershipFence,
    metadata: ArtifactContentMetadata,
    generation: ArtifactObjectGeneration,
    name: Option<String>,
    expires: u64,
) -> ArtifactPublication {
    ArtifactPublication::new(
        p.key().clone(),
        fence,
        metadata,
        generation,
        p.scan_verdict(),
        name,
        p.published_at_unix_millis(),
        expires,
    )
    .expect("changed publication")
}

#[test]
fn durable_publication_reopens_all_sources_and_preserves_exact_names_without_adopting_orphans() {
    let root = private_root();
    let runtime = runtime();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let store = open_store(
        config(root.path()),
        runtime.handle().clone(),
        Some(Arc::new(FixedScanner)),
    )
    .expect("store");
    let requests = [
        request_for(tenant.clone(), session.clone(), b"gen", true),
        request_for(tenant.clone(), session.clone(), b"upl", false),
        ArtifactStoreRequest::new_browser_download(
            tenant.clone(),
            session.clone(),
            ArtifactId::new(),
            OwnershipFence::new(WorkerId::new("artifact-test").expect("worker"), 1, 1, 1),
            b"get".to_vec(),
            "text/plain",
            8,
        )
        .expect("download"),
    ];
    let mut published = Vec::new();
    for (request, name) in requests
        .iter()
        .zip([None, Some("문서.csv"), Some("download.txt")])
    {
        let receipt = store.store(request).expect("bytes");
        let p = publication(request, &receipt, name);
        assert!(
            store
                .get_retained_artifact(p.key(), 1_001)
                .expect("unpublished")
                .is_none()
        );
        store.publish_artifact(&p).expect("publish");
        store.publish_artifact(&p).expect("exact idempotency");
        published.push(p);
    }
    let orphan_request = request_for(tenant.clone(), session.clone(), b"old", true);
    let orphan_receipt = store.store(&orphan_request).expect("unpublished bytes");
    let orphan = publication(&orphan_request, &orphan_receipt, None);
    drop(store);
    let store = open_store(config(root.path()), runtime.handle().clone(), None)
        .expect("reopened without scanner or browser sessions");
    for (p, expected) in published.iter().zip([b"gen", b"upl", b"get"]) {
        assert_eq!(
            store.get_retained_artifact(p.key(), 1_001).expect("get"),
            Some(p.clone())
        );
        assert_eq!(read_all(&store, p), expected);
        store.publish_artifact(p).expect("durable exact replay");
    }
    assert_eq!(
        store
            .list_retained_artifacts(&tenant, &session, None, 101, 1_001)
            .expect("list")
            .len(),
        3
    );
    assert!(
        store
            .get_retained_artifact(orphan.key(), 1_001)
            .expect("orphan hidden")
            .is_none()
    );
    assert!(
        store.publish_artifact(&orphan).is_err(),
        "restart must not invent source provenance for byte-only receipts"
    );
    assert!(
        store
            .store(&request_for(tenant, session, b"x", true))
            .is_err(),
        "all four original objects remain charged"
    );
}

#[test]
fn publication_rejects_changed_origin_generation_fence_name_and_expiry() {
    let root = private_root();
    let runtime = runtime();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, Some("safe.txt"));
    let changed_fence = OwnershipFence::new(p.original_fence().worker_id().clone(), 2, 1, 1);
    let changed_origin = ArtifactContentMetadata::new(
        3,
        *p.metadata().checksum(),
        p.metadata().content_type(),
        p.metadata().source(),
        "untrusted-origin",
    )
    .expect("metadata");
    for changed in [
        rebind(
            &p,
            changed_fence,
            p.metadata().clone(),
            p.object_generation(),
            Some("safe.txt".into()),
            100_000,
        ),
        rebind(
            &p,
            p.original_fence().clone(),
            changed_origin,
            p.object_generation(),
            Some("safe.txt".into()),
            100_000,
        ),
        rebind(
            &p,
            p.original_fence().clone(),
            p.metadata().clone(),
            ArtifactObjectGeneration::new([7; 32]),
            Some("safe.txt".into()),
            100_000,
        ),
    ] {
        assert!(store.publish_artifact(&changed).is_err());
    }
    store.publish_artifact(&p).expect("exact publish");
    for changed in [
        rebind(
            &p,
            p.original_fence().clone(),
            p.metadata().clone(),
            p.object_generation(),
            Some("renamed.txt".into()),
            100_000,
        ),
        rebind(
            &p,
            p.original_fence().clone(),
            p.metadata().clone(),
            p.object_generation(),
            Some("safe.txt".into()),
            100_001,
        ),
    ] {
        assert!(store.publish_artifact(&changed).is_err());
        assert!(store.withdraw_artifact(&changed).is_err());
        assert!(
            store
                .open_retained_artifact(
                    &changed,
                    ArtifactReadLimits::new(2).expect("limits"),
                    1_001
                )
                .is_err()
        );
    }
    assert_eq!(read_all(&store, &p), b"abc");
}

#[test]
fn publication_requires_exact_withdrawal_before_delete_and_cannot_resurrect_after_restart() {
    let root = private_root();
    let runtime = runtime();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, None);
    store.publish_artifact(&p).expect("publish");
    assert!(store.discard(&receipt).is_err());
    store.withdraw_artifact(&p).expect("withdraw");
    store.withdraw_artifact(&p).expect("idempotent withdrawal");
    assert!(
        store
            .get_retained_artifact(p.key(), 1_001)
            .expect("withdrawn")
            .is_none()
    );
    assert!(store.publish_artifact(&p).is_err());
    store.discard(&receipt).expect("exact authorized deletion");
    drop(store);
    let store =
        open_store(config(root.path()), runtime.handle().clone(), None).expect("reopen withdrawal");
    store
        .withdraw_artifact(&p)
        .expect("withdrawal retry after restart");
    store.discard(&receipt).expect("exact tombstone retry");
    assert!(store.publish_artifact(&p).is_err());
    assert!(
        store
            .list_retained_artifacts(p.key().tenant_id(), p.key().session_id(), None, 1, 1_001)
            .expect("empty")
            .is_empty()
    );
}

#[test]
fn withdrawal_before_first_publication_seals_full_identity() {
    let root = private_root();
    let runtime = runtime();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, None);
    store
        .withdraw_artifact(&p)
        .expect("never published rollback");
    assert!(store.publish_artifact(&p).is_err());
    store.discard(&receipt).expect("rollback deletion");
    let changed = rebind(
        &p,
        p.original_fence().clone(),
        p.metadata().clone(),
        p.object_generation(),
        Some("changed".into()),
        100_000,
    );
    assert!(store.withdraw_artifact(&changed).is_err());
}

#[test]
fn generated_sink_abort_preserves_published_object_until_durable_withdrawal() {
    let root = private_root();
    let runtime = runtime();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let generated = GeneratedArtifactRequest::new(
        request.key().clone(),
        request.fence().clone(),
        "application/octet-stream",
        request.origin(),
        8,
    )
    .expect("generated");
    let mut sink = store.begin_generated(&generated).expect("sink");
    runtime.block_on(sink.write_chunk(b"abc")).expect("write");
    let receipt = runtime.block_on(sink.finish()).expect("finish");
    let p = publication(&request, &receipt, None);
    store.publish_artifact(&p).expect("publish");
    assert!(runtime.block_on(sink.abort()).is_err());
    assert_eq!(read_all(&store, &p), b"abc");
    store.withdraw_artifact(&p).expect("withdraw");
    runtime
        .block_on(sink.abort())
        .expect("exact post-finish abort");
    drop(sink);
    drop(store);
    open_store(config(root.path()), runtime.handle().clone(), None)
        .expect("withdrawal and quota replay");
}

#[test]
fn retained_enumeration_is_scoped_bounded_ordered_and_expiry_checked() {
    let root = private_root();
    let runtime = runtime();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    for _ in 0..3 {
        let request = request_for(tenant.clone(), session.clone(), b"a", true);
        let receipt = store.store(&request).expect("bytes");
        store
            .publish_artifact(&publication(&request, &receipt, None))
            .expect("publish");
    }
    let first = store
        .list_retained_artifacts(&tenant, &session, None, 2, 1_001)
        .expect("first");
    assert_eq!(first.len(), 2);
    let second = store
        .list_retained_artifacts(
            &tenant,
            &session,
            Some(first[1].key().artifact_id()),
            2,
            1_001,
        )
        .expect("second");
    assert_eq!(second.len(), 1);
    assert!(first[1].key().artifact_id() < second[0].key().artifact_id());
    for now in [999, 100_000] {
        assert!(
            store
                .get_retained_artifact(first[0].key(), now)
                .expect("time hidden")
                .is_none()
        );
        assert!(
            store
                .list_retained_artifacts(&tenant, &session, None, 101, now)
                .expect("expired")
                .is_empty()
        );
        assert!(
            store
                .open_retained_artifact(&first[0], ArtifactReadLimits::new(1).expect("limit"), now)
                .is_err()
        );
    }
    for limit in [0, 102] {
        assert!(
            store
                .list_retained_artifacts(&tenant, &session, None, limit, 1_001)
                .is_err()
        );
    }
    assert!(
        store
            .list_retained_artifacts(&TenantId::new(), &session, None, 101, 1_001)
            .expect("other tenant")
            .is_empty()
    );
    assert!(
        store
            .list_retained_artifacts(&tenant, &SessionId::new(), None, 101, 1_001)
            .expect("other session")
            .is_empty()
    );
}

#[test]
fn retained_metadata_and_open_share_global_operation_cap() {
    let root = private_root();
    let runtime = runtime();
    let mut limits = config(root.path());
    limits.max_operations = 1;
    let store = open_store(limits, runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, None);
    store.publish_artifact(&p).expect("publish");
    let reader = store
        .open_retained_artifact(&p, ArtifactReadLimits::new(1).expect("limit"), 1_001)
        .expect("held read");
    assert!(store.get_retained_artifact(p.key(), 1_001).is_err());
    assert!(
        store
            .list_retained_artifacts(p.key().tenant_id(), p.key().session_id(), None, 1, 1_001)
            .is_err()
    );
    assert!(store.publish_artifact(&p).is_err());
    assert!(store.withdraw_artifact(&p).is_err());
    drop(reader);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match store.get_retained_artifact(p.key(), 1_001) {
            Ok(value) => {
                assert_eq!(value, Some(p));
                break;
            }
            Err(DependencyError::Rejected | DependencyError::Unavailable)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            result => {
                assert!(
                    result.is_ok(),
                    "reader FD cleanup did not release capacity: {result:?}"
                );
                break;
            }
        }
    }
}

#[test]
fn retained_reader_stops_after_withdrawal() {
    let root = private_root();
    let runtime = runtime();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, None);
    store.publish_artifact(&p).expect("publish");
    let mut reader = store
        .open_retained_artifact(&p, ArtifactReadLimits::new(1).expect("limit"), 1_001)
        .expect("reader");
    assert_eq!(reader.next_chunk().expect("first"), Some(b"a".to_vec()));
    store.withdraw_artifact(&p).expect("withdraw");
    assert!(reader.next_chunk().is_err());
}

#[test]
fn journal_corruption_is_fail_closed_on_reopen_and_blocks_runtime_deletion() {
    for damage in ["torn", "digest", "unknown"] {
        let root = private_root();
        let runtime = runtime();
        let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
        let request = request(SessionId::new(), b"abc", true);
        let receipt = store.store(&request).expect("bytes");
        let p = publication(&request, &receipt, None);
        store.publish_artifact(&p).expect("publish");
        let path = root.path().join("publications.journal");
        let mut bytes = std::fs::read(&path).expect("journal");
        match damage {
            "torn" => {
                bytes.pop();
            }
            "digest" => {
                let text = String::from_utf8(bytes).expect("json");
                bytes = text
                    .replace("\"published_at\":1000", "\"published_at\":1001")
                    .into_bytes();
            }
            _ => bytes.extend_from_slice(b"{}\n"),
        }
        std::fs::write(&path, bytes).expect("damage");
        assert!(store.discard(&receipt).is_err());
        drop(store);
        assert!(
            open_store(config(root.path()), runtime.handle().clone(), None).is_err(),
            "{damage}"
        );
    }
}

#[test]
fn publication_journal_rejects_unsafe_mode_symlink_hardlink_and_fifo() {
    for kind in ["mode", "symlink", "hardlink", "fifo"] {
        let root = private_root();
        let runtime = runtime();
        let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
        drop(store);
        let path = root.path().join("publications.journal");
        match kind {
            "mode" => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .expect("mode"),
            "hardlink" => std::fs::hard_link(&path, root.path().join("extra")).expect("hardlink"),
            "symlink" => {
                std::fs::remove_file(&path).expect("unlink");
                std::os::unix::fs::symlink("quota.journal", &path).expect("symlink");
            }
            _ => {
                std::fs::remove_file(&path).expect("unlink");
                nix::unistd::mkfifo(
                    &path,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .expect("fifo");
            }
        }
        assert!(
            open_store(config(root.path()), runtime.handle().clone(), None).is_err(),
            "{kind}"
        );
    }
}

#[test]
fn startup_verifies_published_payload_checksum_and_charge() {
    let root = private_root();
    let runtime = runtime();
    let store = open_store(config(root.path()), runtime.handle().clone(), None).expect("store");
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, None);
    store.publish_artifact(&p).expect("publish");
    drop(store);
    let data = root
        .path()
        .join("objects")
        .join(p.key().tenant_id().to_string())
        .join(p.key().session_id().to_string())
        .join(p.key().artifact_id().to_string())
        .join("data");
    OpenOptions::new()
        .write(true)
        .open(data)
        .expect("payload")
        .write_all(b"bad")
        .expect("same-size damage");
    assert!(open_store(config(root.path()), runtime.handle().clone(), None).is_err());
}

#[test]
fn simultaneous_publication_and_discard_never_leave_a_visible_deleted_object() {
    let root = private_root();
    let runtime = runtime();
    let store =
        Arc::new(open_store(config(root.path()), runtime.handle().clone(), None).expect("store"));
    let request = request(SessionId::new(), b"abc", true);
    let receipt = store.store(&request).expect("bytes");
    let p = publication(&request, &receipt, None);
    let gate = Arc::new(Barrier::new(3));
    let publishing = {
        let store = store.clone();
        let p = p.clone();
        let gate = gate.clone();
        std::thread::spawn(move || {
            gate.wait();
            store.publish_artifact(&p)
        })
    };
    let deleting = {
        let store = store.clone();
        let receipt = receipt.clone();
        let gate = gate.clone();
        std::thread::spawn(move || {
            gate.wait();
            store.discard(&receipt)
        })
    };
    gate.wait();
    let published = publishing.join().expect("publish thread");
    let deleted = deleting.join().expect("delete thread");
    assert!(!(published.is_ok() && deleted.is_ok()));
    if let Some(visible) = store
        .get_retained_artifact(p.key(), 1_001)
        .expect("canonical state")
    {
        assert_eq!(visible, p);
        assert_eq!(read_all(&store, &p), b"abc");
        assert!(deleted.is_err());
    } else {
        assert!(published.is_err());
    }
}
