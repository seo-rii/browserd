use super::*;
use browserd_core::{
    NotificationAck, NotificationArtifactState, NotificationCommit, WorkerNotificationEvent,
};
use browserd_worker::{ArtifactPublication, ArtifactStoreReceipt};
use std::sync::atomic::{AtomicU64, Ordering};

const DAY: u64 = 86_400_000;
struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<browserd_session::SessionTime, browserd_worker::WorkerError> {
        Ok(browserd_session::SessionTime::new(
            self.0.load(Ordering::SeqCst),
        ))
    }
}
struct Scanner(Result<ArtifactScanVerdict, DependencyError>);
#[async_trait]
impl ArtifactScanner for Scanner {
    async fn scan(&self, _bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        self.0
    }
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        self.0
            .map(|verdict| observed_result(verdict, bytes, Some(1000)))
    }
}
fn open(
    root: &std::path::Path,
    runtime: &tokio::runtime::Runtime,
    clock: &Arc<Clock>,
    verdict: Option<Result<ArtifactScanVerdict, DependencyError>>,
) -> ProductionArtifactStore {
    ProductionArtifactStore::open_with_retention(
        config(root),
        runtime.handle().clone(),
        verdict.map(|verdict| Arc::new(Scanner(verdict)) as Arc<dyn ArtifactScanner>),
        browser_worker::ArtifactRetentionConfig {
            orphan_grace: Duration::from_millis(100),
            compact_at_bytes: 1,
            ..browser_worker::ArtifactRetentionConfig::default()
        },
        clock.clone(),
    )
    .expect("store")
}
fn publication(
    request: &ArtifactStoreRequest,
    receipt: &ArtifactStoreReceipt,
    now: u64,
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
        None,
        now,
        now + 100,
        receipt.scan_attestation().cloned(),
    )
    .expect("publication")
}
fn oldest(store: &ProductionArtifactStore) -> NotificationCommit {
    let page = store.pending_notifications(None, 32, 8).expect("pending");
    assert_eq!(page.commits.len(), 1);
    page.commits[0].clone()
}
fn drain(store: &ProductionArtifactStore) -> Vec<NotificationCommit> {
    let mut commits = Vec::new();
    loop {
        let page = store.pending_notifications(None, 32, 8).expect("page");
        if page.commits.is_empty() {
            break;
        }
        for commit in page.commits {
            store
                .acknowledge_notifications(&commit.ack())
                .expect("positive source ACK");
            commits.push(commit);
        }
    }
    commits
}

#[test]
fn clean_download_available_and_completed_share_one_authority_sequence_and_ack() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1001)));
    let store = open(
        root.path(),
        &runtime,
        &clock,
        Some(Ok(ArtifactScanVerdict::Clean)),
    );
    let tenant = TenantId::new();
    let session = SessionId::new();
    let request = ArtifactStoreRequest::new_browser_download(
        tenant.clone(),
        session.clone(),
        ArtifactId::new(),
        OwnershipFence::new(WorkerId::new("artifact-test").expect("worker"), 7, 9, 11),
        b"secret!!".to_vec(),
        "text/plain",
        8,
    )
    .expect("download");
    let receipt = store.store(&request).expect("clean bytes");
    assert!(
        store
            .pending_notifications(None, 32, 8)
            .expect("unpublished")
            .commits
            .is_empty()
    );
    let publication = publication(&request, &receipt, 1000);
    store.publish_artifact(&publication).expect("publish");
    store.publish_artifact(&publication).expect("exact retry");
    let commit = oldest(&store);
    assert_eq!(commit.source_sequence(), 1);
    assert_eq!(commit.occurred_at_unix_ms(), 1001);
    assert_eq!(commit.scope().tenant_id(), &tenant);
    assert_eq!(commit.descriptors().len(), 2);
    assert_eq!(
        commit.descriptors()[0].event(),
        &WorkerNotificationEvent::ArtifactStateChanged {
            artifact_id: request.key().artifact_id().clone(),
            state: NotificationArtifactState::Available
        }
    );
    assert_eq!(
        commit.descriptors()[1].event(),
        &WorkerNotificationEvent::DownloadCompleted {
            artifact_id: request.key().artifact_id().clone()
        }
    );
    for descriptor in commit.descriptors() {
        assert_eq!(descriptor.session_scope().session_id(), &session);
        assert_eq!(
            descriptor.session_scope().fence(),
            browserd_core::PlacementFence::new(7, 9, 11)
        );
    }
    assert!(
        store.pending_notifications(None, 32, 1).is_err(),
        "a page must not split an atomic transition"
    );
    let encoded = serde_json::to_string(&commit).expect("metadata");
    assert!(!encoded.contains("secret!!"));
    assert!(!encoded.contains("text/plain"));
    assert!(!encoded.contains("browserd-worker-download"));
    drop(store);
    let store = open(root.path(), &runtime, &clock, None);
    assert_eq!(oldest(&store), commit);
    store.acknowledge_notifications(&commit.ack()).expect("ACK");
    assert!(
        store
            .pending_notifications(None, 32, 8)
            .expect("ACKed")
            .commits
            .is_empty()
    );
}

#[test]
fn pending_notifications_survive_object_retirement_compaction_and_reopen() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1000)));
    let store = open(root.path(), &runtime, &clock, None);
    let request = request(SessionId::new(), b"secret!!", true);
    let receipt = store.store(&request).expect("bytes");
    let published = publication(&request, &receipt, 1000);
    store.publish_artifact(&published).expect("publish");
    let first = oldest(&store);
    clock.0.store(1101, Ordering::SeqCst);
    store.maintain(32).expect("exact expiry cleanup");
    clock.0.store(1101 + DAY, Ordering::SeqCst);
    store.maintain(32).expect("retire original object metadata");
    assert_eq!(oldest(&store), first);
    assert!(
        store
            .get_retained_artifact(request.key(), 1101 + DAY)
            .expect("retired")
            .is_none()
    );
    drop(store);
    let store = open(root.path(), &runtime, &clock, None);
    let commits = drain(&store);
    assert_eq!(commits.len(), 3);
    assert_eq!(commits[0], first);
    assert_eq!(
        commits
            .iter()
            .map(NotificationCommit::source_sequence)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    for (commit, state) in commits.iter().zip([
        NotificationArtifactState::Available,
        NotificationArtifactState::Deleting,
        NotificationArtifactState::Deleted,
    ]) {
        assert_eq!(commit.scope(), first.scope());
        assert_eq!(
            commit.descriptors()[0].event(),
            &WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: request.key().artifact_id().clone(),
                state
            }
        );
    }
    store.maintain(32).expect("compact after copy ACK");
    drop(store);
    let store = open(root.path(), &runtime, &clock, None);
    store
        .acknowledge_notifications(&commits[2].ack())
        .expect("lost ACK reply exact replay after compaction");
    let next = request_for(
        request.key().tenant_id().clone(),
        SessionId::new(),
        b"next",
        true,
    );
    let receipt = store.store(&next).expect("capacity reused");
    let next_publication = publication(&next, &receipt, 1101 + DAY);
    store
        .publish_artifact(&next_publication)
        .expect("new publication");
    let next = oldest(&store);
    assert_eq!(next.scope(), first.scope());
    assert_eq!(next.source_sequence(), 4);
}

#[test]
fn nonclean_scan_commits_metadata_only_and_never_available_or_download_completed() {
    for (verdict, state) in [
        (
            Ok(ArtifactScanVerdict::Rejected),
            NotificationArtifactState::Rejected,
        ),
        (
            Ok(ArtifactScanVerdict::Quarantined),
            NotificationArtifactState::Quarantined,
        ),
        (
            Err(DependencyError::Unavailable),
            NotificationArtifactState::Rejected,
        ),
    ] {
        let root = private_root();
        let runtime = runtime();
        let clock = Arc::new(Clock(AtomicU64::new(1001)));
        let store = open(root.path(), &runtime, &clock, Some(verdict));
        let request = ArtifactStoreRequest::new_browser_download(
            TenantId::new(),
            SessionId::new(),
            ArtifactId::new(),
            OwnershipFence::new(WorkerId::new("artifact-test").expect("worker"), 1, 2, 3),
            b"unsafe".to_vec(),
            "text/plain",
            8,
        )
        .expect("request");
        assert_eq!(store.store(&request), Err(DependencyError::Rejected));
        let commit = oldest(&store);
        assert_eq!(commit.descriptors().len(), 1);
        assert_eq!(
            commit.descriptors()[0].event(),
            &WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: request.key().artifact_id().clone(),
                state
            }
        );
        assert_eq!(store.store(&request), Err(DependencyError::Rejected));
        assert_eq!(
            oldest(&store),
            commit,
            "same logical rejection is idempotent"
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
        assert!(
            store
                .get_retained_artifact(request.key(), 1001)
                .expect("hidden metadata")
                .is_none()
        );
        drop(store);
        let store = open(root.path(), &runtime, &clock, None);
        assert_eq!(oldest(&store), commit);
        store.acknowledge_notifications(&commit.ack()).expect("ACK");
    }
}

#[test]
fn source_ack_digest_and_tenant_conflicts_preserve_pending_custody() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1000)));
    let store = open(root.path(), &runtime, &clock, None);
    let request = request(SessionId::new(), b"bytes", true);
    let receipt = store.store(&request).expect("bytes");
    store
        .publish_artifact(&publication(&request, &receipt, 1000))
        .expect("publication");
    let commit = oldest(&store);
    for field in ["digest", "tenant"] {
        let mut value = serde_json::to_value(commit.ack()).expect("ACK");
        if field == "digest" {
            let byte = value["digest"][0].as_u64().expect("byte");
            value["digest"][0] = serde_json::json!((byte + 1) % 256);
        } else {
            value["scope"]["tenant_id"] = serde_json::json!(TenantId::new());
        }
        let wrong: NotificationAck =
            serde_json::from_value(value).expect("valid but conflicting ACK");
        assert!(store.acknowledge_notifications(&wrong).is_err());
        assert_eq!(oldest(&store), commit);
    }
    store.acknowledge_notifications(&commit.ack()).expect("ACK");
    let bytes = std::fs::read(root.path().join("publications.journal")).expect("journal");
    store
        .acknowledge_notifications(&commit.ack())
        .expect("exact replay");
    assert_eq!(
        std::fs::read(root.path().join("publications.journal")).expect("journal"),
        bytes
    );
}

#[test]
fn notification_pagination_visits_empty_scopes_and_rejects_foreign_cursors() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1000)));
    let store = open(root.path(), &runtime, &clock, None);
    for _ in 0..3 {
        let request = request(SessionId::new(), b"x", true);
        let receipt = store.store(&request).expect("bytes");
        store
            .publish_artifact(&publication(&request, &receipt, 1000))
            .expect("publication");
    }
    let first = store.pending_notifications(None, 1, 8).expect("first");
    assert_eq!(first.examined, 1);
    assert!(!first.is_complete);
    let first_commit = first.commits[0].clone();
    store
        .acknowledge_notifications(&first_commit.ack())
        .expect("ACK");
    let empty = store
        .pending_notifications(None, 1, 8)
        .expect("empty scope");
    assert_eq!(empty.examined, 1);
    assert!(empty.commits.is_empty());
    assert!(!empty.is_complete);
    let next = store
        .pending_notifications(empty.cursor.as_deref(), 1, 8)
        .expect("progress");
    assert_eq!(next.commits.len(), 1);
    assert_ne!(next.commits[0].scope(), first_commit.scope());
    let other_root = private_root();
    let other = open(other_root.path(), &runtime, &clock, None);
    assert!(
        other
            .pending_notifications(first.cursor.as_deref(), 1, 8)
            .is_err()
    );
}

#[test]
fn restart_commits_deleted_only_after_the_exact_backend_generation_receipt() {
    use browserd_artifacts::ArtifactObjectStore;
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1000)));
    let store = open(root.path(), &runtime, &clock, None);
    let request = request(SessionId::new(), b"bytes", true);
    let receipt = store.store(&request).expect("bytes");
    let published = publication(&request, &receipt, 1000);
    store.publish_artifact(&published).expect("publish");
    store
        .withdraw_artifact(&published)
        .expect("durable metadata deletion intent");
    let backend = FilesystemArtifactStore::open(root.path()).expect("owned test backend");
    runtime
        .block_on(backend.delete_exact(
            &request.key().namespace(),
            request.key(),
            receipt.object_generation(),
        ))
        .expect("simulate backend completion before metadata ACK");
    drop(backend);
    drop(store);
    let store = open(root.path(), &runtime, &clock, None);
    let commits = drain(&store);
    assert_eq!(commits.len(), 3);
    assert_eq!(
        commits[2].descriptors()[0].event(),
        &WorkerNotificationEvent::ArtifactStateChanged {
            artifact_id: request.key().artifact_id().clone(),
            state: NotificationArtifactState::Deleted
        }
    );
    drop(store);
    let store = open(root.path(), &runtime, &clock, None);
    assert!(
        drain(&store).is_empty(),
        "same exact backend receipt cannot emit twice"
    );
}

#[test]
fn compacted_source_tail_detects_loss_of_a_whole_pending_frame() {
    let root = private_root();
    let runtime = runtime();
    let clock = Arc::new(Clock(AtomicU64::new(1000)));
    let store = open(root.path(), &runtime, &clock, None);
    let request = request(SessionId::new(), b"bytes", true);
    let receipt = store.store(&request).expect("bytes");
    store
        .publish_artifact(&publication(&request, &receipt, 1000))
        .expect("publish");
    clock.0.store(1101, Ordering::SeqCst);
    store.maintain(32).expect("delete");
    clock.0.store(1101 + DAY, Ordering::SeqCst);
    store.maintain(32).expect("retire and compact");
    drop(store);
    let path = root.path().join("publications.journal");
    let mut bytes = std::fs::read(&path).expect("journal");
    let cutoff = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .expect("prior full frame")
        + 1;
    bytes.truncate(cutoff);
    std::fs::write(path, bytes).expect("simulate lost complete frame");
    assert!(
        ProductionArtifactStore::open_with_retention(
            config(root.path()),
            runtime.handle().clone(),
            None,
            browser_worker::ArtifactRetentionConfig::default(),
            clock
        )
        .is_err(),
        "permanent source tail must not silently rewind to surviving pending frames"
    );
}
