#![allow(clippy::expect_used)]

use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use browserd_artifacts::{
    ArtifactJanitor, ArtifactKey, ArtifactMultipartStore, ArtifactNamespace,
    AuthorizedCleanupCandidate, CleanupCandidate, CleanupOutcome, FilesystemArtifactStore,
    FilesystemMultipartJanitor, JanitorBackend, JanitorError,
};
use browserd_core::{ArtifactId, SessionId, TenantId};
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tokio::sync::Notify;

fn artifact_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("artifact directory should be created");
    #[cfg(unix)]
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("artifact directory should be private");
    directory
}

#[tokio::test]
async fn filesystem_janitor_bounds_each_scan_and_never_emits_an_alien_namespace() {
    let directory = artifact_directory();
    let store =
        FilesystemArtifactStore::open(directory.path()).expect("artifact store should open");
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let namespace = ArtifactNamespace::new(tenant_id.clone(), session_id.clone());
    let first_key = ArtifactKey::new(tenant_id.clone(), session_id.clone(), ArtifactId::new());
    let second_key = ArtifactKey::new(tenant_id, session_id, ArtifactId::new());
    let alien_key = ArtifactKey::new(TenantId::new(), SessionId::new(), ArtifactId::new());

    let first_upload = store
        .begin(&first_key)
        .await
        .expect("first upload should begin");
    let second_upload = store
        .begin(&second_key)
        .await
        .expect("second upload should begin");
    let alien_upload = store
        .begin(&alien_key)
        .await
        .expect("alien upload should begin");
    store
        .append(&first_upload, Bytes::from_static(b"first-partial"))
        .await
        .expect("first partial should append");

    let backend = FilesystemMultipartJanitor::new(
        store.clone(),
        namespace.clone(),
        Duration::from_secs(60 * 60),
        1,
    )
    .expect("bounded janitor configuration should be valid");
    let janitor = ArtifactJanitor::new(namespace, backend);
    let fresh = janitor
        .run_once(Utc::now())
        .await
        .expect("fresh multipart scan should succeed");
    assert_eq!(fresh.scanned, 0);

    let expired_now = Utc::now() + ChronoDuration::hours(2);
    let mut cleaned = 0_usize;
    for _ in 0..8 {
        let report = janitor
            .run_once(expired_now)
            .await
            .expect("bounded janitor pass should succeed");
        assert!(report.scanned <= 1);
        assert_eq!(report.namespace_denied, 0);
        cleaned += report.cleaned;
    }
    assert_eq!(cleaned, 2);
    assert!(
        !directory
            .path()
            .join(".multipart")
            .join(first_upload.as_str())
            .exists()
    );
    assert!(
        !directory
            .path()
            .join(".multipart")
            .join(second_upload.as_str())
            .exists()
    );
    assert!(
        directory
            .path()
            .join(".multipart")
            .join(alien_upload.as_str())
            .exists()
    );
}

#[derive(Clone)]
struct PausingJanitor {
    inner: FilesystemMultipartJanitor,
    scan_finished: std::sync::Arc<Notify>,
    resume: std::sync::Arc<Notify>,
}

impl JanitorBackend for PausingJanitor {
    async fn scan(&self, now: DateTime<Utc>) -> Result<Vec<CleanupCandidate>, JanitorError> {
        let candidates = self.inner.scan(now).await?;
        self.scan_finished.notify_one();
        self.resume.notified().await;
        Ok(candidates)
    }

    async fn cleanup(
        &self,
        candidate: &AuthorizedCleanupCandidate,
    ) -> Result<CleanupOutcome, JanitorError> {
        self.inner.cleanup(candidate).await
    }
}

#[tokio::test]
async fn activity_after_scan_invalidates_the_exact_cleanup_observation() {
    let directory = artifact_directory();
    let store =
        FilesystemArtifactStore::open(directory.path()).expect("artifact store should open");
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let namespace = ArtifactNamespace::new(tenant_id.clone(), session_id.clone());
    let key = ArtifactKey::new(tenant_id, session_id, ArtifactId::new());
    let upload_id = store
        .begin(&key)
        .await
        .expect("multipart upload should begin");
    let scan_finished = std::sync::Arc::new(Notify::new());
    let resume = std::sync::Arc::new(Notify::new());
    let backend = PausingJanitor {
        inner: FilesystemMultipartJanitor::new(
            store.clone(),
            namespace.clone(),
            Duration::from_secs(60 * 60),
            8,
        )
        .expect("janitor configuration should be valid"),
        scan_finished: std::sync::Arc::clone(&scan_finished),
        resume: std::sync::Arc::clone(&resume),
    };
    let janitor = ArtifactJanitor::new(namespace, backend);
    let run = tokio::spawn(async move {
        janitor
            .run_once(Utc::now() + ChronoDuration::hours(2))
            .await
    });
    scan_finished.notified().await;

    store
        .append(&upload_id, Bytes::from_static(b"new-activity"))
        .await
        .expect("upload activity should win before cleanup");
    resume.notify_one();
    let report = run
        .await
        .expect("janitor task should join")
        .expect("activity conflict should be isolated to its candidate");

    assert_eq!(report.scanned, 1);
    assert_eq!(report.cleaned, 0);
    assert_eq!(report.failed, 1);
    assert!(
        directory
            .path()
            .join(".multipart")
            .join(upload_id.as_str())
            .exists()
    );
    store
        .abort(&upload_id)
        .await
        .expect("active fixture should remain explicitly abortable");
}
