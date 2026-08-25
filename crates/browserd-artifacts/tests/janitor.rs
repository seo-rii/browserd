#![allow(clippy::expect_used)]

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use browserd_artifacts::{
    ArtifactJanitor, CleanupCandidate, CleanupKind, CleanupOutcome, JanitorBackend, JanitorError,
};
use chrono::{DateTime, Utc};

#[derive(Clone)]
struct StaleCandidateBackend {
    candidates: Arc<Vec<CleanupCandidate>>,
    cleaned_ids: Arc<Mutex<HashSet<String>>>,
    destructive_calls: Arc<Mutex<usize>>,
}

impl StaleCandidateBackend {
    fn new(candidates: Vec<CleanupCandidate>) -> Self {
        Self {
            candidates: Arc::new(candidates),
            cleaned_ids: Arc::new(Mutex::new(HashSet::new())),
            destructive_calls: Arc::new(Mutex::new(0)),
        }
    }

    fn destructive_calls(&self) -> usize {
        *self
            .destructive_calls
            .lock()
            .expect("test cleanup counter lock should not be poisoned")
    }
}

impl JanitorBackend for StaleCandidateBackend {
    async fn scan(&self, _now: DateTime<Utc>) -> Result<Vec<CleanupCandidate>, JanitorError> {
        // Deliberately return stale candidates after cleanup. A retry must still
        // be safe when an earlier janitor response was lost.
        Ok(self.candidates.as_ref().clone())
    }

    async fn cleanup(&self, candidate: &CleanupCandidate) -> Result<CleanupOutcome, JanitorError> {
        let mut cleaned_ids = self
            .cleaned_ids
            .lock()
            .expect("test cleanup set lock should not be poisoned");
        if !cleaned_ids.insert(candidate.id().to_owned()) {
            return Ok(CleanupOutcome::AlreadyClean);
        }

        *self
            .destructive_calls
            .lock()
            .expect("test cleanup counter lock should not be poisoned") += 1;
        Ok(CleanupOutcome::Cleaned)
    }
}

fn all_cleanup_kinds() -> Vec<CleanupCandidate> {
    vec![
        CleanupCandidate::new("temp-1", CleanupKind::OrphanTempFile),
        CleanupCandidate::new("multipart-1", CleanupKind::AbandonedMultipart),
        CleanupCandidate::new("reservation-1", CleanupKind::ExpiredReservation),
        CleanupCandidate::new("quarantine-1", CleanupKind::FailedQuarantineObject),
        CleanupCandidate::new("artifact-1", CleanupKind::ExpiredArtifact),
    ]
}

#[tokio::test]
async fn janitor_cleans_every_partial_kind_and_is_idempotent_on_retry() {
    let backend = StaleCandidateBackend::new(all_cleanup_kinds());
    let janitor = ArtifactJanitor::new(backend.clone());
    let now = DateTime::from_timestamp(1_800_000_000, 0).expect("fixed timestamp must be valid");

    let first = janitor
        .run_once(now)
        .await
        .expect("first janitor pass should succeed");
    assert_eq!(first.scanned, 5);
    assert_eq!(first.cleaned, 5);
    assert_eq!(first.already_clean, 0);
    assert_eq!(first.failed, 0);
    assert_eq!(backend.destructive_calls(), 5);

    let retry = janitor
        .run_once(now)
        .await
        .expect("retry janitor pass should succeed");
    assert_eq!(retry.scanned, 5);
    assert_eq!(retry.cleaned, 0);
    assert_eq!(retry.already_clean, 5);
    assert_eq!(retry.failed, 0);
    assert_eq!(
        backend.destructive_calls(),
        5,
        "a retry must not repeat destructive cleanup"
    );
}
