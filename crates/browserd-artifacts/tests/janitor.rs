#![allow(clippy::expect_used)]

mod common;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use browserd_artifacts::{
    ArtifactJanitor, ArtifactKey, ArtifactObjectGeneration, AuthorizedCleanupCandidate,
    CleanupCandidate, CleanupKind, CleanupOutcome, JanitorBackend, JanitorError,
};
use chrono::{DateTime, Utc};

use common::{artifact_fixture, artifact_key};

#[derive(Clone)]
struct StaleCandidateBackend {
    candidates: Arc<Vec<CleanupCandidate>>,
    cleaned: Arc<Mutex<HashSet<(ArtifactKey, String, ArtifactObjectGeneration)>>>,
    destructive_calls: Arc<Mutex<usize>>,
}

impl StaleCandidateBackend {
    fn new(candidates: Vec<CleanupCandidate>) -> Self {
        Self {
            candidates: Arc::new(candidates),
            cleaned: Arc::new(Mutex::new(HashSet::new())),
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
        Ok(self.candidates.as_ref().clone())
    }

    async fn cleanup(
        &self,
        candidate: &AuthorizedCleanupCandidate,
    ) -> Result<CleanupOutcome, JanitorError> {
        let identity = (
            candidate.key().clone(),
            candidate.id().to_owned(),
            candidate.object_generation(),
        );
        let mut cleaned = self
            .cleaned
            .lock()
            .expect("test cleanup set lock should not be poisoned");
        if !cleaned.insert(identity) {
            return Ok(CleanupOutcome::AlreadyClean);
        }

        *self
            .destructive_calls
            .lock()
            .expect("test cleanup counter lock should not be poisoned") += 1;
        Ok(CleanupOutcome::Cleaned)
    }
}

fn generation(byte: u8) -> ArtifactObjectGeneration {
    ArtifactObjectGeneration::new([byte; 32])
}

fn all_cleanup_kinds(namespace: &browserd_artifacts::ArtifactNamespace) -> Vec<CleanupCandidate> {
    vec![
        CleanupCandidate::new(
            artifact_key(namespace),
            "temp-1",
            CleanupKind::OrphanTempFile,
            generation(1),
        ),
        CleanupCandidate::new(
            artifact_key(namespace),
            "multipart-1",
            CleanupKind::AbandonedMultipart,
            generation(2),
        ),
        CleanupCandidate::new(
            artifact_key(namespace),
            "reservation-1",
            CleanupKind::ExpiredReservation,
            generation(3),
        ),
        CleanupCandidate::new(
            artifact_key(namespace),
            "quarantine-1",
            CleanupKind::FailedQuarantineObject,
            generation(4),
        ),
        CleanupCandidate::new(
            artifact_key(namespace),
            "artifact-1",
            CleanupKind::ExpiredArtifact,
            generation(5),
        ),
    ]
}

#[tokio::test]
async fn janitor_cleans_every_partial_kind_and_is_idempotent_on_retry() {
    let fixture = artifact_fixture();
    let backend = StaleCandidateBackend::new(all_cleanup_kinds(&fixture.namespace));
    let janitor = ArtifactJanitor::new(fixture.namespace, backend.clone());
    let now = DateTime::from_timestamp(1_800_000_000, 0).expect("fixed timestamp must be valid");

    let first = janitor
        .run_once(now)
        .await
        .expect("first janitor pass should succeed");
    assert_eq!(first.scanned, 5);
    assert_eq!(first.cleaned, 5);
    assert_eq!(first.already_clean, 0);
    assert_eq!(first.namespace_denied, 0);
    assert_eq!(first.failed, 0);
    assert_eq!(backend.destructive_calls(), 5);

    let retry = janitor
        .run_once(now)
        .await
        .expect("retry janitor pass should succeed");
    assert_eq!(retry.scanned, 5);
    assert_eq!(retry.cleaned, 0);
    assert_eq!(retry.already_clean, 5);
    assert_eq!(retry.namespace_denied, 0);
    assert_eq!(retry.failed, 0);
    assert_eq!(
        backend.destructive_calls(),
        5,
        "a retry must not repeat destructive cleanup"
    );
}

#[tokio::test]
async fn alien_tenant_or_session_candidates_never_reach_destructive_cleanup() {
    let fixture = artifact_fixture();
    let alien = artifact_fixture();
    let own = CleanupCandidate::new(
        fixture.key,
        "own-object",
        CleanupKind::ExpiredArtifact,
        generation(1),
    );
    let alien_tenant = CleanupCandidate::new(
        alien.key,
        "alien-object",
        CleanupKind::ExpiredArtifact,
        generation(1),
    );
    let backend = StaleCandidateBackend::new(vec![own, alien_tenant]);
    let janitor = ArtifactJanitor::new(fixture.namespace, backend.clone());

    let report = janitor
        .run_once(Utc::now())
        .await
        .expect("namespace denial is a per-candidate result");

    assert_eq!(report.scanned, 2);
    assert_eq!(report.cleaned, 1);
    assert_eq!(report.namespace_denied, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(backend.destructive_calls(), 1);
}

#[derive(Clone)]
struct OwnershipCheckingBackend {
    candidates: Arc<Vec<CleanupCandidate>>,
    current_owners: Arc<Mutex<HashMap<String, (ArtifactKey, ArtifactObjectGeneration)>>>,
    destructive_calls: Arc<Mutex<usize>>,
}

impl JanitorBackend for OwnershipCheckingBackend {
    async fn scan(&self, _now: DateTime<Utc>) -> Result<Vec<CleanupCandidate>, JanitorError> {
        Ok(self.candidates.as_ref().clone())
    }

    async fn cleanup(
        &self,
        candidate: &AuthorizedCleanupCandidate,
    ) -> Result<CleanupOutcome, JanitorError> {
        let owners = self
            .current_owners
            .lock()
            .expect("owner map lock should not be poisoned");
        let expected = (candidate.key().clone(), candidate.object_generation());
        if owners.get(candidate.id()) != Some(&expected) {
            return Err(JanitorError::new("cleanup ownership changed"));
        }
        drop(owners);
        *self
            .destructive_calls
            .lock()
            .expect("destructive counter lock should not be poisoned") += 1;
        Ok(CleanupOutcome::Cleaned)
    }
}

#[tokio::test]
async fn authorized_cleanup_request_preserves_the_exact_artifact_fence_for_revalidation() {
    let fixture = artifact_fixture();
    let replacement_key = artifact_key(&fixture.namespace);
    let candidate = CleanupCandidate::new(
        fixture.key,
        "rebound-object",
        CleanupKind::AbandonedMultipart,
        generation(1),
    );
    let backend = OwnershipCheckingBackend {
        candidates: Arc::new(vec![candidate]),
        current_owners: Arc::new(Mutex::new(HashMap::from([(
            "rebound-object".to_owned(),
            (replacement_key, generation(1)),
        )]))),
        destructive_calls: Arc::new(Mutex::new(0)),
    };
    let janitor = ArtifactJanitor::new(fixture.namespace, backend.clone());

    let report = janitor
        .run_once(Utc::now())
        .await
        .expect("ownership change is isolated to its candidate");

    assert_eq!(report.failed, 1);
    assert_eq!(report.cleaned, 0);
    assert_eq!(
        *backend
            .destructive_calls
            .lock()
            .expect("destructive counter lock should not be poisoned"),
        0
    );
}

#[tokio::test]
async fn stale_generation_cannot_delete_a_replacement_with_the_same_artifact_key() {
    let fixture = artifact_fixture();
    let candidate = CleanupCandidate::new(
        fixture.key.clone(),
        "replacement-object",
        CleanupKind::AbandonedMultipart,
        generation(1),
    );
    let backend = OwnershipCheckingBackend {
        candidates: Arc::new(vec![candidate]),
        current_owners: Arc::new(Mutex::new(HashMap::from([(
            "replacement-object".to_owned(),
            (fixture.key, generation(2)),
        )]))),
        destructive_calls: Arc::new(Mutex::new(0)),
    };
    let janitor = ArtifactJanitor::new(fixture.namespace, backend.clone());

    let report = janitor
        .run_once(Utc::now())
        .await
        .expect("generation conflict is isolated to its candidate");

    assert_eq!(report.failed, 1);
    assert_eq!(report.cleaned, 0);
    assert_eq!(
        *backend
            .destructive_calls
            .lock()
            .expect("destructive counter lock should not be poisoned"),
        0
    );
}

#[derive(Clone)]
struct LostResponseBackend {
    candidate: CleanupCandidate,
    cleaned: Arc<Mutex<bool>>,
    destructive_calls: Arc<Mutex<usize>>,
}

impl JanitorBackend for LostResponseBackend {
    async fn scan(&self, _now: DateTime<Utc>) -> Result<Vec<CleanupCandidate>, JanitorError> {
        Ok(vec![self.candidate.clone()])
    }

    async fn cleanup(
        &self,
        _candidate: &AuthorizedCleanupCandidate,
    ) -> Result<CleanupOutcome, JanitorError> {
        let mut cleaned = self
            .cleaned
            .lock()
            .expect("cleanup state lock should not be poisoned");
        if *cleaned {
            return Ok(CleanupOutcome::AlreadyClean);
        }
        *cleaned = true;
        *self
            .destructive_calls
            .lock()
            .expect("destructive counter lock should not be poisoned") += 1;
        Err(JanitorError::new("cleanup response lost after delete"))
    }
}

#[tokio::test]
async fn cleanup_response_loss_retries_without_repeating_the_destructive_effect() {
    let fixture = artifact_fixture();
    let backend = LostResponseBackend {
        candidate: CleanupCandidate::new(
            fixture.key,
            "lost-response",
            CleanupKind::ExpiredArtifact,
            generation(1),
        ),
        cleaned: Arc::new(Mutex::new(false)),
        destructive_calls: Arc::new(Mutex::new(0)),
    };
    let janitor = ArtifactJanitor::new(fixture.namespace, backend.clone());

    let first = janitor
        .run_once(Utc::now())
        .await
        .expect("per-candidate cleanup failure should be reported");
    assert_eq!(first.failed, 1);
    let retry = janitor
        .run_once(Utc::now())
        .await
        .expect("retry should observe the completed cleanup");
    assert_eq!(retry.already_clean, 1);
    assert_eq!(
        *backend
            .destructive_calls
            .lock()
            .expect("destructive counter lock should not be poisoned"),
        1
    );
}
