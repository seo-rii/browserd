#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use browserd_artifacts::{ArtifactKey, ArtifactState};
use browserd_worker::{GeneratedArtifactRequest, GeneratedArtifactSink, GeneratedCaptureResult};
use serde_json::{Value, json};

struct Rollback {
    receipt: ArtifactStoreReceipt,
    aborted: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl GeneratedArtifactSink for Rollback {
    async fn write_chunk(&mut self, _: &[u8]) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    async fn finish(&mut self) -> Result<ArtifactStoreReceipt, DependencyError> {
        Ok(self.receipt.clone())
    }
    async fn abort(&mut self) -> Result<(), DependencyError> {
        self.aborted.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
pub(super) fn capture(
    driver: &FakeDriver,
    request: GeneratedArtifactRequest,
) -> Result<GeneratedCaptureResult, DependencyError> {
    driver
        .capture_requests
        .lock()
        .unwrap()
        .push(request.clone());
    let mode = driver.capture_mode.load(Ordering::SeqCst);
    let key = if mode == 1 {
        ArtifactKey::new(
            request.key().tenant_id().clone(),
            request.key().session_id().clone(),
            ArtifactId::new(),
        )
    } else {
        request.key().clone()
    };
    let generation = ArtifactObjectGeneration::new(if mode == 2 { [0; 32] } else { [4; 32] });
    let bytes = if mode == 4 {
        request.max_bytes() + 1
    } else {
        16
    };
    let checksum = ArtifactChecksum::new([3; 32]);
    let receipt = if mode == 3 {
        ArtifactStoreReceipt::new(
            key,
            bytes,
            checksum,
            request.content_type(),
            generation,
            ArtifactScanVerdict::Clean,
        )
    } else {
        ArtifactStoreReceipt::new_generated(
            key,
            bytes,
            checksum,
            request.content_type(),
            generation,
        )
    }
    .unwrap();
    Ok(GeneratedCaptureResult {
        result: serde_json::to_vec(&json!({"artifact_id":request.key().artifact_id()})).unwrap(),
        receipt: Some(receipt.clone()),
        cleanup: Some(Box::new(Rollback {
            receipt,
            aborted: driver.capture_aborts.clone(),
        })),
    })
}
fn run_capture(
    worker: &WorkerControlPlane<FakeDriver, FakeSandbox>,
    peer: &AuthenticatedPeer,
    created: &CreateSessionOutcome,
    key: &str,
    now: u64,
) -> browserd_worker::WorkerActionSnapshot {
    worker
        .submit_action(
            peer,
            PrincipalId::new(),
            &created.session_id,
            &created.fence,
            key,
            [7; 32],
            ActionKind::ReadOnly,
            None,
            Some(created.primary_page_id.clone()),
            serde_json::to_vec(&json!({"type":"screenshot"})).unwrap(),
            None,
            SessionTime::new(now),
        )
        .unwrap();
    worker
        .run_next_action(
            peer,
            &created.session_id,
            &created.fence,
            SessionTime::new(now + 1),
        )
        .unwrap()
        .unwrap()
}
#[test]
fn generated_capture_registers_available_metadata_and_releases_unused_reservation() {
    let (worker, peer, driver, _) =
        ready_worker_with_artifact_limits(WorkerArtifactLimits::new(1024, 2048, 1024).unwrap())
            .expect("worker");
    let created = create_ready_session(&worker, &peer, "capture-success").expect("session");
    for (index, key) in ["first", "second"].into_iter().enumerate() {
        let action = run_capture(&worker, &peer, &created, key, 2 + 2 * index as u64);
        assert_eq!(action.status, ActionStatus::Succeeded);
        let json: Value = serde_json::from_slice(action.result.as_ref().unwrap()).unwrap();
        let artifact: ArtifactId = serde_json::from_value(json["artifact_id"].clone()).unwrap();
        let metadata = worker
            .get_artifact(&peer, &created.session_id, &artifact, &created.fence)
            .unwrap();
        assert_eq!(metadata.state, ArtifactState::Available);
        assert_eq!(metadata.source, ArtifactContentSource::Generated);
        assert_eq!(metadata.origin, "browserd-capture");
        assert_eq!(
            metadata.object_generation,
            ArtifactObjectGeneration::new([4; 32])
        );
        assert_eq!(metadata.size_bytes, 16);
    }
    assert_eq!(driver.capture_aborts.load(Ordering::SeqCst), 0);
    assert_eq!(driver.capture_requests.lock().unwrap().len(), 2);
}
#[test]
fn invalid_generated_receipts_rollback_and_release_quota_before_the_next_capture() {
    for mode in 1..=4 {
        let (worker, peer, driver, _) =
            ready_worker_with_artifact_limits(WorkerArtifactLimits::new(1024, 2048, 1024).unwrap())
                .expect("worker");
        let created = create_ready_session(&worker, &peer, "capture-rollback").expect("session");
        driver.capture_mode.store(mode, Ordering::SeqCst);
        let failed = run_capture(&worker, &peer, &created, "invalid", 2);
        assert_eq!(
            failed.status,
            ActionStatus::FailedKnown,
            "receipt mode {mode}"
        );
        assert_eq!(driver.capture_aborts.load(Ordering::SeqCst), 1);
        let request = driver.capture_requests.lock().unwrap()[0].clone();
        assert!(
            worker
                .get_artifact(
                    &peer,
                    &created.session_id,
                    request.key().artifact_id(),
                    &created.fence
                )
                .is_err()
        );
        driver.capture_mode.store(0, Ordering::SeqCst);
        assert_eq!(
            run_capture(&worker, &peer, &created, "valid", 4).status,
            ActionStatus::Succeeded
        );
        assert_eq!(driver.capture_aborts.load(Ordering::SeqCst), 1);
    }
}
