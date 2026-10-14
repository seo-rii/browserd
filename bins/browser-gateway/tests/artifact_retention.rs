#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Real storage + control plane + authenticated RPC handler + gateway, with no browser session.
//! The scanner supplies explicit test observations; this is not scanner qualification.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browser_worker::{
    ArtifactRetentionConfig, ArtifactScanResult, ArtifactScanner, ArtifactStoreConfig,
    ClamAvFreshnessPolicy, ProductionArtifactStore, RoutedArtifactStore, UnixClamAvScanner,
};
use browserd_actions::ActionJournalLimits;
use browserd_api::{
    ApiRequest, ApiResponse, ApiRouter, ApiService, ArtifactListRequest, ArtifactRequest,
};
use browserd_artifacts::{
    ArtifactContentMetadata, ArtifactContentSource, ArtifactKey, ArtifactReadLimits,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{ActionId, ArtifactId, PageId, PrincipalId, SessionId, TenantId, WorkerId};
use browserd_http::ArtifactTransport;
use browserd_policy::CanonicalActionProposal;
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactPublication,
    ArtifactPublicationWire, ArtifactReadStream, ArtifactScanAttestation, ArtifactScanVerdict,
    ArtifactScannerObservation, ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer,
    ChromiumDriver, DependencyError, InternalEndpoint, LiveApprovalContext, SandboxClient,
    WorkerClock, WorkerConfig, WorkerControlPlane, WorkerControlPlaneRpcHandler,
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerError,
    WorkerRetainedArtifactReceipt, WorkerRetainedArtifactScope, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcHandler, WorkerRpcRequest, WorkerRpcResponse,
};
use chrono::Utc;
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;

#[path = "support/artifact_scanner_peer.rs"]
mod artifact_scanner_peer;
use artifact_scanner_peer::ScannerPeer;

#[derive(Default)]
struct NoBrowser(AtomicUsize);
impl NoBrowser {
    fn forbidden<T>(&self) -> T {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("retained reads must not access browser lifecycle or actions");
    }
}
impl ChromiumDriver for NoBrowser {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.forbidden()
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        self.forbidden()
    }
    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        self.forbidden()
    }
    fn create_page(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        self.forbidden()
    }
    fn close_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        self.forbidden()
    }
    fn activate_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        self.forbidden()
    }
    fn execute_action(&self, _: &SessionId, _: Option<&PageId>, _: &[u8]) -> ActionExecutionResult {
        self.forbidden()
    }
    fn inspect_approval_context(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        self.forbidden()
    }
    fn execute_approved_action(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &[u8],
        _: &CanonicalActionProposal,
        _: &LiveApprovalContext,
        _: &mut dyn FnMut(&LiveApprovalContext) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        self.forbidden()
    }
    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        self.forbidden()
    }
}

struct RetainedSandbox {
    store: ProductionArtifactStore,
    forbidden: Arc<NoBrowser>,
}
impl SandboxClient for RetainedSandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.forbidden.forbidden()
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.forbidden.forbidden()
    }
    fn cleanup(&self, _: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        self.forbidden.forbidden()
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        self.forbidden.forbidden()
    }
    fn store_artifact(
        &self,
        _: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.forbidden.forbidden()
    }
    fn get_retained_artifact(
        &self,
        key: &ArtifactKey,
        now: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        self.store.get_retained_artifact(key, now)
    }
    fn list_retained_artifacts(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        after: Option<&ArtifactId>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        self.store
            .list_retained_artifacts(tenant, session, after, limit, now)
    }
    fn open_retained_artifact(
        &self,
        publication: &ArtifactPublication,
        limits: ArtifactReadLimits,
        now: u64,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        self.store.open_retained_artifact(publication, limits, now)
    }
}
struct CleanScanner(Arc<AtomicUsize>, Arc<Clock>);
#[async_trait]
impl ArtifactScanner for CleanScanner {
    async fn scan(&self, bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        self.scan_with_observation(bytes)
            .await
            .map(|result| result.verdict)
    }
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let now = self
            .1
            .now()
            .map_err(|_| DependencyError::Unavailable)?
            .get();
        Ok(ArtifactScanResult {
            verdict: ArtifactScanVerdict::Clean,
            observation: Some(ArtifactScannerObservation {
                schema_version: 1,
                program_version: "fixture-1".to_owned(),
                database_version: 1,
                database_built_at_unix_millis: now - 3_600_000,
                observed_before_unix_millis: now,
                observed_after_unix_millis: now,
                expected_peer_uid: 1000,
                peer_uid: 1000,
                version_metadata_sha256: Sha256::digest(b"fixture scanner version").into(),
                scanned_size_bytes: bytes.len() as u64,
                scanned_checksum_sha256: Sha256::digest(bytes).into(),
                max_database_age_millis: 48 * 60 * 60 * 1000,
                max_future_skew_millis: 5 * 60 * 1000,
            }),
        })
    }
}
struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}
struct NoPending;
impl GatewayWorkerPending for NoPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        panic!("no actions")
    }
}

/// All normal replies come from a real control-plane RPC handler, including serialization.
/// Faults model an untrusted/mismatched reply after this actual backend response.
struct HandlerClient {
    handler: Arc<dyn WorkerRpcHandler>,
    runtime: Arc<Runtime>,
    fault: AtomicUsize,
    requests: AtomicUsize,
}
impl GatewayWorkerClient for HandlerClient {
    type PendingAction = NoPending;
    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        panic!("no create session")
    }
    fn enqueue_action(&self, _: WorkerRpcRequest) -> Result<NoPending, WorkerRpcEnqueueError> {
        panic!("no enqueue")
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        assert!(
            matches!(
                request,
                WorkerRpcRequest::ListRetainedArtifacts { .. }
                    | WorkerRpcRequest::GetRetainedArtifact { .. }
                    | WorkerRpcRequest::OpenRetainedArtifact { .. }
                    | WorkerRpcRequest::ReadRetainedArtifact { .. }
                    | WorkerRpcRequest::CloseRetainedArtifact { .. }
            ),
            "gateway tried live session authority"
        );
        let wire = serde_json::to_vec(&request).map_err(|_| WorkerRpcError::Protocol)?;
        let decoded = serde_json::from_slice(&wire).map_err(|_| WorkerRpcError::Protocol)?;
        let response = self.runtime.block_on(self.handler.handle(decoded));
        let mut response: WorkerRpcResponse = serde_json::from_slice(
            &serde_json::to_vec(&response).map_err(|_| WorkerRpcError::Protocol)?,
        )
        .map_err(|_| WorkerRpcError::Protocol)?;
        let fault = self.fault.load(Ordering::SeqCst);
        match &mut response {
            WorkerRpcResponse::RetainedArtifact(receipt)
                if fault <= 7 || (10..=12).contains(&fault) =>
            {
                corrupt_receipt(receipt, fault)
            }
            WorkerRpcResponse::RetainedArtifacts(receipts) if fault <= 7 => {
                if let Some(receipt) = receipts.last_mut() {
                    corrupt_receipt(receipt, fault);
                }
            }
            WorkerRpcResponse::RetainedArtifactOpened { receipt, .. } if fault == 8 => {
                receipt.publication.artifact.display_filename = Some("changed.txt".to_owned());
            }
            WorkerRpcResponse::RetainedArtifactOpened { receipt, .. } if fault == 13 => {
                receipt.publication.scan_attestation = None;
            }
            WorkerRpcResponse::RetainedArtifactChunk { bytes, .. }
                if fault == 9 && !bytes.is_empty() =>
            {
                bytes[0] ^= 1;
            }
            _ => {}
        }
        Ok(response)
    }
}
fn corrupt_receipt(receipt: &mut WorkerRetainedArtifactReceipt, fault: usize) {
    match fault {
        1 => receipt.serving_worker_id = WorkerId::new("foreign-worker").unwrap(),
        2 => receipt.serving_worker_epoch += 1,
        3 => receipt.publication.artifact.fence.tenant_id = TenantId::new(),
        4 => receipt.publication.artifact.fence.session_id = SessionId::new(),
        5 => receipt.publication.expires_at_unix_millis = 1,
        6 => receipt.publication.artifact.display_filename = Some("../private/file".to_owned()),
        7 => receipt.publication.original_worker_id = WorkerId::new("foreign-original").unwrap(),
        10 => receipt.publication.scan_attestation = None,
        11 => {
            let publication = receipt.publication.to_publication().unwrap();
            receipt.publication.scan_attestation = Some(Box::new(
                ArtifactScanAttestation::new(
                    publication.key(),
                    publication.original_fence(),
                    publication.metadata().source(),
                    browserd_artifacts::ArtifactObjectGeneration::new([99; 32]),
                    publication.metadata().size_bytes(),
                    *publication.metadata().checksum(),
                    publication
                        .scan_attestation()
                        .unwrap()
                        .observation()
                        .clone(),
                )
                .unwrap(),
            ));
        }
        12 => {
            let mut evidence =
                serde_json::to_value(receipt.publication.scan_attestation.as_ref().unwrap())
                    .unwrap();
            evidence["observation"]["database_version"] = serde_json::json!(999);
            receipt.publication.scan_attestation = Some(serde_json::from_value(evidence).unwrap());
        }
        _ => {}
    }
}

#[test]
fn retained_scanned_artifacts_require_unchanged_generation_bound_evidence() {
    let f = Fixture::new();
    let id = f
        .artifacts
        .iter()
        .find(|(publication, _)| {
            publication.metadata().source() == ArtifactContentSource::ClientUpload
        })
        .unwrap()
        .0
        .key()
        .artifact_id();
    for fault in 10..=12 {
        f.client.fault.store(fault, Ordering::SeqCst);
        assert!(
            f.router
                .execute(
                    &f.principal,
                    ApiRequest::GetArtifact(ArtifactRequest {
                        session_id: f.scope.session_id.clone(),
                        artifact_id: id.clone(),
                    }),
                )
                .is_err(),
            "scan evidence fault {fault}"
        );
    }
    f.client.fault.store(0, Ordering::SeqCst);
    let token = f.download_token(id);
    f.client.fault.store(13, Ordering::SeqCst);
    f.runtime.block_on(async {
        assert!(
            f.gateway
                .consume(&f.principal, &f.scope.session_id, id, &token)
                .await
                .is_err()
        );
    });
    f.assert_browser_unused();
}

#[test]
fn unix_scanner_evidence_survives_storage_restart_retained_rpc_and_gateway_download() {
    let f = Fixture::with_scanner(true);
    let (uid, version_sha256) = f.scanner_identity.unwrap();
    for (publication, expected_bytes) in &f.artifacts {
        let id = publication.key().artifact_id();
        let receipt = f.receipt(id);
        assert_eq!(receipt.publication.to_publication().unwrap(), *publication);
        match publication.metadata().source() {
            ArtifactContentSource::Generated => assert!(publication.scan_attestation().is_none()),
            ArtifactContentSource::ClientUpload | ArtifactContentSource::BrowserDownload => {
                let evidence = publication.scan_attestation().unwrap();
                evidence
                    .validate_for(
                        publication.key(),
                        publication.original_fence(),
                        publication.metadata(),
                        publication.object_generation(),
                    )
                    .unwrap();
                let observation = evidence.observation();
                assert_eq!(observation.program_version, "1.4.3");
                assert_eq!(observation.database_version, 1);
                assert_eq!(observation.peer_uid, uid);
                assert_eq!(observation.expected_peer_uid, uid);
                assert_eq!(observation.version_metadata_sha256, version_sha256);
                assert_eq!(observation.scanned_size_bytes, expected_bytes.len() as u64);
                assert_eq!(
                    observation.scanned_checksum_sha256,
                    <[u8; 32]>::from(Sha256::digest(expected_bytes))
                );
            }
        }
        let token = f.download_token(id);
        let bytes = f.runtime.block_on(async {
            let mut body = f
                .gateway
                .consume(&f.principal, &f.scope.session_id, id, &token)
                .await
                .unwrap();
            let mut bytes = Vec::new();
            while let Some(chunk) = body.stream.next_chunk().await.unwrap() {
                bytes.extend_from_slice(&chunk);
            }
            bytes
        });
        assert_eq!(&bytes, expected_bytes);
    }
    f.assert_browser_unused();
}

struct Fixture {
    gateway: Arc<GatewayWorkerRuntime<HandlerClient>>,
    router: ApiRouter<GatewayWorkerRuntime<HandlerClient>>,
    client: Arc<HandlerClient>,
    no_browser: Arc<NoBrowser>,
    clock: Arc<Clock>,
    principal: AuthenticatedPrincipal,
    scope: WorkerRetainedArtifactScope,
    artifacts: Vec<(ArtifactPublication, Vec<u8>)>,
    orphan: ArtifactId,
    expired: ArtifactId,
    scanner_identity: Option<(u32, [u8; 32])>,
    _root: tempfile::TempDir,
    _journal: tempfile::TempDir,
    runtime: Arc<Runtime>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_scanner(false)
    }
    fn with_scanner(use_unix: bool) -> Self {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = tempfile::tempdir().unwrap();
        let tenant = TenantId::new();
        let session = SessionId::new();
        let worker_id = WorkerId::new("retained-worker").unwrap();
        let original = OwnershipFence::new(worker_id.clone(), 1, 7, 11);
        let now = u64::try_from(Utc::now().timestamp_millis()).unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(now - 1500)));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut scanner_peer = use_unix.then(|| ScannerPeer::start(now - 1500, calls.clone()));
        let scanner_identity = scanner_peer
            .as_ref()
            .map(|peer| (peer.uid, peer.version_sha256));
        let scanner: Arc<dyn ArtifactScanner> = if let Some(peer) = &scanner_peer {
            Arc::new(
                UnixClamAvScanner::new(
                    peer.socket.clone(),
                    peer.uid,
                    1024,
                    Duration::from_secs(2),
                    ClamAvFreshnessPolicy::new_utc(
                        Duration::from_secs(48 * 3600),
                        Duration::from_secs(300),
                    )
                    .unwrap(),
                    clock.clone(),
                )
                .unwrap(),
            )
        } else {
            Arc::new(CleanScanner(calls.clone(), clock.clone()))
        };
        let store = ProductionArtifactStore::open_with_retention(
            store_config(root.path()),
            runtime.handle().clone(),
            Some(scanner.clone()),
            ArtifactRetentionConfig::default(),
            clock.clone(),
        )
        .unwrap();
        let mut artifacts = Vec::new();
        for (source, bytes, name) in [
            (
                ArtifactContentSource::ClientUpload,
                "첨부 파일 내용".as_bytes().to_vec(),
                Some("첨부 문서.txt".to_owned()),
            ),
            (
                ArtifactContentSource::Generated,
                b"generated fixture bytes".to_vec(),
                None,
            ),
            (
                ArtifactContentSource::BrowserDownload,
                b"download fixture bytes".to_vec(),
                None,
            ),
        ] {
            let id = ArtifactId::new();
            let request = match source {
                ArtifactContentSource::ClientUpload => ArtifactStoreRequest::new(
                    tenant.clone(),
                    session.clone(),
                    id,
                    original.clone(),
                    bytes.clone(),
                    "text/plain",
                    1024,
                ),
                ArtifactContentSource::Generated => ArtifactStoreRequest::new_generated(
                    tenant.clone(),
                    session.clone(),
                    id,
                    original.clone(),
                    bytes.clone(),
                    "text/plain",
                    1024,
                    "browserd-capture",
                ),
                ArtifactContentSource::BrowserDownload => {
                    ArtifactStoreRequest::new_browser_download(
                        tenant.clone(),
                        session.clone(),
                        id,
                        original.clone(),
                        bytes.clone(),
                        "text/plain",
                        1024,
                    )
                }
            }
            .unwrap();
            let receipt = store.store(&request).unwrap();
            let publication = ArtifactPublication::new_with_scan_attestation(
                request.key().clone(),
                original.clone(),
                ArtifactContentMetadata::new(
                    receipt.size_bytes(),
                    *receipt.checksum(),
                    receipt.detected_content_type(),
                    source,
                    request.origin(),
                )
                .unwrap(),
                receipt.object_generation(),
                receipt.scan_verdict(),
                name,
                now - 1500,
                now + 3_600_000,
                receipt.scan_attestation().cloned(),
            )
            .unwrap();
            store.publish_artifact(&publication).unwrap();
            artifacts.push((publication, bytes));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        if let Some(peer) = &mut scanner_peer {
            let scanned_bytes = peer.finish();
            let expected_bytes = artifacts
                .iter()
                .filter(|(publication, _)| publication.scan_attestation().is_some())
                .map(|(_, bytes)| bytes.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                scanned_bytes, expected_bytes,
                "exact upload/download bytes reached INSTREAM; generated content skips scanning"
            );
        }
        let orphan_request = ArtifactStoreRequest::new_generated(
            tenant.clone(),
            session.clone(),
            ArtifactId::new(),
            original.clone(),
            b"unpublished".to_vec(),
            "text/plain",
            1024,
            "browserd-capture",
        )
        .unwrap();
        store.store(&orphan_request).unwrap();
        let orphan = orphan_request.key().artifact_id().clone();
        let expired_request = ArtifactStoreRequest::new_generated(
            tenant.clone(),
            session.clone(),
            ArtifactId::new(),
            original.clone(),
            b"expired".to_vec(),
            "text/plain",
            1024,
            "browserd-capture",
        )
        .unwrap();
        let expired_receipt = store.store(&expired_request).unwrap();
        let expired_publication = ArtifactPublication::new(
            expired_request.key().clone(),
            original,
            ArtifactContentMetadata::new(
                expired_receipt.size_bytes(),
                *expired_receipt.checksum(),
                expired_receipt.detected_content_type(),
                ArtifactContentSource::Generated,
                expired_request.origin(),
            )
            .unwrap(),
            expired_receipt.object_generation(),
            None,
            None,
            now - 2000,
            now - 1000,
        )
        .unwrap();
        store.publish_artifact(&expired_publication).unwrap();
        let expired = expired_request.key().artifact_id().clone();
        // No adapter or stream remains alive across restart. Metadata must come from disk.
        drop(store);
        clock.0.store(now, Ordering::SeqCst);
        let store = ProductionArtifactStore::open_with_retention(
            store_config(root.path()),
            runtime.handle().clone(),
            None,
            ArtifactRetentionConfig::default(),
            clock.clone(),
        )
        .unwrap();
        let over_capacity = ArtifactStoreRequest::new_generated(
            tenant.clone(),
            session.clone(),
            ArtifactId::new(),
            artifacts[0].0.original_fence().clone(),
            vec![1],
            "text/plain",
            1024,
            "browserd-capture",
        )
        .unwrap();
        assert_eq!(
            store.store(&over_capacity),
            Err(DependencyError::Rejected),
            "unpublished and expired objects remain charged after restart"
        );
        let no_browser = Arc::new(NoBrowser::default());
        let sandbox = Arc::new(RetainedSandbox {
            store,
            forbidden: no_browser.clone(),
        });
        let peer = AuthenticatedPeer::new("retained-gateway").unwrap();
        let config = WorkerConfig::new(
            worker_id.clone(),
            5,
            InternalEndpoint::loopback("127.0.0.1:9022".parse().unwrap()).unwrap(),
            peer.clone(),
            2,
            2,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).unwrap(),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30)).unwrap(),
            Duration::from_secs(5),
            ActionJournalConfig::new(journal.path(), ActionJournalLimits::default()).unwrap(),
        )
        .unwrap();
        let worker = Arc::new(WorkerControlPlane::new_with_clock(
            config,
            no_browser.clone(),
            sandbox,
            clock.clone(),
        ));
        // In particular: no qualify, start, create_session, provision, or hydrate call.
        worker.begin_drain(&peer).unwrap();
        assert!(!worker.is_ready(), "retained reads must work while unready");
        let handler = Arc::new(WorkerControlPlaneRpcHandler::new(worker, peer));
        let client = Arc::new(HandlerClient {
            handler,
            runtime: runtime.clone(),
            fault: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
        });
        let gateway = Arc::new(
            GatewayWorkerRuntime::new(
                client.clone(),
                GatewayWorkerPlacement::new(worker_id.clone(), 5, 99, 99).unwrap(),
            )
            .unwrap(),
        );
        let router = ApiRouter::new(gateway.clone());
        let principal = principal(tenant.clone(), &["artifact:read"]);
        artifacts.sort_by(|a, b| a.0.key().artifact_id().cmp(b.0.key().artifact_id()));
        Self {
            scanner_identity,
            gateway,
            router,
            client,
            no_browser,
            clock,
            principal,
            scope: WorkerRetainedArtifactScope {
                worker_id,
                worker_epoch: 5,
                tenant_id: tenant,
                session_id: session,
            },
            artifacts,
            orphan,
            expired,
            _root: root,
            _journal: journal,
            runtime,
        }
    }
    fn receipt(&self, id: &ArtifactId) -> WorkerRetainedArtifactReceipt {
        let WorkerRpcResponse::RetainedArtifact(receipt) = self
            .client
            .request(WorkerRpcRequest::GetRetainedArtifact {
                scope: self.scope.clone(),
                artifact_id: id.clone(),
            })
            .unwrap()
        else {
            panic!("expected retained receipt");
        };
        receipt
    }
    fn download_token(&self, id: &ArtifactId) -> String {
        let ApiResponse::ArtifactDownload(token) = self
            .router
            .execute(
                &self.principal,
                ApiRequest::DownloadArtifact(ArtifactRequest {
                    session_id: self.scope.session_id.clone(),
                    artifact_id: id.clone(),
                }),
            )
            .unwrap()
        else {
            panic!("expected token");
        };
        self.gateway.present_token(token.data()).unwrap()
    }
    fn assert_browser_unused(&self) {
        assert_eq!(self.no_browser.0.load(Ordering::SeqCst), 0);
    }
}
fn store_config(root: &std::path::Path) -> ArtifactStoreConfig {
    ArtifactStoreConfig {
        root: root.to_owned(),
        max_file_bytes: 1024,
        max_worker_bytes: 8192,
        max_worker_in_flight_bytes: 2048,
        max_session_bytes: 8192,
        max_session_in_flight_bytes: 2048,
        max_retained_artifacts: 5,
        max_operations: 8,
        chunk_bytes: 4,
        operation_timeout: Duration::from_secs(2),
    }
}
fn principal(tenant: TenantId, scopes: &[&str]) -> AuthenticatedPrincipal {
    let key = [9; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("test", Algorithm::HS256, &key).unwrap();
    let claims = ServiceClaims::new(
        "issuer",
        "audience",
        PrincipalId::new(),
        tenant,
        scopes.iter().map(|s| (*s).to_owned()).collect(),
        "retained-test",
        1,
        100,
        None,
    );
    let token = ServiceTokenSigner::new("test", Algorithm::HS256, &key)
        .sign(&claims)
        .unwrap();
    ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    )
    .verify_at(&token, None, 10)
    .unwrap()
}

#[test]
fn restart_preserves_publication_names_and_all_sources_without_any_browser_session() {
    let f = Fixture::new();
    let mut after = None;
    let mut listed = Vec::new();
    loop {
        let ApiResponse::Artifacts(page) = f
            .router
            .execute(
                &f.principal,
                ApiRequest::ListArtifacts(ArtifactListRequest {
                    session_id: f.scope.session_id.clone(),
                    after,
                    limit: 1,
                }),
            )
            .unwrap()
        else {
            panic!("expected list");
        };
        listed.extend(
            page.data()
                .items
                .iter()
                .map(|metadata| metadata.key.artifact_id().clone()),
        );
        after = page.data().next_cursor.clone();
        if after.is_none() {
            break;
        }
    }
    assert_eq!(
        listed,
        f.artifacts
            .iter()
            .map(|(p, _)| p.key().artifact_id().clone())
            .collect::<Vec<_>>()
    );
    for (publication, expected_bytes) in &f.artifacts {
        let id = publication.key().artifact_id();
        let receipt = f.receipt(id);
        assert_eq!(receipt.serving_worker_epoch, 5);
        assert_eq!(receipt.serving_worker_id, f.scope.worker_id);
        assert_eq!(receipt.publication.to_publication().unwrap(), *publication);
        assert_eq!(receipt.publication.artifact.fence.worker_epoch, 1);
        let ApiResponse::Artifact(metadata) = f
            .router
            .execute(
                &f.principal,
                ApiRequest::GetArtifact(ArtifactRequest {
                    session_id: f.scope.session_id.clone(),
                    artifact_id: id.clone(),
                }),
            )
            .unwrap()
        else {
            panic!("expected artifact");
        };
        assert_eq!(
            metadata.data().display_filename.as_deref(),
            publication.display_filename()
        );
        let token = f.download_token(id);
        let bytes = f.runtime.block_on(async {
            let mut body = f
                .gateway
                .consume(&f.principal, &f.scope.session_id, id, &token)
                .await
                .unwrap();
            assert_eq!(body.size_bytes, expected_bytes.len() as u64);
            let mut bytes = Vec::new();
            while let Some(chunk) = body.stream.next_chunk().await.unwrap() {
                bytes.extend(chunk);
            }
            assert!(
                f.gateway
                    .consume(&f.principal, &f.scope.session_id, id, &token)
                    .await
                    .is_err()
            );
            bytes
        });
        assert_eq!(&bytes, expected_bytes);
    }
    for id in [&f.orphan, &f.expired] {
        assert!(
            f.router
                .execute(
                    &f.principal,
                    ApiRequest::GetArtifact(ArtifactRequest {
                        session_id: f.scope.session_id.clone(),
                        artifact_id: id.clone()
                    })
                )
                .is_err()
        );
    }
    f.assert_browser_unused();
}

#[test]
fn retained_scope_requires_current_service_identity_and_exact_tenant_session() {
    let f = Fixture::new();
    let id = f.artifacts[0].0.key().artifact_id().clone();
    for field in 0..4 {
        let mut scope = f.scope.clone();
        match field {
            0 => scope.worker_id = WorkerId::new("different-worker").unwrap(),
            1 => scope.worker_epoch = 1,
            2 => scope.tenant_id = TenantId::new(),
            _ => scope.session_id = SessionId::new(),
        }
        assert!(matches!(
            f.client
                .request(WorkerRpcRequest::GetRetainedArtifact {
                    scope,
                    artifact_id: id.clone()
                })
                .unwrap(),
            WorkerRpcResponse::Failure(_)
        ));
    }
    assert!(
        f.router
            .execute(
                &principal(TenantId::new(), &["artifact:read"]),
                ApiRequest::GetArtifact(ArtifactRequest {
                    session_id: f.scope.session_id.clone(),
                    artifact_id: id.clone()
                })
            )
            .is_err()
    );
    let requests = f.client.requests.load(Ordering::SeqCst);
    assert!(
        f.router
            .execute(
                &principal(f.scope.tenant_id.clone(), &[]),
                ApiRequest::GetArtifact(ArtifactRequest {
                    session_id: f.scope.session_id.clone(),
                    artifact_id: id
                })
            )
            .is_err()
    );
    assert_eq!(
        f.client.requests.load(Ordering::SeqCst),
        requests,
        "scope rejection precedes RPC"
    );
    f.assert_browser_unused();
}

#[test]
fn corrupted_retained_receipts_and_hidden_lookahead_never_authorize_public_metadata() {
    let f = Fixture::new();
    let id = f.artifacts[0].0.key().artifact_id().clone();
    for fault in 1..=7 {
        f.client.fault.store(fault, Ordering::SeqCst);
        assert!(
            f.router
                .execute(
                    &f.principal,
                    ApiRequest::GetArtifact(ArtifactRequest {
                        session_id: f.scope.session_id.clone(),
                        artifact_id: id.clone()
                    })
                )
                .is_err(),
            "fault {fault}"
        );
        assert!(
            f.router
                .execute(
                    &f.principal,
                    ApiRequest::ListArtifacts(ArtifactListRequest {
                        session_id: f.scope.session_id.clone(),
                        after: None,
                        limit: 1
                    })
                )
                .is_err(),
            "hidden lookahead fault {fault}"
        );
    }
    f.client.fault.store(0, Ordering::SeqCst);
    f.clock
        .0
        .store(f.artifacts[0].0.expires_at_unix_millis(), Ordering::SeqCst);
    assert!(matches!(
        f.client
            .request(WorkerRpcRequest::GetRetainedArtifact {
                scope: f.scope.clone(),
                artifact_id: id
            })
            .unwrap(),
        WorkerRpcResponse::Failure(_)
    ));
    f.assert_browser_unused();
}

#[test]
fn retained_stream_scope_and_sequence_are_checked_before_reading_or_closing() {
    let f = Fixture::new();
    let publication = &f.artifacts[0].0;
    let WorkerRpcResponse::RetainedArtifactOpened { receipt, stream_id } = f
        .client
        .request(WorkerRpcRequest::OpenRetainedArtifact {
            scope: f.scope.clone(),
            publication: ArtifactPublicationWire::from_publication(publication),
            max_chunk_bytes: 4,
        })
        .unwrap()
    else {
        panic!("expected opened stream");
    };
    assert_eq!(receipt.publication.to_publication().unwrap(), *publication);
    for field in 0..4 {
        let mut foreign = f.scope.clone();
        match field {
            0 => foreign.worker_epoch = 1,
            1 => foreign.worker_id = WorkerId::new("foreign").unwrap(),
            2 => foreign.tenant_id = TenantId::new(),
            _ => foreign.session_id = SessionId::new(),
        }
        assert!(matches!(
            f.client
                .request(WorkerRpcRequest::ReadRetainedArtifact {
                    scope: foreign.clone(),
                    stream_id: stream_id.clone(),
                    sequence: 0
                })
                .unwrap(),
            WorkerRpcResponse::Failure(_)
        ));
        assert!(matches!(
            f.client
                .request(WorkerRpcRequest::CloseRetainedArtifact {
                    scope: foreign,
                    stream_id: stream_id.clone()
                })
                .unwrap(),
            WorkerRpcResponse::Failure(_)
        ));
    }
    assert!(matches!(
        f.client
            .request(WorkerRpcRequest::ReadRetainedArtifact {
                scope: f.scope.clone(),
                stream_id: stream_id.clone(),
                sequence: 1
            })
            .unwrap(),
        WorkerRpcResponse::Failure(_)
    ));
    let WorkerRpcResponse::RetainedArtifactChunk {
        scope,
        sequence,
        bytes,
        end,
        ..
    } = f
        .client
        .request(WorkerRpcRequest::ReadRetainedArtifact {
            scope: f.scope.clone(),
            stream_id: stream_id.clone(),
            sequence: 0,
        })
        .unwrap()
    else {
        panic!("expected first chunk");
    };
    assert_eq!(scope, f.scope);
    assert_eq!(sequence, 0);
    assert!(!end);
    assert_eq!(bytes, f.artifacts[0].1[..4]);
    assert!(matches!(
        f.client
            .request(WorkerRpcRequest::ReadRetainedArtifact {
                scope: f.scope.clone(),
                stream_id: stream_id.clone(),
                sequence: 0
            })
            .unwrap(),
        WorkerRpcResponse::Failure(_)
    ));
    assert!(matches!(
        f.client
            .request(WorkerRpcRequest::CloseRetainedArtifact {
                scope: f.scope.clone(),
                stream_id
            })
            .unwrap(),
        WorkerRpcResponse::RetainedArtifactClosed { .. }
    ));
    f.assert_browser_unused();
}

#[test]
fn retained_download_tokens_bind_whole_receipt_and_stream_checksum() {
    let f = Fixture::new();
    let id = f.artifacts[0].0.key().artifact_id();
    let token = f.download_token(id);
    f.client.fault.store(8, Ordering::SeqCst);
    f.runtime.block_on(async {
        assert!(
            f.gateway
                .consume(&f.principal, &f.scope.session_id, id, &token)
                .await
                .is_err(),
            "changed display filename invalidates token receipt"
        );
    });
    f.client.fault.store(0, Ordering::SeqCst);
    let token = f.download_token(id);
    f.client.fault.store(9, Ordering::SeqCst);
    f.runtime.block_on(async {
        let mut body = f
            .gateway
            .consume(&f.principal, &f.scope.session_id, id, &token)
            .await
            .unwrap();
        loop {
            match body.stream.next_chunk().await {
                Ok(Some(_)) => {}
                Err(_) => break,
                Ok(None) => panic!("corrupted stream must fail full checksum"),
            }
        }
        assert!(
            f.gateway
                .consume(&f.principal, &f.scope.session_id, id, &token)
                .await
                .is_err()
        );
    });
    f.assert_browser_unused();
}
