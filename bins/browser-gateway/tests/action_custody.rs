#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionDeliveryEvidence, ActionKind, ActionSequence, BrowserResult, CanonicalRequestHash,
    DispatchId, JournalSessionScope, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind,
    ResultDigest, TerminalCustodyReceipt, TerminalDetail, TransportLoss,
};
use browserd_api::{
    ActionResolveBody, ActionResolveRequest, ApiRequest, ApiResponse, ApiRouter, ApiService,
    ResolutionRequestKind, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionRecoveryCursor, GatewayActionRecoveryPage, GatewayActionSnapshot,
    GatewayCustodyCursor, GatewayCustodyPage, GatewayPendingCustody, MemoryGatewayActionStore,
    SessionLossClaim, SessionLossOutcome,
};
use browserd_core::{ActionId, PageId, PlacementFence, PrincipalId, SessionId, TenantId, WorkerId};
use browserd_worker::{
    WorkerActionReceipt, WorkerActionStatus, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcFailure, WorkerRpcFailureCode,
    WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence, WorkerSessionLifecycle,
    WorkerSessionOwnershipReceipt, WorkerSessionReceipt, WorkerTerminalCustodyAck,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const BODY: &[u8] = br#"{"custody":"retained"}"#;

#[derive(Clone, Copy, Debug)]
enum AckFault {
    None,
    LostResponseOnce,
    Worker,
    Epoch,
    Digest,
    NotFound,
    Phase,
}

struct NeverPending;
impl GatewayWorkerPending for NeverPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        panic!("custody never submits browser work")
    }
}

struct CustodyWorker {
    id: WorkerId,
    epoch: AtomicU64,
    fault: Mutex<AckFault>,
    release_fault: Mutex<AckFault>,
    receipts: Mutex<HashMap<ActionId, WorkerActionReceipt>>,
    calls: Mutex<Vec<&'static str>>,
    fsynced: Mutex<HashSet<[u8; 32]>>,
    acks: Mutex<Vec<TerminalCustodyReceipt>>,
    releases: Mutex<Vec<TerminalCustodyReceipt>>,
    released: Mutex<HashSet<[u8; 32]>>,
    before_action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    before_ack: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    create_session_id: Mutex<Option<SessionId>>,
    resolution_missing: AtomicBool,
}
impl GatewayWorkerClient for CustodyWorker {
    type PendingAction = NeverPending;
    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        let session = self
            .create_session_id
            .lock()
            .unwrap()
            .take()
            .expect("custody recovery never creates a browser session");
        self.calls.lock().unwrap().push("create");
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: session,
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: PageId::new(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
            restored_checkpoint: None,
        })
    }
    fn enqueue_action(
        &self,
        _: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        panic!("custody never replays a browser action")
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        match request {
            WorkerRpcRequest::InspectSession {
                expected_worker_id,
                fence,
            } => {
                self.calls.lock().unwrap().push("inspect");
                assert_eq!(expected_worker_id, self.id);
                Ok(WorkerRpcResponse::SessionOwnership(
                    WorkerSessionOwnershipReceipt {
                        worker_id: self.id.clone(),
                        session: WorkerSessionReceipt {
                            fence,
                            lifecycle: WorkerSessionLifecycle::Ready,
                            primary_page_id: PageId::new(),
                        },
                    },
                ))
            }
            WorkerRpcRequest::GetAction { action_id, .. } => {
                self.calls.lock().unwrap().push("action");
                let hook = self.before_action.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
                Ok(WorkerRpcResponse::Action(
                    self.receipts
                        .lock()
                        .unwrap()
                        .get(&action_id)
                        .unwrap()
                        .clone(),
                ))
            }
            WorkerRpcRequest::ResolveAction {
                fence,
                action_id,
                resolution,
                resolved_by,
                basis,
                now_unix_millis,
            } => {
                self.calls.lock().unwrap().push("resolve");
                if self.resolution_missing.load(Ordering::Acquire) {
                    return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::NotFound,
                        "action unavailable",
                    )));
                }
                let mut receipts = self.receipts.lock().unwrap();
                let receipt = receipts.get_mut(&action_id).unwrap();
                assert_eq!(receipt.fence, fence);
                let annotation =
                    ResolutionAnnotation::new(resolution, resolved_by, now_unix_millis, basis);
                let old = receipt.custody.as_deref().unwrap();
                let custody = TerminalCustodyReceipt::new(
                    old.scope().clone(),
                    old.action_id().clone(),
                    old.action_sequence(),
                    old.kind(),
                    old.request_hash(),
                    old.dispatch_id().cloned(),
                    old.terminal(),
                    Some(annotation.clone()),
                )
                .unwrap();
                receipt.resolution = Some(annotation);
                receipt.custody = Some(Box::new(custody));
                Ok(WorkerRpcResponse::Action(receipt.clone()))
            }
            WorkerRpcRequest::AckTerminalCustody {
                expected_serving_worker_id,
                expected_serving_worker_epoch,
                receipt,
            } => {
                self.calls.lock().unwrap().push("ack");
                assert_eq!(expected_serving_worker_id, self.id);
                assert_eq!(
                    expected_serving_worker_epoch,
                    self.epoch.load(Ordering::Acquire)
                );
                // A restarted serving process keeps the WAL's original epoch, not its own epoch.
                assert_eq!(receipt.fence().worker_epoch, 3);
                self.acks.lock().unwrap().push((*receipt).clone());
                let hook = self.before_ack.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
                let fault = *self.fault.lock().unwrap();
                if matches!(fault, AckFault::NotFound) {
                    return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::NotFound,
                        "custody unavailable",
                    )));
                }
                self.fsynced.lock().unwrap().insert(receipt.digest());
                if matches!(fault, AckFault::LostResponseOnce) {
                    *self.fault.lock().unwrap() = AckFault::None;
                    return Err(WorkerRpcError::Timeout);
                }
                if matches!(fault, AckFault::Phase) {
                    return Ok(WorkerRpcResponse::TerminalCustodyRelease(
                        WorkerTerminalCustodyAck {
                            worker_id: self.id.clone(),
                            worker_epoch: expected_serving_worker_epoch,
                            receipt_sha256: receipt.digest(),
                        },
                    ));
                }
                Ok(WorkerRpcResponse::TerminalCustodyAck(
                    WorkerTerminalCustodyAck {
                        worker_id: if matches!(fault, AckFault::Worker) {
                            WorkerId::new("other-worker").unwrap()
                        } else {
                            self.id.clone()
                        },
                        worker_epoch: expected_serving_worker_epoch
                            + u64::from(matches!(fault, AckFault::Epoch)),
                        receipt_sha256: if matches!(fault, AckFault::Digest) {
                            [0; 32]
                        } else {
                            receipt.digest()
                        },
                    },
                ))
            }
            WorkerRpcRequest::ReleaseTerminalCustody {
                expected_serving_worker_id,
                expected_serving_worker_epoch,
                receipt,
            } => {
                self.calls.lock().unwrap().push("release");
                assert_eq!(expected_serving_worker_id, self.id);
                assert_eq!(
                    expected_serving_worker_epoch,
                    self.epoch.load(Ordering::Acquire)
                );
                // A restarted serving process keeps the WAL's original epoch, not its own epoch.
                assert_eq!(receipt.fence().worker_epoch, 3);
                self.releases.lock().unwrap().push((*receipt).clone());
                let fault = *self.release_fault.lock().unwrap();
                if matches!(fault, AckFault::NotFound) {
                    return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::NotFound,
                        "custody unavailable",
                    )));
                }
                assert!(
                    self.fsynced.lock().unwrap().contains(&receipt.digest()),
                    "release must follow positive copy ACK"
                );
                self.released.lock().unwrap().insert(receipt.digest());
                if matches!(fault, AckFault::LostResponseOnce) {
                    *self.release_fault.lock().unwrap() = AckFault::None;
                    return Err(WorkerRpcError::Timeout);
                }
                if matches!(fault, AckFault::Phase) {
                    return Ok(WorkerRpcResponse::TerminalCustodyAck(
                        WorkerTerminalCustodyAck {
                            worker_id: self.id.clone(),
                            worker_epoch: expected_serving_worker_epoch,
                            receipt_sha256: receipt.digest(),
                        },
                    ));
                }
                Ok(WorkerRpcResponse::TerminalCustodyRelease(
                    WorkerTerminalCustodyAck {
                        worker_id: if matches!(fault, AckFault::Worker) {
                            WorkerId::new("other-worker").unwrap()
                        } else {
                            self.id.clone()
                        },
                        worker_epoch: expected_serving_worker_epoch
                            + u64::from(matches!(fault, AckFault::Epoch)),
                        receipt_sha256: if matches!(fault, AckFault::Digest) {
                            [0; 32]
                        } else {
                            receipt.digest()
                        },
                    },
                ))
            }
            _ => panic!("custody sent a browser mutation, resolution or readiness probe"),
        }
    }
}

struct Fixture {
    executor: tokio::runtime::Runtime,
    store: Arc<MemoryGatewayActionStore>,
    worker: Arc<CustodyWorker>,
    tenant: TenantId,
}
impl Fixture {
    fn new() -> Self {
        Self {
            executor: tokio::runtime::Runtime::new().unwrap(),
            store: Arc::new(MemoryGatewayActionStore::default()),
            tenant: TenantId::new(),
            worker: Arc::new(CustodyWorker {
                id: WorkerId::new("custody-worker").unwrap(),
                epoch: AtomicU64::new(3),
                fault: Mutex::new(AckFault::None),
                release_fault: Mutex::new(AckFault::None),
                receipts: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                fsynced: Mutex::new(HashSet::new()),
                acks: Mutex::new(Vec::new()),
                releases: Mutex::new(Vec::new()),
                released: Mutex::new(HashSet::new()),
                before_action: Mutex::new(None),
                before_ack: Mutex::new(None),
                create_session_id: Mutex::new(None),
                resolution_missing: AtomicBool::new(false),
            }),
        }
    }
    fn gateway(&self, epoch: u64) -> GatewayWorkerRuntime<CustodyWorker> {
        self.gateway_store(epoch, self.store.clone())
    }
    fn gateway_store<S: GatewayActionCoordination + 'static>(
        &self,
        epoch: u64,
        store: Arc<S>,
    ) -> GatewayWorkerRuntime<CustodyWorker> {
        self.worker.epoch.store(epoch, Ordering::Release);
        GatewayWorkerRuntime::with_action_coordination(
            self.worker.clone(),
            GatewayWorkerPlacement::new(self.worker.id.clone(), epoch, 4, 6).unwrap(),
            store,
            CoordinationActorConfig::default(),
        )
        .unwrap()
    }
    fn seed(&self, unknown: bool) -> GatewayActionSnapshot {
        self.seed_session(unknown, SessionId::new(), 5)
    }
    fn seed_session(
        &self,
        unknown: bool,
        session: SessionId,
        incarnation: u64,
    ) -> GatewayActionSnapshot {
        let tenant = self.tenant.clone();
        let id = ActionId::new();
        let placement = GatewayActionPlacement::new(
            DirectoryFence::new(self.worker.id.clone(), 3, 4, incarnation).unwrap(),
            6,
        )
        .unwrap();
        let durable = self.executor.block_on(async {
            let claimed = self
                .store
                .claim_action(
                    ClaimGatewayAction::new(
                        tenant.clone(),
                        session.clone(),
                        id.clone(),
                        id.to_string(),
                        CanonicalRequestHash::new([17; 32]),
                        ActionKind::Mutating,
                        placement.clone(),
                    )
                    .unwrap(),
                    Utc::now(),
                )
                .await
                .unwrap()
                .into_snapshot();
            self.store
                .arm_dispatch(
                    &tenant,
                    &session,
                    &id,
                    claimed.revision(),
                    &placement,
                    DispatchId::new(),
                    Utc::now(),
                )
                .await
                .unwrap()
        });
        let detail = if unknown {
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch)
        } else {
            TerminalDetail::Succeeded(ResultDigest::new(Sha256::digest(BODY).into()))
        };
        let custody = self.custody(&durable, detail, None);
        self.worker.receipts.lock().unwrap().insert(
            id.clone(),
            WorkerActionReceipt {
                fence: WorkerSessionFence {
                    tenant_id: tenant,
                    session_id: session,
                    worker_epoch: 3,
                    placement_version: 4,
                    session_incarnation: incarnation,
                },
                action_id: id,
                action_sequence: durable.action_sequence(),
                idempotency_key: durable.idempotency_key().to_owned(),
                canonical_request_hash: *durable.request_hash().as_bytes(),
                kind: durable.kind(),
                status: if unknown {
                    WorkerActionStatus::OutcomeUnknown
                } else {
                    WorkerActionStatus::Succeeded
                },
                dispatch_acknowledged: true,
                approval_decision: None,
                terminal_detail: Some(detail),
                result: if unknown { None } else { Some(BODY.to_vec()) },
                resolution: None,
                custody: Some(Box::new(custody)),
                custody_requirement: None,
            },
        );
        durable
    }
    fn custody(
        &self,
        action: &GatewayActionSnapshot,
        detail: TerminalDetail,
        resolution: Option<ResolutionAnnotation>,
    ) -> TerminalCustodyReceipt {
        TerminalCustodyReceipt::new(
            JournalSessionScope::new(
                action.tenant_id().clone(),
                action.session_id().clone(),
                self.worker.id.clone(),
                PlacementFence::new(
                    3,
                    4,
                    action.placement().directory_fence().session_incarnation(),
                ),
            )
            .unwrap(),
            action.action_id().clone(),
            action.action_sequence(),
            action.kind(),
            CanonicalRequestHash::new([77; 32]),
            Some(DispatchId::new()),
            detail,
            resolution,
        )
        .unwrap()
    }
    fn stored(&self, action: &GatewayActionSnapshot) -> GatewayActionSnapshot {
        self.executor
            .block_on(self.store.get_effective_action(
                action.tenant_id(),
                action.session_id(),
                action.action_id(),
            ))
            .unwrap()
            .unwrap()
    }
    fn pending(&self) -> GatewayCustodyPage {
        self.executor
            .block_on(
                self.store
                    .scan_pending_custody(GatewayCustodyCursor::default(), 256),
            )
            .unwrap()
    }
    fn recover(&self) {
        assert_eq!(self.gateway(3).reconcile_pending_actions(7).unwrap(), 1);
    }
}

#[test]
fn terminal_commit_preserves_source_event_and_internal_identity_before_any_ack() {
    let fixture = Fixture::new();
    let action = fixture.seed(false);
    fixture.recover();
    let stored = fixture.stored(&action);
    assert_eq!(stored.result_content(), Some(BODY));
    let pending = fixture.pending();
    assert_eq!(pending.entries().len(), 1);
    assert_ne!(
        pending.entries()[0].receipt().request_hash(),
        action.request_hash()
    );
    let ActionDeliveryEvidence::DispatchArmed(dispatch) = action.delivery() else {
        panic!("armed")
    };
    assert_ne!(pending.entries()[0].receipt().dispatch_id(), Some(dispatch));
    assert!(fixture.worker.acks.lock().unwrap().is_empty());
    let event = fixture
        .executor
        .block_on(
            fixture
                .store
                .peek_event_projection(action.tenant_id(), action.session_id()),
        )
        .unwrap()
        .expect("source event committed");
    // No external outbox is configured: source-event delivery stays pending while custody proceeds.
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries()[0].is_release());
    assert!(fixture.worker.releases.lock().unwrap().is_empty());
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries().is_empty());
    let after = fixture
        .executor
        .block_on(
            fixture
                .store
                .peek_event_projection(action.tenant_id(), action.session_id()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(after, event);
    assert_eq!(
        *fixture.worker.calls.lock().unwrap(),
        ["inspect", "action", "ack", "release"]
    );
}

#[test]
fn lost_worker_ack_response_retries_exact_custody_after_gateway_restart() {
    let fixture = Fixture::new();
    fixture.seed(false);
    fixture.recover();
    let receipt = fixture.pending().entries()[0].receipt().clone();
    *fixture.worker.fault.lock().unwrap() = AckFault::LostResponseOnce;
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        0
    );
    assert_eq!(fixture.pending().entries().len(), 1);
    assert!(
        fixture
            .worker
            .fsynced
            .lock()
            .unwrap()
            .contains(&receipt.digest())
    );
    assert_eq!(
        fixture.gateway(6).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert_eq!(
        *fixture.worker.acks.lock().unwrap(),
        [receipt.clone(), receipt.clone()]
    );
    assert!(fixture.pending().entries()[0].is_release());
    assert_eq!(
        fixture.gateway(7).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert_eq!(*fixture.worker.releases.lock().unwrap(), [receipt]);
    assert!(fixture.pending().entries().is_empty());
    assert_eq!(
        *fixture.worker.calls.lock().unwrap(),
        ["inspect", "action", "ack", "ack", "release"]
    );
}

#[test]
fn mismatched_ack_identity_digest_and_missing_custody_preserve_obligation() {
    for fault in [
        AckFault::Worker,
        AckFault::Epoch,
        AckFault::Digest,
        AckFault::NotFound,
        AckFault::Phase,
    ] {
        let fixture = Fixture::new();
        fixture.seed(false);
        fixture.recover();
        *fixture.worker.fault.lock().unwrap() = fault;
        assert_eq!(
            fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
            0,
            "{fault:?}"
        );
        assert_eq!(fixture.pending().entries().len(), 1, "{fault:?}");
        *fixture.worker.fault.lock().unwrap() = AckFault::None;
        assert_eq!(
            fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
            1
        );
    }
}

#[test]
fn unrelated_serving_worker_never_receives_historical_custody() {
    let fixture = Fixture::new();
    fixture.seed(false);
    fixture.recover();
    let runtime = GatewayWorkerRuntime::with_action_coordination(
        fixture.worker.clone(),
        GatewayWorkerPlacement::new(WorkerId::new("foreign-worker").unwrap(), 5, 4, 6).unwrap(),
        fixture.store.clone(),
        CoordinationActorConfig::default(),
    )
    .unwrap();
    assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 0);
    assert_eq!(fixture.pending().entries().len(), 1);
    assert!(fixture.worker.acks.lock().unwrap().is_empty());
}

#[test]
fn custody_scan_has_a_hard_sixteen_rpc_bound_and_progresses_without_browser_replay() {
    let fixture = Fixture::new();
    for _ in 0..17 {
        fixture.seed(false);
        fixture.recover();
    }
    let runtime = fixture.gateway(5);
    assert!(runtime.reconcile_terminal_custody(0).is_err());
    assert!(runtime.reconcile_terminal_custody(257).is_err());
    assert_eq!(runtime.reconcile_terminal_custody(256).unwrap(), 16);
    assert_eq!(fixture.worker.acks.lock().unwrap().len(), 16);
    assert_eq!(fixture.pending().entries().len(), 17);
    assert_eq!(runtime.reconcile_terminal_custody(256).unwrap(), 1);
    assert_eq!(runtime.reconcile_terminal_custody(256).unwrap(), 16);
    assert_eq!(fixture.worker.releases.lock().unwrap().len(), 16);
    assert_eq!(runtime.reconcile_terminal_custody(256).unwrap(), 1);
    assert!(fixture.pending().entries().is_empty());
}

#[test]
fn malformed_outer_receipt_or_exact_custody_binding_never_transfers_retention() {
    for mismatch in 0..12 {
        let fixture = Fixture::new();
        let action = fixture.seed(false);
        let mut receipts = fixture.worker.receipts.lock().unwrap();
        let receipt = receipts.get_mut(action.action_id()).unwrap();
        if mismatch == 0 {
            receipt.canonical_request_hash[0] ^= 1;
        } else if mismatch == 1 {
            receipt.result = Some(b"changed".to_vec());
        } else {
            let old = receipt.custody.as_deref().unwrap();
            let scope = JournalSessionScope::new(
                if mismatch == 2 {
                    TenantId::new()
                } else {
                    old.tenant_id().clone()
                },
                if mismatch == 3 {
                    SessionId::new()
                } else {
                    old.session_id().clone()
                },
                if mismatch == 4 {
                    WorkerId::new("foreign").unwrap()
                } else {
                    old.original_worker_id().clone()
                },
                PlacementFence::new(
                    3 + u64::from(mismatch == 5),
                    4 + u64::from(mismatch == 6),
                    5 + u64::from(mismatch == 7),
                ),
            )
            .unwrap();
            let custody = TerminalCustodyReceipt::new(
                scope,
                if mismatch == 8 {
                    ActionId::new()
                } else {
                    old.action_id().clone()
                },
                if mismatch == 9 {
                    ActionSequence::new(99)
                } else {
                    old.action_sequence()
                },
                if mismatch == 10 {
                    ActionKind::ReadOnly
                } else {
                    old.kind()
                },
                old.request_hash(),
                old.dispatch_id().cloned(),
                if mismatch == 11 {
                    TerminalDetail::Succeeded(ResultDigest::new([45; 32]))
                } else {
                    old.terminal()
                },
                None,
            )
            .unwrap();
            receipt.custody = Some(Box::new(custody));
        }
        drop(receipts);
        assert_eq!(
            fixture.gateway(3).reconcile_pending_actions(7).unwrap(),
            0,
            "mismatch {mismatch}"
        );
        assert!(fixture.stored(&action).terminal().is_none());
        assert!(fixture.pending().entries().is_empty());
        assert_eq!(
            fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
            0
        );
        assert!(fixture.worker.acks.lock().unwrap().is_empty());
    }
}

#[test]
fn newer_resolution_custody_survives_inflight_old_ack() {
    let fixture = Fixture::new();
    let action = fixture.seed(true);
    fixture.recover();
    let old = fixture.pending().entries()[0].receipt().clone();
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        1_000,
        "verified no external effect".to_owned(),
    );
    let resolved = TerminalCustodyReceipt::new(
        old.scope().clone(),
        old.action_id().clone(),
        old.action_sequence(),
        old.kind(),
        old.request_hash(),
        old.dispatch_id().cloned(),
        old.terminal(),
        Some(annotation.clone()),
    )
    .unwrap();
    let store = fixture.store.clone();
    let current = fixture.stored(&action);
    let next = resolved.clone();
    *fixture.worker.before_ack.lock().unwrap() = Some(Box::new(move || {
        let executor = tokio::runtime::Runtime::new().unwrap();
        executor
            .block_on(store.resolve_unknown_with_custody(
                current.tenant_id(),
                current.session_id(),
                current.action_id(),
                current.revision(),
                current.placement(),
                annotation,
                Some(next),
                None,
                Utc::now(),
            ))
            .unwrap();
    }));
    let runtime = fixture.gateway(5);
    assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 0);
    assert_eq!(fixture.pending().entries()[0].receipt(), &resolved);
    assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(
        *fixture.worker.acks.lock().unwrap(),
        [old, resolved.clone()]
    );
    assert!(fixture.pending().entries()[0].is_release());
    assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(*fixture.worker.releases.lock().unwrap(), [resolved]);
    assert!(fixture.pending().entries().is_empty());
    assert_eq!(
        fixture.stored(&action).resolution().unwrap().kind(),
        ResolutionKind::ConfirmedNotExecuted
    );
}

struct LostCommitStore {
    inner: Arc<MemoryGatewayActionStore>,
    lose_response: AtomicBool,
    commits: AtomicUsize,
    ack_fault: AtomicUsize,
    catchup_fault: AtomicUsize,
    catchup_scans: Mutex<Vec<GatewayActionRecoveryCursor>>,
}
#[allow(clippy::too_many_arguments)]
#[async_trait]
impl GatewayActionCoordination for LostCommitStore {
    async fn scan_terminal_custody_catchup(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<
        browserd_coordination::GatewayTerminalCustodyCatchupPage,
        GatewayActionCoordinationError,
    > {
        self.catchup_scans.lock().unwrap().push(cursor.clone());
        self.inner
            .scan_terminal_custody_catchup(cursor, limit)
            .await
    }
    async fn attach_terminal_custody(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        action: &ActionId,
        revision: u64,
        placement: &GatewayActionPlacement,
        receipt: TerminalCustodyReceipt,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let fault = self.catchup_fault.swap(0, Ordering::AcqRel);
        if fault == 1 {
            return Err(GatewayActionCoordinationError::RedisUnavailable);
        }
        let saved = self
            .inner
            .attach_terminal_custody(tenant, session, action, revision, placement, receipt)
            .await?;
        if fault == 2 {
            return Err(GatewayActionCoordinationError::RedisUnavailable);
        }
        Ok(saved)
    }
    async fn scan_pending_actions(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        self.inner.scan_pending_actions(cursor, limit).await
    }

    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.inner.claim_action(claim, now).await
    }

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        self.inner
            .get_effective_action(tenant_id, session_id, action_id)
            .await
    }

    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .arm_dispatch(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                now,
            )
            .await
    }

    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_result(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                result,
                result_body,
                now,
            )
            .await
    }

    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_terminal(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                detail,
                now,
            )
            .await
    }

    async fn record_worker_terminal_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        custody: Option<browserd_actions::TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_terminal_with_custody(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                detail,
                custody,
                custody_requirement,
                now,
            )
            .await
    }

    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_transport_loss(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                loss,
                now,
            )
            .await
    }

    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .cancel_before_dispatch(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                now,
            )
            .await
    }

    async fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .resolve_unknown(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                annotation,
                now,
            )
            .await
    }

    async fn resolve_unknown_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        custody: Option<browserd_actions::TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .resolve_unknown_with_custody(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                annotation,
                custody,
                custody_requirement,
                now,
            )
            .await
    }

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        self.inner.mark_session_lost(claim, now).await
    }

    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        self.inner.materialize_session_loss(claim, limit, now).await
    }

    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .mark_exposure_possible(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                now,
            )
            .await
    }
    async fn record_worker_result_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        custody: Option<TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let saved = self
            .inner
            .record_worker_result_with_custody(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                result,
                result_body,
                custody,
                custody_requirement,
                now,
            )
            .await?;
        self.commits.fetch_add(1, Ordering::AcqRel);
        if self.lose_response.swap(false, Ordering::AcqRel) {
            return Err(GatewayActionCoordinationError::RedisUnavailable);
        }
        Ok(saved)
    }
    async fn scan_pending_custody(
        &self,
        cursor: GatewayCustodyCursor,
        limit: usize,
    ) -> Result<GatewayCustodyPage, GatewayActionCoordinationError> {
        self.inner.scan_pending_custody(cursor, limit).await
    }
    async fn ack_pending_custody(
        &self,
        entry: &GatewayPendingCustody,
        now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        let fault = self.ack_fault.swap(0, Ordering::AcqRel);
        if fault == 1 {
            return Err(GatewayActionCoordinationError::RedisUnavailable);
        }
        self.inner.ack_pending_custody(entry, now).await?;
        if fault == 2 {
            return Err(GatewayActionCoordinationError::RedisUnavailable);
        }
        Ok(())
    }
    async fn complete_custody_release(
        &self,
        entry: &GatewayPendingCustody,
        now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.inner.complete_custody_release(entry, now).await
    }
}

#[test]
fn lost_atomic_commit_response_keeps_result_event_and_retryable_custody_together() {
    let fixture = Fixture::new();
    let action = fixture.seed(false);
    let store = Arc::new(LostCommitStore {
        inner: fixture.store.clone(),
        lose_response: AtomicBool::new(true),
        commits: AtomicUsize::new(0),
        ack_fault: AtomicUsize::new(0),
        catchup_fault: AtomicUsize::new(0),
        catchup_scans: Mutex::new(Vec::new()),
    });
    let gateway = fixture.gateway_store(3, store.clone());
    assert!(gateway.reconcile_pending_actions(7).is_err());
    assert_eq!(store.commits.load(Ordering::Acquire), 1);
    assert_eq!(fixture.stored(&action).result_content(), Some(BODY));
    assert!(fixture.stored(&action).terminal_outbox_append().is_some());
    assert_eq!(fixture.pending().entries().len(), 1);
    assert!(fixture.worker.acks.lock().unwrap().is_empty());
    drop(gateway);
    assert_eq!(
        fixture
            .gateway_store(5, store)
            .reconcile_terminal_custody(16)
            .unwrap(),
        1
    );
    assert!(fixture.pending().entries()[0].is_release());
    assert!(fixture.worker.releases.lock().unwrap().is_empty());
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries().is_empty());
    assert_eq!(
        *fixture.worker.calls.lock().unwrap(),
        ["inspect", "action", "ack", "release"]
    );
}

#[test]
fn already_resolved_worker_receipt_atomically_recovers_terminal_resolution_and_custody() {
    let fixture = Fixture::new();
    let action = fixture.seed(true);
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        1_000,
        "operator verified external result",
    );
    let resolved = {
        let mut receipts = fixture.worker.receipts.lock().unwrap();
        let receipt = receipts.get_mut(action.action_id()).unwrap();
        let old = receipt.custody.as_deref().unwrap();
        let resolved = TerminalCustodyReceipt::new(
            old.scope().clone(),
            old.action_id().clone(),
            old.action_sequence(),
            old.kind(),
            old.request_hash(),
            old.dispatch_id().cloned(),
            old.terminal(),
            Some(annotation.clone()),
        )
        .unwrap();
        receipt.resolution = Some(annotation.clone());
        receipt.custody = Some(Box::new(resolved.clone()));
        resolved
    };
    fixture.recover();
    let saved = fixture.stored(&action);
    assert_eq!(saved.resolution(), Some(&annotation));
    assert_eq!(saved.terminal().unwrap().detail(), resolved.terminal());
    assert_eq!(fixture.pending().entries()[0].receipt(), &resolved);
    let first = fixture
        .executor
        .block_on(
            fixture
                .store
                .peek_event_projection(action.tenant_id(), action.session_id()),
        )
        .unwrap()
        .unwrap();
    fixture
        .executor
        .block_on(fixture.store.ack_event_projection(&first))
        .unwrap();
    let second = fixture
        .executor
        .block_on(
            fixture
                .store
                .peek_event_projection(action.tenant_id(), action.session_id()),
        )
        .unwrap()
        .expect("resolution source event committed together");
    assert_ne!(first, second);
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries()[0].is_release());
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries().is_empty());
    assert_eq!(
        *fixture.worker.calls.lock().unwrap(),
        ["inspect", "action", "ack", "release"]
    );
}

fn principal(tenant: TenantId) -> AuthenticatedPrincipal {
    let secret = [41; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("custody", Algorithm::HS256, &secret)
        .unwrap();
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let token = ServiceTokenSigner::new("custody", Algorithm::HS256, &secret)
        .sign(&ServiceClaims::new(
            "issuer",
            "audience",
            PrincipalId::new(),
            tenant,
            BTreeSet::from([
                "session:create".to_owned(),
                "session:read".to_owned(),
                "browser:act".to_owned(),
            ]),
            "custody",
            1,
            100,
            None,
        ))
        .unwrap();
    verifier.verify_at(&token, None, 10).unwrap()
}

#[test]
fn operator_resolution_transfers_new_worker_custody_but_not_found_never_fabricates_it() {
    for missing in [false, true] {
        let fixture = Fixture::new();
        let session = SessionId::new();
        *fixture.worker.create_session_id.lock().unwrap() = Some(session.clone());
        let runtime = Arc::new(fixture.gateway(3));
        let router = ApiRouter::new(runtime.clone());
        let principal = principal(fixture.tenant.clone());
        router.execute(&principal,ApiRequest::CreateSession { body:decode_session_create(r#"{"isolation":"shared_context","workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},"locale":"ko-KR","timezone":"Asia/Seoul","user_agent":null,"network_policy_id":"public-web-default","network_class":"public","checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":1800,"idle_timeout_seconds":600,"metadata":{}}"#).unwrap(),idempotency_key:Uuid::new_v4().to_string(),received_at:Instant::now() }).unwrap();
        let action = fixture.seed_session(true, session.clone(), 1);
        assert_eq!(runtime.reconcile_pending_actions(7).unwrap(), 1);
        assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 1);
        assert!(fixture.pending().entries()[0].is_release());
        assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 1);
        fixture
            .worker
            .resolution_missing
            .store(missing, Ordering::Release);
        let request = || {
            ApiRequest::ResolveAction(ActionResolveRequest {
                session_id: session.clone(),
                action_id: action.action_id().clone(),
                body: ActionResolveBody {
                    resolution: ResolutionRequestKind::ConfirmedNotExecuted,
                    basis: "verified external state".to_owned(),
                    note: None,
                },
            })
        };
        let ApiResponse::Action(response) = router.execute(&principal, request()).unwrap() else {
            panic!("action")
        };
        assert_eq!(
            response.data().resolution().unwrap().kind(),
            ResolutionKind::ConfirmedNotExecuted
        );
        assert_eq!(fixture.pending().entries().len(), usize::from(!missing));
        assert_eq!(
            runtime.reconcile_terminal_custody(16).unwrap(),
            usize::from(!missing)
        );
        assert_eq!(
            runtime.reconcile_terminal_custody(16).unwrap(),
            usize::from(!missing)
        );
        assert!(fixture.pending().entries().is_empty());
        // An idempotent caller retry never invokes ResolveAction or invents another custody ACK.
        router.execute(&principal, request()).unwrap();
        let calls = fixture.worker.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|call| **call == "resolve").count(), 1);
        assert_eq!(
            calls.iter().filter(|call| **call == "ack").count(),
            1 + usize::from(!missing)
        );
        assert_eq!(
            calls.iter().filter(|call| **call == "release").count(),
            1 + usize::from(!missing)
        );
    }
}

#[test]
fn concurrent_custody_pass_does_not_duplicate_an_inflight_worker_ack() {
    let fixture = Fixture::new();
    fixture.seed(false);
    fixture.recover();
    let (entered_send, entered) = std::sync::mpsc::channel();
    let (release_send, release) = std::sync::mpsc::channel();
    *fixture.worker.before_ack.lock().unwrap() = Some(Box::new(move || {
        entered_send.send(()).unwrap();
        release
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
    }));
    let runtime = Arc::new(fixture.gateway(5));
    let runner = runtime.clone();
    let pass = std::thread::spawn(move || runner.reconcile_terminal_custody(16));
    entered
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("ACK entered");
    let concurrent = runtime.reconcile_terminal_custody(16);
    release_send.send(()).unwrap();
    assert_eq!(concurrent.unwrap(), 0);
    assert_eq!(pass.join().unwrap().unwrap(), 1);
    assert_eq!(fixture.worker.acks.lock().unwrap().len(), 1);
    assert!(fixture.pending().entries()[0].is_release());
    assert_eq!(runtime.reconcile_terminal_custody(16).unwrap(), 1);
    assert!(fixture.pending().entries().is_empty());
}

#[test]
fn lost_release_response_keeps_release_obligation_until_authenticated_idempotent_retry() {
    let fixture = Fixture::new();
    fixture.seed(false);
    fixture.recover();
    let receipt = fixture.pending().entries()[0].receipt().clone();
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries()[0].is_release());
    *fixture.worker.release_fault.lock().unwrap() = AckFault::LostResponseOnce;
    assert_eq!(
        fixture.gateway(6).reconcile_terminal_custody(16).unwrap(),
        0
    );
    assert!(
        fixture
            .worker
            .released
            .lock()
            .unwrap()
            .contains(&receipt.digest())
    );
    assert!(fixture.pending().entries()[0].is_release());
    assert_eq!(
        fixture.gateway(7).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries().is_empty());
    assert_eq!(
        *fixture.worker.releases.lock().unwrap(),
        [receipt.clone(), receipt]
    );
    assert_eq!(
        *fixture.worker.calls.lock().unwrap(),
        ["inspect", "action", "ack", "release", "release"]
    );
}

#[test]
fn release_response_identity_and_phase_are_checked_before_coordinator_forgets_obligation() {
    for fault in [
        AckFault::Worker,
        AckFault::Epoch,
        AckFault::Digest,
        AckFault::NotFound,
        AckFault::Phase,
    ] {
        let fixture = Fixture::new();
        fixture.seed(false);
        fixture.recover();
        assert_eq!(
            fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
            1
        );
        *fixture.worker.release_fault.lock().unwrap() = fault;
        assert_eq!(
            fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
            0
        );
        assert!(fixture.pending().entries()[0].is_release());
        *fixture.worker.release_fault.lock().unwrap() = AckFault::None;
        assert_eq!(
            fixture.gateway(6).reconcile_terminal_custody(16).unwrap(),
            1
        );
        assert!(fixture.pending().entries().is_empty());
        assert_eq!(fixture.worker.acks.lock().unwrap().len(), 1);
    }
}

#[test]
fn concurrent_same_unknown_terminal_does_not_strand_worker_resolution_or_custody() {
    let fixture = Fixture::new();
    let action = fixture.seed(true);
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        1_000,
        "verified external effect",
    );
    let resolved = {
        let mut receipts = fixture.worker.receipts.lock().unwrap();
        let receipt = receipts.get_mut(action.action_id()).unwrap();
        let old = receipt.custody.as_deref().unwrap();
        let resolved = TerminalCustodyReceipt::new(
            old.scope().clone(),
            old.action_id().clone(),
            old.action_sequence(),
            old.kind(),
            old.request_hash(),
            old.dispatch_id().cloned(),
            old.terminal(),
            Some(annotation.clone()),
        )
        .unwrap();
        receipt.resolution = Some(annotation.clone());
        receipt.custody = Some(Box::new(resolved.clone()));
        resolved
    };
    let store = fixture.store.clone();
    let racing = action.clone();
    let detail = resolved.terminal();
    *fixture.worker.before_action.lock().unwrap() = Some(Box::new(move || {
        let ActionDeliveryEvidence::DispatchArmed(dispatch) = racing.delivery() else {
            panic!("armed")
        };
        let executor = tokio::runtime::Runtime::new().unwrap();
        executor
            .block_on(store.record_worker_terminal(
                racing.tenant_id(),
                racing.session_id(),
                racing.action_id(),
                racing.revision(),
                racing.placement(),
                dispatch,
                racing.action_sequence(),
                detail,
                Utc::now(),
            ))
            .unwrap();
    }));
    fixture.recover();
    assert_eq!(fixture.stored(&action).resolution(), Some(&annotation));
    assert_eq!(fixture.pending().entries()[0].receipt(), &resolved);
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert_eq!(
        fixture.gateway(5).reconcile_terminal_custody(16).unwrap(),
        1
    );
    assert!(fixture.pending().entries().is_empty());
    assert_eq!(
        *fixture.worker.calls.lock().unwrap(),
        ["inspect", "action", "ack", "release"]
    );
}

#[test]
fn copy_ack_coordination_failure_never_releases_without_durable_release_phase() {
    for fault in [1, 2] {
        let fixture = Fixture::new();
        fixture.seed(false);
        fixture.recover();
        let store = Arc::new(LostCommitStore {
            inner: fixture.store.clone(),
            lose_response: AtomicBool::new(false),
            commits: AtomicUsize::new(0),
            ack_fault: AtomicUsize::new(fault),
            catchup_fault: AtomicUsize::new(0),
            catchup_scans: Mutex::new(Vec::new()),
        });
        let runtime = fixture.gateway_store(5, store.clone());
        assert!(runtime.reconcile_terminal_custody(16).is_err());
        assert!(fixture.worker.releases.lock().unwrap().is_empty());
        assert_eq!(fixture.pending().entries()[0].is_release(), fault == 2);
        drop(runtime);
        let restarted = fixture.gateway_store(6, store);
        assert_eq!(restarted.reconcile_terminal_custody(16).unwrap(), 1);
        if fault == 1 {
            assert!(fixture.worker.releases.lock().unwrap().is_empty());
            assert!(fixture.pending().entries()[0].is_release());
            assert_eq!(restarted.reconcile_terminal_custody(16).unwrap(), 1);
        }
        assert!(fixture.pending().entries().is_empty());
        assert_eq!(fixture.worker.releases.lock().unwrap().len(), 1);
        assert_eq!(
            fixture.worker.acks.lock().unwrap().len(),
            if fault == 1 { 2 } else { 1 }
        );
    }
}

#[path = "support/terminal_custody_catchup.rs"]
mod terminal_custody_catchup;
