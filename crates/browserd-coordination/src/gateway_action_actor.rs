use std::sync::Arc;
use std::sync::mpsc::{self, SyncSender};

use browserd_actions::{
    ActionSequence, BrowserResult, DispatchId, ResolutionAnnotation, TerminalCustodyReceipt,
    TerminalCustodyRequirement, TerminalDetail, TransportLoss,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, Utc};

use crate::{
    ClaimGatewayAction, CoordinationActorConfig, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionRecoveryCursor, GatewayActionRecoveryPage, GatewayActionRetentionCursor,
    GatewayActionRetentionPage, GatewayActionSnapshot, GatewayActionSubmissionLease,
    GatewayCustodyCursor, GatewayCustodyPage, GatewayEventProjection, GatewayEventScanCursor,
    GatewayEventScanPage, GatewayPendingCustody, GatewayTerminalCustodyCatchupPage,
    SessionLossClaim, SessionLossOutcome, SessionLossReceipt,
};

mod fleet;
mod session_directory;

enum Command {
    Fleet(Box<fleet::FleetCommand>),
    SessionDirectory(Box<session_directory::DirectoryCommand>),
    ScanTerminalCustodyCatchup {
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
        response:
            SyncSender<Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError>>,
    },
    AttachTerminalCustody {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        receipt: TerminalCustodyReceipt,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    MaintainActionRetention {
        cursor: GatewayActionRetentionCursor,
        limit: usize,
        response: SyncSender<Result<GatewayActionRetentionPage, GatewayActionCoordinationError>>,
    },
    ScanPendingCustody {
        cursor: GatewayCustodyCursor,
        limit: usize,
        response: SyncSender<Result<GatewayCustodyPage, GatewayActionCoordinationError>>,
    },
    AckPendingCustody {
        entry: GatewayPendingCustody,
        now: DateTime<Utc>,
        response: SyncSender<Result<(), GatewayActionCoordinationError>>,
    },
    CompleteCustodyRelease {
        entry: GatewayPendingCustody,
        now: DateTime<Utc>,
        response: SyncSender<Result<(), GatewayActionCoordinationError>>,
    },
    ScanPendingActions {
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
        response: SyncSender<Result<GatewayActionRecoveryPage, GatewayActionCoordinationError>>,
    },
    ArmDispatchOwned {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        dispatch_id: DispatchId,
        lease: GatewayActionSubmissionLease,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    ExpireUnattemptedAction {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        lease: GatewayActionSubmissionLease,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    ScanEventSessions {
        cursor: GatewayEventScanCursor,
        limit: usize,
        response: SyncSender<Result<GatewayEventScanPage, GatewayActionCoordinationError>>,
    },
    PeekEventProjection {
        tenant_id: TenantId,
        session_id: SessionId,
        response:
            SyncSender<Result<Option<GatewayEventProjection>, GatewayActionCoordinationError>>,
    },
    AckEventProjection {
        projection: GatewayEventProjection,
        response: SyncSender<Result<(), GatewayActionCoordinationError>>,
    },
    Claim {
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionClaimOutcome, GatewayActionCoordinationError>>,
    },
    Get {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        response: SyncSender<Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError>>,
    },
    ArmDispatch {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    MarkExposurePossible {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    RecordWorkerResult {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        dispatch_id: DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    RecordWorkerTerminal {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        dispatch_id: DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    RecordTransportLoss {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        dispatch_id: DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    CancelBeforeDispatch {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    ResolveUnknown {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    MarkSessionLost {
        claim: SessionLossClaim,
        now: DateTime<Utc>,
        response: SyncSender<Result<SessionLossOutcome, GatewayActionCoordinationError>>,
    },
    EnsureSessionLost {
        proposed: SessionLossClaim,
        now: DateTime<Utc>,
        response: SyncSender<Result<SessionLossReceipt, GatewayActionCoordinationError>>,
    },
    MaterializeSessionLoss {
        claim: SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
        response: SyncSender<Result<usize, GatewayActionCoordinationError>>,
    },
}

#[derive(Clone)]
pub struct GatewayActionBlockingClient {
    sender: SyncSender<Command>,
    query_timeout: std::time::Duration,
    mutation_timeout: std::time::Duration,
}

impl GatewayActionBlockingClient {
    pub fn spawn<S>(
        store: Arc<S>,
        config: CoordinationActorConfig,
    ) -> Result<Self, GatewayActionCoordinationError>
    where
        S: GatewayActionCoordination + 'static,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.max_in_flight())
            .enable_all()
            .build()
            .map_err(|_| GatewayActionCoordinationError::ActorSpawn)?;
        let (sender, receiver) = mpsc::sync_channel(config.queue_capacity());
        let permits = Arc::new(tokio::sync::Semaphore::new(config.max_in_flight()));
        let permit_count = u32::try_from(config.max_in_flight()).unwrap_or_default();
        std::thread::Builder::new()
            .name("browserd-gateway-actions".to_owned())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    let Ok(permit) = runtime.block_on(Arc::clone(&permits).acquire_owned()) else {
                        break;
                    };
                    let store = Arc::clone(&store);
                    runtime.spawn(async move {
                        match command {
                            Command::Fleet(command) => command.run(store.as_ref()).await,
                            Command::SessionDirectory(command) => command.run(store.as_ref()).await,
                            Command::ScanTerminalCustodyCatchup {
                                cursor,
                                limit,
                                response,
                            } => {
                                let _ = response
                                    .send(store.scan_terminal_custody_catchup(cursor, limit).await);
                            }
                            Command::AttachTerminalCustody {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                receipt,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .attach_terminal_custody(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            receipt,
                                        )
                                        .await,
                                );
                            }
                            Command::MaintainActionRetention {
                                cursor,
                                limit,
                                response,
                            } => {
                                let _ = response
                                    .send(store.maintain_action_retention(cursor, limit).await);
                            }
                            Command::ScanPendingCustody {
                                cursor,
                                limit,
                                response,
                            } => {
                                let _ =
                                    response.send(store.scan_pending_custody(cursor, limit).await);
                            }
                            Command::AckPendingCustody {
                                entry,
                                now,
                                response,
                            } => {
                                let _ = response.send(store.ack_pending_custody(&entry, now).await);
                            }
                            Command::CompleteCustodyRelease {
                                entry,
                                now,
                                response,
                            } => {
                                let _ = response
                                    .send(store.complete_custody_release(&entry, now).await);
                            }
                            Command::ScanPendingActions {
                                cursor,
                                limit,
                                response,
                            } => {
                                let _ =
                                    response.send(store.scan_pending_actions(cursor, limit).await);
                            }
                            Command::ArmDispatchOwned {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                dispatch_id,
                                lease,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .arm_dispatch_owned(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            dispatch_id,
                                            &lease,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::ExpireUnattemptedAction {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                lease,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .expire_unattempted_action(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &lease,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::ScanEventSessions {
                                cursor,
                                limit,
                                response,
                            } => {
                                let _ =
                                    response.send(store.scan_event_sessions(cursor, limit).await);
                            }
                            Command::PeekEventProjection {
                                tenant_id,
                                session_id,
                                response,
                            } => {
                                let _ = response.send(
                                    store.peek_event_projection(&tenant_id, &session_id).await,
                                );
                            }
                            Command::AckEventProjection {
                                projection,
                                response,
                            } => {
                                let _ =
                                    response.send(store.ack_event_projection(&projection).await);
                            }
                            Command::Claim {
                                claim,
                                now,
                                response,
                            } => {
                                let _ = response.send(store.claim_action(claim, now).await);
                            }
                            Command::Get {
                                tenant_id,
                                session_id,
                                action_id,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .get_effective_action(&tenant_id, &session_id, &action_id)
                                        .await,
                                );
                            }
                            Command::ArmDispatch {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                dispatch_id,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .arm_dispatch(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            dispatch_id,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::MarkExposurePossible {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                dispatch_id,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .mark_exposure_possible(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &dispatch_id,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::RecordWorkerResult {
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
                                requirement,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .record_worker_result_with_custody(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &dispatch_id,
                                            action_sequence,
                                            result,
                                            result_body,
                                            custody,
                                            requirement,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::RecordWorkerTerminal {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                dispatch_id,
                                action_sequence,
                                detail,
                                custody,
                                requirement,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .record_worker_terminal_with_custody(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &dispatch_id,
                                            action_sequence,
                                            detail,
                                            custody,
                                            requirement,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::RecordTransportLoss {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                dispatch_id,
                                loss,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .record_transport_loss(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &dispatch_id,
                                            loss,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::CancelBeforeDispatch {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .cancel_before_dispatch(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::ResolveUnknown {
                                tenant_id,
                                session_id,
                                action_id,
                                expected_revision,
                                placement,
                                annotation,
                                custody,
                                requirement,
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .resolve_unknown_with_custody(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            annotation,
                                            custody,
                                            requirement,
                                            now,
                                        )
                                        .await,
                                );
                            }
                            Command::MarkSessionLost {
                                claim,
                                now,
                                response,
                            } => {
                                let _ = response.send(store.mark_session_lost(&claim, now).await);
                            }
                            Command::EnsureSessionLost {
                                proposed,
                                now,
                                response,
                            } => {
                                let _ =
                                    response.send(store.ensure_session_lost(&proposed, now).await);
                            }
                            Command::MaterializeSessionLoss {
                                claim,
                                limit,
                                now,
                                response,
                            } => {
                                let _ = response
                                    .send(store.materialize_session_loss(&claim, limit, now).await);
                            }
                        }
                        drop(permit);
                    });
                }
                if let Ok(in_flight) =
                    runtime.block_on(Arc::clone(&permits).acquire_many_owned(permit_count))
                {
                    drop(in_flight);
                }
            })
            .map_err(|_| GatewayActionCoordinationError::ActorSpawn)?;
        Ok(Self {
            sender,
            query_timeout: config.query_timeout(),
            mutation_timeout: config.mutation_timeout(),
        })
    }

    pub fn scan_terminal_custody_catchup(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ScanTerminalCustodyCatchup {
                cursor,
                limit,
                response,
            },
            ResponsePolicy::Query,
        )
    }
    pub fn attach_terminal_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        receipt: TerminalCustodyReceipt,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::AttachTerminalCustody {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                receipt,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn maintain_action_retention(
        &self,
        cursor: GatewayActionRetentionCursor,
        limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::MaintainActionRetention {
                cursor,
                limit,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn scan_pending_custody(
        &self,
        cursor: GatewayCustodyCursor,
        limit: usize,
    ) -> Result<GatewayCustodyPage, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ScanPendingCustody {
                cursor,
                limit,
                response,
            },
            ResponsePolicy::Query,
        )
    }
    pub fn ack_pending_custody(
        &self,
        entry: &GatewayPendingCustody,
        now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.submit(
            |response| Command::AckPendingCustody {
                entry: entry.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn complete_custody_release(
        &self,
        entry: &GatewayPendingCustody,
        now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.submit(
            |response| Command::CompleteCustodyRelease {
                entry: entry.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn scan_pending_actions(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ScanPendingActions {
                cursor,
                limit,
                response,
            },
            ResponsePolicy::Query,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn arm_dispatch_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ArmDispatchOwned {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                dispatch_id,
                lease: lease.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn expire_unattempted_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ExpireUnattemptedAction {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                lease: lease.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::Claim {
                claim,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::Get {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                response,
            },
            ResponsePolicy::Query,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ArmDispatch {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                dispatch_id,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::MarkExposurePossible {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                dispatch_id: dispatch_id.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_worker_result(
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
        self.record_worker_result_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            dispatch_id,
            action_sequence,
            result,
            result_body,
            None,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_worker_result_with_custody(
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
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::RecordWorkerResult {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                dispatch_id: dispatch_id.clone(),
                action_sequence,
                result,
                result_body,
                custody,
                requirement,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_worker_terminal(
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
        self.record_worker_terminal_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            dispatch_id,
            action_sequence,
            detail,
            None,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_worker_terminal_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::RecordWorkerTerminal {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                dispatch_id: dispatch_id.clone(),
                action_sequence,
                detail,
                custody,
                requirement,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_transport_loss(
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
        self.submit(
            |response| Command::RecordTransportLoss {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                dispatch_id: dispatch_id.clone(),
                loss,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::CancelBeforeDispatch {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.resolve_unknown_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            annotation,
            None,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_unknown_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ResolveUnknown {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                annotation,
                custody,
                requirement,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::MarkSessionLost {
                claim: claim.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn ensure_session_lost(
        &self,
        proposed: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::EnsureSessionLost {
                proposed: proposed.clone(),
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::MaterializeSessionLoss {
                claim: claim.clone(),
                limit,
                now,
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    pub fn scan_event_sessions(
        &self,
        cursor: GatewayEventScanCursor,
        limit: usize,
    ) -> Result<GatewayEventScanPage, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::ScanEventSessions {
                cursor,
                limit,
                response,
            },
            ResponsePolicy::Query,
        )
    }

    pub fn peek_event_projection(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<GatewayEventProjection>, GatewayActionCoordinationError> {
        self.submit(
            |response| Command::PeekEventProjection {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                response,
            },
            ResponsePolicy::Query,
        )
    }

    pub fn ack_event_projection(
        &self,
        projection: &GatewayEventProjection,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.submit(
            |response| Command::AckEventProjection {
                projection: projection.clone(),
                response,
            },
            ResponsePolicy::Mutation,
        )
    }

    fn submit<T>(
        &self,
        build: impl FnOnce(SyncSender<Result<T, GatewayActionCoordinationError>>) -> Command,
        response_policy: ResponsePolicy,
    ) -> Result<T, GatewayActionCoordinationError> {
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(build(response_sender))
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => GatewayActionCoordinationError::ActorQueueFull,
                mpsc::TrySendError::Disconnected(_) => {
                    GatewayActionCoordinationError::ActorDisconnected
                }
            })?;
        let timeout = match response_policy {
            ResponsePolicy::Query => self.query_timeout,
            ResponsePolicy::Mutation => self.mutation_timeout,
        };
        response_receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => match response_policy {
                    ResponsePolicy::Query => GatewayActionCoordinationError::ActorQueryTimedOut,
                    ResponsePolicy::Mutation => {
                        GatewayActionCoordinationError::ActorMutationTimedOut
                    }
                },
                mpsc::RecvTimeoutError::Disconnected => {
                    GatewayActionCoordinationError::ActorDisconnected
                }
            })?
    }
}

#[derive(Clone, Copy)]
enum ResponsePolicy {
    Query,
    Mutation,
}
