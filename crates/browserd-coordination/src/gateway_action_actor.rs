use std::sync::Arc;
use std::sync::mpsc::{self, SyncSender};

use browserd_actions::{
    ActionSequence, BrowserResult, DispatchId, ResolutionAnnotation, TerminalDetail, TransportLoss,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, Utc};

use crate::{
    ClaimGatewayAction, CoordinationActorConfig, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionSnapshot, SessionLossClaim, SessionLossOutcome,
};

enum Command {
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
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
    MarkSessionLost {
        claim: SessionLossClaim,
        now: DateTime<Utc>,
        response: SyncSender<Result<SessionLossOutcome, GatewayActionCoordinationError>>,
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
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .record_worker_result(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &dispatch_id,
                                            action_sequence,
                                            result,
                                            result_body,
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
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .record_worker_terminal(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            &dispatch_id,
                                            action_sequence,
                                            detail,
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
                                now,
                                response,
                            } => {
                                let _ = response.send(
                                    store
                                        .resolve_unknown(
                                            &tenant_id,
                                            &session_id,
                                            &action_id,
                                            expected_revision,
                                            &placement,
                                            annotation,
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
        self.submit(
            |response| Command::ResolveUnknown {
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: action_id.clone(),
                expected_revision,
                placement: placement.clone(),
                annotation,
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
