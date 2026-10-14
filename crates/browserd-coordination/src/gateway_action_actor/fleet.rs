//! Bounded typed fleet commands use the existing action actor's owned task lifetime.
use super::{Command, GatewayActionBlockingClient, ResponsePolicy};
use crate::session_admission::*;
use crate::{
    ClaimGatewayAction, DirectoryKey, DispatchLeaseToken, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionSnapshot, GatewayActionSubmissionLease,
};
use browserd_actions::DispatchId;
use browserd_core::{ActionId, LeaseId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use std::sync::mpsc::SyncSender;
use std::time::Duration;

pub(super) enum FleetCommand {
    EnqueueSessionAdmission {
        request: Box<GatewaySessionAdmissionRequest>,
        response:
            SyncSender<Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError>>,
    },
    GetSessionAdmission {
        key: GatewaySessionAdmissionKey,
        response: SyncSender<
            Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError>,
        >,
    },
    ObserveFleetWorker {
        observation: Box<GatewayFleetWorkerObservation>,
        advisory_ttl: Duration,
        response: SyncSender<Result<(), GatewayActionCoordinationError>>,
    },
    ReserveNextSession {
        reservation_ttl: Duration,
        response: SyncSender<
            Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError>,
        >,
    },
    RecordSessionReservation {
        expected: Box<GatewaySessionAdmissionSnapshot>,
        proof: Box<GatewaySessionWorkerReservationProof>,
        response:
            SyncSender<Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError>>,
    },
    ArmSessionCreate {
        expected: Box<GatewaySessionAdmissionSnapshot>,
        dispatch_lease: DispatchLeaseToken,
        placement_ttl: Duration,
        response:
            SyncSender<Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError>>,
    },
    CommitSessionPlacement {
        expected: Box<GatewaySessionAdmissionSnapshot>,
        proof: Box<GatewaySessionWorkerReadyProof>,
        response:
            SyncSender<Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError>>,
    },
    ResolveSessionPlacement {
        key: DirectoryKey,
        response: SyncSender<
            Result<Option<GatewaySessionPlacementAuthority>, GatewayActionCoordinationError>,
        >,
    },
    ValidateSessionAuthority {
        authority: Box<GatewaySessionAuthorityRef>,
        response: SyncSender<Result<(), GatewayActionCoordinationError>>,
    },
    BeginSessionRenewal {
        expected: Box<GatewaySessionPlacementAuthority>,
        renewal_nonce: LeaseId,
        placement_ttl: Duration,
        response: SyncSender<Result<GatewaySessionRenewalIntent, GatewayActionCoordinationError>>,
    },
    FinishSessionRenewal {
        intent: Box<GatewaySessionRenewalIntent>,
        proof: Box<GatewaySessionWorkerRenewalProof>,
        response:
            SyncSender<Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError>>,
    },
    BeginSessionClose {
        expected: Box<GatewaySessionPlacementAuthority>,
        response:
            SyncSender<Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError>>,
    },
    ReleaseSessionReservation {
        expected: Box<GatewaySessionAdmissionSnapshot>,
        proof: Box<GatewaySessionCleanupProof>,
        response:
            SyncSender<Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError>>,
    },
    ScanSessionAdmissions {
        cursor: GatewaySessionAdmissionCursor,
        limit: usize,
        response: SyncSender<Result<GatewaySessionAdmissionPage, GatewayActionCoordinationError>>,
    },
    AckSessionCreateProjection {
        expected: Box<GatewaySessionAdmissionSnapshot>,
        response:
            SyncSender<Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError>>,
    },
    ClaimActionAuthorized {
        claim: Box<ClaimGatewayAction>,
        authority: Box<GatewaySessionAuthorityRef>,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionClaimOutcome, GatewayActionCoordinationError>>,
    },
    ArmDispatchOwnedAuthorized {
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        expected_revision: u64,
        placement: Box<GatewayActionPlacement>,
        dispatch_id: DispatchId,
        lease: Box<GatewayActionSubmissionLease>,
        authority: Box<GatewaySessionAuthorityRef>,
        now: DateTime<Utc>,
        response: SyncSender<Result<GatewayActionSnapshot, GatewayActionCoordinationError>>,
    },
}
impl FleetCommand {
    pub(super) async fn run<S: GatewayActionCoordination>(self, store: &S) {
        match self {
            Self::EnqueueSessionAdmission { request, response } => {
                let _ = response.send(store.enqueue_session_admission(*request).await);
            }
            Self::GetSessionAdmission { key, response } => {
                let _ = response.send(store.get_session_admission(&key).await);
            }
            Self::ObserveFleetWorker {
                observation,
                advisory_ttl,
                response,
            } => {
                let _ = response.send(store.observe_fleet_worker(*observation, advisory_ttl).await);
            }
            Self::ReserveNextSession {
                reservation_ttl,
                response,
            } => {
                let _ = response.send(store.reserve_next_session(reservation_ttl).await);
            }
            Self::RecordSessionReservation {
                expected,
                proof,
                response,
            } => {
                let _ = response.send(store.record_session_reservation(&expected, *proof).await);
            }
            Self::ArmSessionCreate {
                expected,
                dispatch_lease,
                placement_ttl,
                response,
            } => {
                let _ = response.send(
                    store
                        .arm_session_create(&expected, &dispatch_lease, placement_ttl)
                        .await,
                );
            }
            Self::CommitSessionPlacement {
                expected,
                proof,
                response,
            } => {
                let _ = response.send(store.commit_session_placement(&expected, *proof).await);
            }
            Self::ResolveSessionPlacement { key, response } => {
                let _ = response.send(store.resolve_session_placement(&key).await);
            }
            Self::ValidateSessionAuthority {
                authority,
                response,
            } => {
                let _ = response.send(store.validate_session_authority(&authority).await);
            }
            Self::BeginSessionRenewal {
                expected,
                renewal_nonce,
                placement_ttl,
                response,
            } => {
                let _ = response.send(
                    store
                        .begin_session_renewal(&expected, renewal_nonce, placement_ttl)
                        .await,
                );
            }
            Self::FinishSessionRenewal {
                intent,
                proof,
                response,
            } => {
                let _ = response.send(store.finish_session_renewal(&intent, *proof).await);
            }
            Self::BeginSessionClose { expected, response } => {
                let _ = response.send(store.begin_session_close(&expected).await);
            }
            Self::ReleaseSessionReservation {
                expected,
                proof,
                response,
            } => {
                let _ = response.send(store.release_session_reservation(&expected, *proof).await);
            }
            Self::ScanSessionAdmissions {
                cursor,
                limit,
                response,
            } => {
                let _ = response.send(store.scan_session_admissions(cursor, limit).await);
            }
            Self::AckSessionCreateProjection { expected, response } => {
                let _ = response.send(store.ack_session_create_projection(&expected).await);
            }
            Self::ClaimActionAuthorized {
                claim,
                authority,
                now,
                response,
            } => {
                let _ = response.send(store.claim_action_authorized(*claim, &authority, now).await);
            }
            Self::ArmDispatchOwnedAuthorized {
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                lease,
                authority,
                now,
                response,
            } => {
                let _ = response.send(
                    store
                        .arm_dispatch_owned_authorized(
                            &tenant_id,
                            &session_id,
                            &action_id,
                            expected_revision,
                            &placement,
                            dispatch_id,
                            &lease,
                            &authority,
                            now,
                        )
                        .await,
                );
            }
        }
    }
}
impl GatewayActionBlockingClient {
    pub fn enqueue_session_admission(
        &self,
        request: GatewaySessionAdmissionRequest,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::EnqueueSessionAdmission {
                    request: Box::new(request),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn get_session_admission(
        &self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::GetSessionAdmission {
                    key: key.clone(),
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
    pub fn observe_fleet_worker(
        &self,
        observation: GatewayFleetWorkerObservation,
        advisory_ttl: Duration,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ObserveFleetWorker {
                    observation: Box::new(observation),
                    advisory_ttl,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn reserve_next_session(
        &self,
        reservation_ttl: Duration,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ReserveNextSession {
                    reservation_ttl,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn record_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReservationProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::RecordSessionReservation {
                    expected: Box::new(expected.clone()),
                    proof: Box::new(proof),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn arm_session_create(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        dispatch_lease: &DispatchLeaseToken,
        placement_ttl: Duration,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ArmSessionCreate {
                    expected: Box::new(expected.clone()),
                    dispatch_lease: dispatch_lease.clone(),
                    placement_ttl,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn commit_session_placement(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReadyProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::CommitSessionPlacement {
                    expected: Box::new(expected.clone()),
                    proof: Box::new(proof),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn resolve_session_placement(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ResolveSessionPlacement {
                    key: key.clone(),
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
    pub fn validate_session_authority(
        &self,
        authority: &GatewaySessionAuthorityRef,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ValidateSessionAuthority {
                    authority: Box::new(authority.clone()),
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
    pub fn begin_session_renewal(
        &self,
        expected: &GatewaySessionPlacementAuthority,
        renewal_nonce: LeaseId,
        placement_ttl: Duration,
    ) -> Result<GatewaySessionRenewalIntent, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::BeginSessionRenewal {
                    expected: Box::new(expected.clone()),
                    renewal_nonce,
                    placement_ttl,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn finish_session_renewal(
        &self,
        intent: &GatewaySessionRenewalIntent,
        proof: GatewaySessionWorkerRenewalProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::FinishSessionRenewal {
                    intent: Box::new(intent.clone()),
                    proof: Box::new(proof),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn begin_session_close(
        &self,
        expected: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::BeginSessionClose {
                    expected: Box::new(expected.clone()),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn release_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionCleanupProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ReleaseSessionReservation {
                    expected: Box::new(expected.clone()),
                    proof: Box::new(proof),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn scan_session_admissions(
        &self,
        cursor: GatewaySessionAdmissionCursor,
        limit: usize,
    ) -> Result<GatewaySessionAdmissionPage, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ScanSessionAdmissions {
                    cursor,
                    limit,
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
    pub fn ack_session_create_projection(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::AckSessionCreateProjection {
                    expected: Box::new(expected.clone()),
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn claim_action_authorized(
        &self,
        claim: ClaimGatewayAction,
        authority: &GatewaySessionAuthorityRef,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ClaimActionAuthorized {
                    claim: Box::new(claim),
                    authority: Box::new(authority.clone()),
                    now,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn arm_dispatch_owned_authorized(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        lease: &GatewayActionSubmissionLease,
        authority: &GatewaySessionAuthorityRef,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::Fleet(Box::new(FleetCommand::ArmDispatchOwnedAuthorized {
                    tenant_id: tenant_id.clone(),
                    session_id: session_id.clone(),
                    action_id: action_id.clone(),
                    expected_revision,
                    placement: Box::new(placement.clone()),
                    dispatch_id,
                    lease: Box::new(lease.clone()),
                    authority: Box::new(authority.clone()),
                    now,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
}
