use super::*;
use browserd_coordination::{
    DirectoryEntry, GatewayFleetExclusiveTenant, GatewayFleetWorkerObservation,
    GatewaySessionAdmissionKey, GatewaySessionAdmissionRequest, GatewaySessionAdmissionSnapshot,
    GatewaySessionAdmissionState, GatewaySessionCleanupProof, GatewaySessionIsolation,
    GatewaySessionReservation, GatewaySessionWorkerReadyProof, GatewaySessionWorkerRenewalProof,
    GatewaySessionWorkerReservationProof, GatewaySessionWorkload, WorkerCapacity, WorkerReadiness,
};
use browserd_core::LeaseId;
use browserd_worker::{
    FleetResourceVector, WorkerCapacityReceipt, WorkerReservationPhase, WorkerReservationReceipt,
    WorkerReservationRequest, WorkerReservationToken,
};

const RESERVATION_TTL: Duration = Duration::from_secs(30);
const PLACEMENT_TTL: Duration = Duration::from_secs(30);
const OBSERVATION_TTL: Duration = Duration::from_secs(6);

fn resources(value: WorkerCapacity) -> FleetResourceVector {
    let [
        memory_bytes,
        cpu_millis,
        pids,
        disk_bytes,
        contexts,
        targets,
    ] = value.components();
    FleetResourceVector {
        memory_bytes,
        cpu_millis,
        pids,
        disk_bytes,
        contexts,
        targets,
    }
}
fn capacity(value: FleetResourceVector) -> WorkerCapacity {
    WorkerCapacity::new(
        value.memory_bytes,
        value.cpu_millis,
        value.pids,
        value.disk_bytes,
        value.contexts,
        value.targets,
    )
}
fn isolation(value: WorkerIsolationProfile) -> GatewaySessionIsolation {
    match value {
        WorkerIsolationProfile::SharedContext => GatewaySessionIsolation::SharedContext,
        WorkerIsolationProfile::TenantDedicatedShard => {
            GatewaySessionIsolation::TenantDedicatedShard
        }
        WorkerIsolationProfile::DedicatedProcess => GatewaySessionIsolation::DedicatedProcess,
        WorkerIsolationProfile::DedicatedWorker => GatewaySessionIsolation::DedicatedWorker,
    }
}
fn public_isolation(value: GatewaySessionIsolation) -> IsolationProfile {
    match value {
        GatewaySessionIsolation::SharedContext => IsolationProfile::SharedContext,
        GatewaySessionIsolation::TenantDedicatedShard => IsolationProfile::TenantDedicatedShard,
        GatewaySessionIsolation::DedicatedProcess => IsolationProfile::DedicatedProcess,
        GatewaySessionIsolation::DedicatedWorker => IsolationProfile::DedicatedWorker,
    }
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    pub(super) fn capacity_status(
        &self,
        peer: &GatewayFleetPeer<C>,
    ) -> Result<WorkerCapacityReceipt, ApiError> {
        let response = peer
            .client
            .request(WorkerRpcRequest::CapacityStatus {
                expected_worker_epoch: 0,
            })
            .map_err(worker_api_error)?;
        let WorkerRpcResponse::Capacity(receipt) = response else {
            return Err(unavailable());
        };
        self.validate_capacity(peer, &receipt)?;
        Ok(receipt)
    }

    fn validate_capacity(
        &self,
        peer: &GatewayFleetPeer<C>,
        receipt: &WorkerCapacityReceipt,
    ) -> Result<(), ApiError> {
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let configured = fleet
            .inventory
            .config
            .workers()
            .iter()
            .find(|worker| worker.worker_id() == &peer.worker_id)
            .ok_or_else(unavailable)?;
        let exclusive = receipt
            .exclusive_assignment
            .as_ref()
            .map(|assignment| {
                GatewayFleetExclusiveTenant::new(
                    assignment.tenant_id().clone(),
                    *assignment.assignment_digest(),
                )
            })
            .transpose()
            .map_err(action_coordination_api_error)?;
        if receipt.worker_id != peer.worker_id
            || receipt.worker_epoch < peer.expected_worker_epoch
            || receipt.capacity_revision == 0
            || !configured
                .compatibility_digests()
                .contains(&receipt.compatibility_digest)
            || !capacity(receipt.capacity).fits_within(configured.capacity_ceiling())
            || !capacity(receipt.raw_free).fits_within(capacity(receipt.capacity))
            || exclusive.as_ref() != configured.exclusive_tenant()
            || receipt
                .exclusive_assignment
                .as_ref()
                .is_some_and(|a| a.worker_id() != &peer.worker_id)
        {
            return Err(mismatched());
        }
        Ok(())
    }

    fn observe_capacity(
        &self,
        peer: &GatewayFleetPeer<C>,
        receipt: &WorkerCapacityReceipt,
    ) -> Result<(), ApiError> {
        self.validate_capacity(peer, receipt)?;
        let observation = GatewayFleetWorkerObservation::new(
            GatewayFleetWorkerIdentity::new(
                receipt.worker_id.clone(),
                receipt.worker_epoch,
                receipt.worker_boot_nonce.clone(),
            )
            .map_err(action_coordination_api_error)?,
            receipt.capacity_revision,
            receipt.acknowledged_debit_sequence,
            capacity(receipt.capacity),
            capacity(receipt.raw_free),
            if receipt.draining {
                WorkerReadiness::Draining
            } else if receipt.ready {
                WorkerReadiness::Ready
            } else {
                WorkerReadiness::Unready
            },
            receipt.compatibility_digest,
            receipt
                .exclusive_assignment
                .as_ref()
                .map(|a| {
                    GatewayFleetExclusiveTenant::new(a.tenant_id().clone(), *a.assignment_digest())
                })
                .transpose()
                .map_err(action_coordination_api_error)?,
        )
        .map_err(action_coordination_api_error)?;
        self.actions
            .observe_fleet_worker(observation, OBSERVATION_TTL)
            .map_err(action_coordination_api_error)
    }

    fn reservation_request(
        &self,
        reservation: &GatewaySessionReservation,
    ) -> Result<WorkerReservationRequest, ApiError> {
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let operation = fleet
            .creates
            .get(
                reservation.key().tenant_id(),
                reservation.key().operation_id(),
            )
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if operation.request_hash().as_bytes() != reservation.canonical_request_hash() {
            return Err(mismatched());
        }
        let body: SessionCreateRequest =
            serde_json::from_value(operation.intent().canonical_request().clone())
                .map_err(|_| unavailable())?;
        let request = worker_create_request(
            reservation.key().operation_id().clone(),
            reservation.key().tenant_id().clone(),
            hex::encode(operation.intent().downstream_dedupe_key().as_bytes()),
            reservation.canonical_request_hash(),
            reservation.worker().worker_epoch(),
            reservation.directory_fence().placement_version(),
            u64::try_from(operation.intent().accepted_at().timestamp_millis())
                .map_err(|_| unavailable())?,
            &body,
        );
        // Original isolation remains part of the canonical create hash. The immutable
        // reserved profile and resources independently select the actual worker placement.
        if !fleet.inventory.config.profiles().iter().any(|profile| {
            profile.profile_digest() == reservation.profile_digest()
                && profile.compatibility_digest() == reservation.compatibility_digest()
                && profile.resources() == reservation.resources()
        }) {
            return Err(mismatched());
        }
        Ok(WorkerReservationRequest {
            request,
            reservation_id: reservation.reservation_id().clone(),
            expected_worker_boot_nonce: reservation.worker().boot_id().clone(),
            compatibility_digest: reservation.compatibility_digest(),
            profile_digest: reservation.profile_digest(),
            resources: resources(reservation.resources()),
            ttl_millis: reservation.requested_ttl_millis(),
        })
    }

    fn reservation_token(
        &self,
        reservation: &GatewaySessionReservation,
    ) -> Result<WorkerReservationToken, ApiError> {
        Ok(WorkerReservationToken {
            request: self.reservation_request(reservation)?,
            worker_id: reservation.worker().worker_id().clone(),
            worker_reservation_nonce: reservation
                .worker_reservation_nonce()
                .ok_or_else(unavailable)?
                .clone(),
            debit_sequence: reservation
                .worker_debit_sequence()
                .ok_or_else(unavailable)?,
        })
    }

    fn validate_reservation(
        &self,
        expected: &GatewaySessionReservation,
        receipt: &WorkerReservationReceipt,
    ) -> Result<(), ApiError> {
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let peer = fleet
            .inventory
            .peers
            .get(expected.worker().worker_id())
            .ok_or_else(unavailable)?;
        self.validate_capacity(peer, &receipt.capacity)?;
        if receipt.token.request != self.reservation_request(expected)?
            || receipt.token.worker_id != *expected.worker().worker_id()
            || receipt.capacity.worker_epoch != expected.worker().worker_epoch()
            || receipt.capacity.worker_boot_nonce != *expected.worker().boot_id()
            || receipt.token.debit_sequence == 0
            || expected
                .worker_reservation_nonce()
                .is_some_and(|nonce| nonce != &receipt.token.worker_reservation_nonce)
            || expected
                .worker_debit_sequence()
                .is_some_and(|sequence| sequence != receipt.token.debit_sequence)
            || receipt.capacity.acknowledged_debit_sequence < receipt.token.debit_sequence
        {
            return Err(mismatched());
        }
        Ok(())
    }

    pub(crate) fn create_fleet_session(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        body: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        let result = self.drive_fleet_create(authority, dispatch, body);
        match result {
            Ok(Some(session)) => RuntimeCreateResult::Succeeded(session),
            Ok(None) => RuntimeCreateResult::Deferred,
            Err(error)
                if matches!(
                    error.code(),
                    ErrorCode::InvalidRequest | ErrorCode::NetworkPolicyDenied
                ) =>
            {
                RuntimeCreateResult::ConfirmedFailure(error)
            }
            Err(error) => RuntimeCreateResult::OutcomeUnknown(error),
        }
    }

    fn drive_fleet_create(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        body: &SessionCreateRequest,
    ) -> Result<Option<SessionResource>, ApiError> {
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let token = dispatch.dispatch_token().ok_or_else(unavailable)?;
        let key = GatewaySessionAdmissionKey::new(
            authority.tenant_id().clone(),
            dispatch.operation_id().clone(),
        );
        let mut admission = if let Some(existing) = self
            .actions
            .get_session_admission(&key)
            .map_err(action_coordination_api_error)?
        {
            if existing.request().principal_id() != authority.principal_id()
                || existing.request().canonical_request_hash() != *dispatch.canonical_request_hash()
            {
                return Err(mismatched());
            }
            existing
        } else {
            let requested = match self.safety_create_isolation(body)? {
                IsolationRequest::SharedContext => GatewaySessionIsolation::SharedContext,
                IsolationRequest::TenantDedicatedShard => {
                    GatewaySessionIsolation::TenantDedicatedShard
                }
                IsolationRequest::DedicatedProcess => GatewaySessionIsolation::DedicatedProcess,
                IsolationRequest::DedicatedWorker => GatewaySessionIsolation::DedicatedWorker,
            };
            let workload = match body.workload_class_hint.as_str() {
                "light" => GatewaySessionWorkload::Light,
                "interactive" => GatewaySessionWorkload::Interactive,
                "heavy" => GatewaySessionWorkload::Heavy,
                _ => return Err(ApiError::invalid_request("unsupported fleet workload")),
            };
            let mut profiles = fleet.inventory.config.profiles().iter().filter(|profile| {
                profile.isolation() == requested && profile.workload() == workload
            });
            let profile = profiles
                .next()
                .ok_or_else(|| ApiError::invalid_request("fleet profile is not configured"))?;
            if profiles.next().is_some() {
                return Err(ApiError::invalid_request("fleet profile is ambiguous"));
            }
            let request = GatewaySessionAdmissionRequest::new(
                key,
                authority.principal_id().clone(),
                *dispatch.canonical_request_hash(),
                profile.profile_digest(),
                profile.compatibility_digest(),
                requested,
                profile.resources(),
                dispatch.accepted_at(),
                dispatch.admission_deadline(),
            )
            .map_err(action_coordination_api_error)?;
            self.actions
                .enqueue_session_admission(request)
                .map_err(action_coordination_api_error)?
        };
        if admission.state() == GatewaySessionAdmissionState::Queued {
            let ready_workers = self.observe_fleet_workers(32)?;
            if ready_workers == 0 {
                return Ok(None);
            }
            // Advance bounded virtual DRR rounds without repeating worker observations. The
            // maximum profile cost is 64 and minimum tenant weight is 1. Stop on the first
            // reservation, even if another tenant's FIFO head wins this scheduling turn.
            for _ in 0..64 {
                if self
                    .actions
                    .reserve_next_session(RESERVATION_TTL)
                    .map_err(action_coordination_api_error)?
                    .is_some()
                {
                    break;
                }
            }
            admission = self
                .actions
                .get_session_admission(admission.request().key())
                .map_err(action_coordination_api_error)?
                .ok_or_else(unavailable)?;
        }
        if admission.state() == GatewaySessionAdmissionState::Queued {
            return Ok(None);
        }
        if matches!(
            admission.state(),
            GatewaySessionAdmissionState::Expired | GatewaySessionAdmissionState::Released
        ) {
            return Err(ApiError::invalid_request(
                "fleet admission expired before exposure",
            ));
        }
        if admission.state() == GatewaySessionAdmissionState::Active {
            return self.publish_fleet_session(&admission, body).map(Some);
        }
        if !matches!(
            admission.state(),
            GatewaySessionAdmissionState::Reserved | GatewaySessionAdmissionState::CommitArmed
        ) {
            return Err(unavailable());
        }
        if admission.state() == GatewaySessionAdmissionState::Reserved {
            let reservation = admission.reservation().ok_or_else(unavailable)?;
            let peer = fleet
                .inventory
                .peers
                .get(reservation.worker().worker_id())
                .ok_or_else(unavailable)?;
            let response = peer
                .client
                .request(WorkerRpcRequest::ReserveSession(
                    self.reservation_request(reservation)?,
                ))
                .map_err(worker_api_error)?;
            let WorkerRpcResponse::SessionReservation(receipt) = response else {
                return Err(unavailable());
            };
            self.validate_reservation(reservation, &receipt)?;
            self.observe_capacity(peer, &receipt.capacity)?;
            if self.release_terminal_reservation(&admission, &receipt)? {
                return Ok(None);
            }
            if receipt.phase != WorkerReservationPhase::Reserved {
                return Err(unavailable());
            }
            let proof = GatewaySessionWorkerReservationProof {
                reservation: reservation.clone(),
                worker_reservation_nonce: receipt.token.worker_reservation_nonce,
                remaining_ttl_millis: receipt.remaining_ttl_millis,
                capacity_revision: receipt.capacity.capacity_revision,
                debit_sequence: receipt.token.debit_sequence,
            };
            admission = self
                .actions
                .record_session_reservation(&admission, proof)
                .map_err(action_coordination_api_error)?;
            admission = self
                .actions
                .arm_session_create(&admission, token, PLACEMENT_TTL)
                .map_err(action_coordination_api_error)?;
        }
        let reservation = admission.reservation().ok_or_else(unavailable)?;
        let peer = fleet
            .inventory
            .peers
            .get(reservation.worker().worker_id())
            .ok_or_else(unavailable)?;
        let worker_token = self.reservation_token(reservation)?;
        // Commit is idempotent on this exact token. It never selects a second worker after arm;
        // the worker records ExposurePossible before browser creation and refuses re-execution.
        let receipt = match peer
            .client
            .request(WorkerRpcRequest::InspectSessionReservation(
                worker_token.clone(),
            )) {
            Ok(WorkerRpcResponse::SessionReservation(receipt)) => {
                self.validate_reservation(reservation, &receipt)?;
                if receipt.phase == WorkerReservationPhase::Reserved {
                    match peer
                        .client
                        .request(WorkerRpcRequest::CommitReservedSession(worker_token))
                    {
                        Ok(WorkerRpcResponse::SessionReservation(receipt)) => receipt,
                        _ => return Err(unavailable()),
                    }
                } else {
                    receipt
                }
            }
            _ => return Err(unavailable()),
        };
        if self.release_terminal_reservation(&admission, &receipt)? {
            return Ok(None);
        }
        self.commit_fleet_ready(&admission, &receipt)?;
        let current = self
            .actions
            .get_session_admission(admission.request().key())
            .map_err(action_coordination_api_error)?
            .ok_or_else(unavailable)?;
        self.publish_fleet_session(&current, body).map(Some)
    }

    fn commit_fleet_ready(
        &self,
        admission: &GatewaySessionAdmissionSnapshot,
        receipt: &WorkerReservationReceipt,
    ) -> Result<(), ApiError> {
        let reservation = admission.reservation().ok_or_else(unavailable)?;
        self.validate_reservation(reservation, receipt)?;
        if receipt.phase != WorkerReservationPhase::Active {
            return Err(unavailable());
        }
        let created = receipt.session.as_ref().ok_or_else(unavailable)?;
        let worker_request = &receipt.token.request.request;
        let fence = reservation.directory_fence();
        if created.operation_id != *admission.request().key().operation_id()
            || created.tenant_id != *admission.request().key().tenant_id()
            || created.worker_epoch != fence.worker_epoch()
            || created.placement_version != fence.placement_version()
            || created.session_incarnation != fence.session_incarnation()
            || !worker_request
                .requested_isolation
                .satisfied_by(created.effective_isolation)
            || match (
                &worker_request.options.checkpoint_ref,
                &created.restored_checkpoint,
            ) {
                (None, None) => false,
                (Some(expected), Some(actual)) => {
                    expected != &actual.checkpoint_ref
                        || actual.source_session_id == created.session_id
                }
                _ => true,
            }
        {
            return Err(mismatched());
        }
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let peer = fleet
            .inventory
            .peers
            .get(fence.worker_id())
            .ok_or_else(unavailable)?;
        self.observe_capacity(peer, &receipt.capacity)?;
        let proof = GatewaySessionWorkerReadyProof {
            reservation: reservation.clone(),
            entry: DirectoryEntry::new(
                DirectoryKey::new(created.tenant_id.clone(), created.session_id.clone()),
                fence.clone(),
                peer.endpoint.clone(),
            )
            .map_err(|_| mismatched())?,
            primary_page_id: created.primary_page_id.clone(),
            effective_isolation: isolation(created.effective_isolation),
            remaining_ownership_ttl_millis: receipt
                .session_lease_remaining_millis
                .ok_or_else(unavailable)?,
            capacity_revision: receipt.capacity.capacity_revision,
            debit_sequence: receipt.token.debit_sequence,
            restored_checkpoint: created
                .restored_checkpoint
                .as_ref()
                .map(|restored| {
                    browserd_coordination::GatewaySessionRestoredCheckpoint::new(
                        restored.checkpoint_ref.clone(),
                        restored.source_session_id.clone(),
                    )
                })
                .transpose()
                .map_err(action_coordination_api_error)?,
        };
        match self.actions.commit_session_placement(admission, proof) {
            Ok(_) => {}
            Err(GatewayActionCoordinationError::SessionActivationExpired) => {
                // This exact provider decision is irreversible: its original activation deadline
                // has elapsed. Close only the positively created session on its original worker.
                let current = self
                    .actions
                    .get_session_admission(admission.request().key())
                    .map_err(action_coordination_api_error)?
                    .ok_or_else(unavailable)?;
                if current.state() != GatewaySessionAdmissionState::CommitArmed
                    || current.reservation() != Some(reservation)
                {
                    return Err(unavailable());
                }
                let fence = WorkerSessionFence {
                    tenant_id: created.tenant_id.clone(),
                    session_id: created.session_id.clone(),
                    worker_epoch: created.worker_epoch,
                    placement_version: created.placement_version,
                    session_incarnation: created.session_incarnation,
                };
                let closed = peer
                    .client
                    .request(WorkerRpcRequest::CloseSession {
                        fence: fence.clone(),
                        now_unix_millis: current_unix_millis()?,
                    })
                    .map_err(worker_api_error)?;
                if !matches!(closed, WorkerRpcResponse::SessionClosed(ref c) if c.fence == fence && matches!(c.lifecycle, WorkerSessionLifecycle::Closed | WorkerSessionLifecycle::Failed))
                {
                    return Err(unavailable());
                }
                let inspected = peer
                    .client
                    .request(WorkerRpcRequest::InspectSessionReservation(
                        receipt.token.clone(),
                    ))
                    .map_err(worker_api_error)?;
                let WorkerRpcResponse::SessionReservation(cleaned) = inspected else {
                    return Err(unavailable());
                };
                if !self.release_terminal_reservation(&current, &cleaned)? {
                    return Err(unavailable());
                }
                return Err(ApiError::invalid_request(
                    "fleet activation expired and exact session was disposed",
                ));
            }
            Err(error) => return Err(action_coordination_api_error(error)),
        }
        Ok(())
    }

    fn release_terminal_reservation(
        &self,
        admission: &GatewaySessionAdmissionSnapshot,
        receipt: &WorkerReservationReceipt,
    ) -> Result<bool, ApiError> {
        if !matches!(
            receipt.phase,
            WorkerReservationPhase::Cancelled
                | WorkerReservationPhase::Expired
                | WorkerReservationPhase::Released
        ) {
            return Ok(false);
        }
        let reservation = admission.reservation().ok_or_else(unavailable)?;
        self.validate_reservation(reservation, receipt)?;
        let proof = if matches!(
            receipt.phase,
            WorkerReservationPhase::Cancelled | WorkerReservationPhase::Expired
        ) {
            if receipt.session.is_some() || receipt.disposed_session.is_some() {
                return Err(mismatched());
            }
            GatewaySessionCleanupProof::NoEffectCancelled {
                reservation: reservation.clone(),
                capacity_revision: receipt.capacity.capacity_revision,
            }
        } else {
            let fence = match (&receipt.session, &receipt.disposed_session) {
                (Some(c), None) => WorkerSessionFence {
                    tenant_id: c.tenant_id.clone(),
                    session_id: c.session_id.clone(),
                    worker_epoch: c.worker_epoch,
                    placement_version: c.placement_version,
                    session_incarnation: c.session_incarnation,
                },
                (None, Some(fence)) => fence.clone(),
                _ => return Err(mismatched()),
            };
            let expected = reservation.directory_fence();
            if fence.tenant_id != *admission.request().key().tenant_id()
                || fence.worker_epoch != expected.worker_epoch()
                || fence.placement_version != expected.placement_version()
                || fence.session_incarnation != expected.session_incarnation()
            {
                return Err(mismatched());
            }
            let peer = self
                .fleet
                .as_ref()
                .ok_or_else(unavailable)?
                .inventory
                .peers
                .get(expected.worker_id())
                .ok_or_else(unavailable)?;
            GatewaySessionCleanupProof::ContextDisposed {
                reservation: reservation.clone(),
                entry: DirectoryEntry::new(
                    DirectoryKey::new(fence.tenant_id, fence.session_id),
                    expected.clone(),
                    peer.endpoint.clone(),
                )
                .map_err(|_| mismatched())?,
                capacity_revision: receipt.capacity.capacity_revision,
            }
        };
        self.actions
            .release_session_reservation(admission, proof)
            .map_err(action_coordination_api_error)?;
        if let Some(peer) = self
            .fleet
            .as_ref()
            .and_then(|f| f.inventory.peers.get(reservation.worker().worker_id()))
        {
            // The worker may retire only after the canonical provider cleanup has committed.
            let _ = peer.client.request(WorkerRpcRequest::AckSessionReservation(
                receipt.token.clone(),
            ));
        }
        Ok(true)
    }

    fn publish_fleet_session(
        &self,
        admission: &GatewaySessionAdmissionSnapshot,
        body: &SessionCreateRequest,
    ) -> Result<SessionResource, ApiError> {
        let placement = admission.placement().ok_or_else(unavailable)?;
        let proof = admission.ready_proof().ok_or_else(unavailable)?;
        let mut metadata = body.metadata.clone();
        metadata.remove("restored_from_checkpoint");
        metadata.remove("recovered_from_session");
        if let Some(restored) = &proof.restored_checkpoint {
            metadata.insert(
                "restored_from_checkpoint".to_owned(),
                restored.checkpoint_ref().to_owned(),
            );
            metadata.insert(
                "recovered_from_session".to_owned(),
                restored.source_session_id().to_string(),
            );
        }
        let resource = SessionResource {
            id: placement.entry().key().session_id().clone(),
            lifecycle: SessionLifecycle::Ready,
            incarnation: placement.entry().fence().session_incarnation(),
            requested_isolation: body.isolation.into(),
            effective_isolation: public_isolation(proof.effective_isolation),
            metadata,
        };
        let directory = placement.entry().fence();
        let fence = WorkerSessionFence {
            tenant_id: admission.request().key().tenant_id().clone(),
            session_id: resource.id.clone(),
            worker_epoch: directory.worker_epoch(),
            placement_version: directory.placement_version(),
            session_incarnation: directory.session_incarnation(),
        };
        let action_placement = placement
            .authority()
            .action_placement()
            .map_err(action_coordination_api_error)?;
        let key = (fence.tenant_id.clone(), fence.session_id.clone());
        let mut sessions = self.sessions.lock().map_err(|_| unavailable())?;
        if let Some(existing) = sessions.get(&key) {
            if existing.fence != fence || existing.action_placement != action_placement {
                return Err(mismatched());
            }
        } else {
            if sessions.len() >= 16_384 {
                return Err(ApiError::new(
                    ErrorCode::GlobalCapacityExceeded,
                    "session cache is full",
                ));
            }
            sessions.insert(
                key,
                GatewaySessionRecord {
                    fence,
                    action_placement,
                    resource: resource.clone(),
                    admission_lane: Arc::new(SessionAdmissionLane::default()),
                    retired_at: None,
                },
            );
        }
        let catalog_resource = sessions
            .get(&(
                admission.request().key().tenant_id().clone(),
                resource.id.clone(),
            ))
            .ok_or_else(unavailable)?
            .resource
            .clone();
        drop(sessions);
        self.catalog.upsert(
            admission.request().key().tenant_id().clone(),
            catalog_resource,
            Utc::now(),
        )?;
        Ok(resource)
    }

    pub(crate) fn fleet_session_record(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<GatewaySessionRecord, ApiError> {
        let authority = self
            .placement_authority(tenant, session)?
            .ok_or_else(unavailable)?;
        if let Some(record) = self
            .sessions
            .lock()
            .map_err(|_| unavailable())?
            .get(&(tenant.clone(), session.clone()))
            .cloned()
        {
            if record.action_placement
                != authority
                    .authority()
                    .action_placement()
                    .map_err(action_coordination_api_error)?
            {
                return Err(mismatched());
            }
            return Ok(record);
        }
        let admission = self
            .actions
            .get_session_admission(authority.admission_key())
            .map_err(action_coordination_api_error)?
            .ok_or_else(unavailable)?;
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let operation = fleet
            .creates
            .get(tenant, authority.admission_key().operation_id())
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let body: SessionCreateRequest =
            serde_json::from_value(operation.intent().canonical_request().clone())
                .map_err(|_| unavailable())?;
        let d = authority.entry().fence();
        let fence = WorkerSessionFence {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            worker_epoch: d.worker_epoch(),
            placement_version: d.placement_version(),
            session_incarnation: d.session_incarnation(),
        };
        let response = self
            .client_for_fence(&fence)?
            .request(WorkerRpcRequest::GetSession {
                fence: fence.clone(),
            })
            .map_err(worker_api_error)?;
        let WorkerRpcResponse::Session(receipt) = response else {
            return Err(unavailable());
        };
        if receipt.fence != fence {
            return Err(mismatched());
        }
        if receipt.lifecycle == WorkerSessionLifecycle::Ready {
            self.actions
                .validate_session_authority(authority.authority())
                .map_err(action_coordination_api_error)?;
        }
        self.publish_fleet_session(&admission, &body)?;
        let mut sessions = self.sessions.lock().map_err(|_| unavailable())?;
        let record = sessions
            .get_mut(&(tenant.clone(), session.clone()))
            .ok_or_else(unavailable)?;
        record.resource.lifecycle = match receipt.lifecycle {
            WorkerSessionLifecycle::Creating => SessionLifecycle::Creating,
            WorkerSessionLifecycle::Ready => SessionLifecycle::Ready,
            WorkerSessionLifecycle::Closing => SessionLifecycle::Closing,
            WorkerSessionLifecycle::Closed => SessionLifecycle::Closed,
            WorkerSessionLifecycle::Failed => SessionLifecycle::Failed,
        };
        let record = record.clone();
        drop(sessions);
        self.catalog
            .upsert(tenant.clone(), record.resource.clone(), Utc::now())?;
        Ok(record)
    }

    pub(crate) fn ack_fleet_projection(
        &self,
        tenant: &TenantId,
        operation: &browserd_core::OperationId,
        session: &SessionId,
    ) -> Result<(), ApiError> {
        let admission = self
            .actions
            .get_session_admission(&GatewaySessionAdmissionKey::new(
                tenant.clone(),
                operation.clone(),
            ))
            .map_err(action_coordination_api_error)?
            .ok_or_else(unavailable)?;
        if admission
            .placement()
            .is_none_or(|placement| placement.entry().key().session_id() != session)
        {
            return Err(mismatched());
        }
        self.actions
            .ack_session_create_projection(&admission)
            .map_err(action_coordination_api_error)?;
        Ok(())
    }

    pub(super) fn renew_fleet_authority(
        &self,
        authority: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, ApiError> {
        if authority.status() != GatewaySessionPlacementStatus::Ready {
            return Err(unavailable());
        }
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let admission = self
            .actions
            .get_session_admission(authority.admission_key())
            .map_err(action_coordination_api_error)?
            .ok_or_else(unavailable)?;
        let reservation = admission.reservation().ok_or_else(unavailable)?;
        let token = self.reservation_token(reservation)?;
        let intent = match authority.renewal() {
            Some(intent) => intent.clone(),
            None => self
                .actions
                .begin_session_renewal(authority, LeaseId::new(), PLACEMENT_TTL)
                .map_err(action_coordination_api_error)?,
        };
        let peer = fleet
            .inventory
            .peers
            .get(reservation.worker().worker_id())
            .ok_or_else(unavailable)?;
        let response = peer
            .client
            .request(WorkerRpcRequest::RenewReservedSession {
                token: token.clone(),
                renewal_nonce: intent.renewal_nonce().clone(),
                expected_lease_revision: intent.expected_lease_revision(),
                requested_ttl_millis: intent.requested_ttl_millis(),
            })
            .map_err(worker_api_error)?;
        let WorkerRpcResponse::ReservedSessionRenewed(receipt) = response else {
            return Err(unavailable());
        };
        let receipt = *receipt;
        let fence = authority.entry().fence();
        if receipt.token != token
            || receipt.renewal_nonce != *intent.renewal_nonce()
            || receipt.expected_lease_revision != intent.expected_lease_revision()
            || receipt.session.fence.tenant_id != *authority.entry().key().tenant_id()
            || receipt.session.fence.session_id != *authority.entry().key().session_id()
            || receipt.session.fence.worker_epoch != fence.worker_epoch()
            || receipt.session.fence.placement_version != fence.placement_version()
            || receipt.session.fence.session_incarnation != fence.session_incarnation()
            || receipt.session.lifecycle != WorkerSessionLifecycle::Ready
        {
            return Err(mismatched());
        }
        self.actions
            .finish_session_renewal(
                &intent,
                GatewaySessionWorkerRenewalProof {
                    authority: authority.authority().clone(),
                    worker: reservation.worker().clone(),
                    renewal_nonce: receipt.renewal_nonce,
                    granted_ttl_millis: receipt.granted_ttl_millis,
                },
            )
            .map_err(action_coordination_api_error)
    }

    pub(crate) fn begin_fleet_close(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<(), ApiError> {
        let authority = self
            .placement_authority(tenant, session)?
            .ok_or_else(unavailable)?;
        if authority.status() == GatewaySessionPlacementStatus::Ready {
            self.actions
                .begin_session_close(&authority)
                .map_err(action_coordination_api_error)?;
        }
        Ok(())
    }

    pub(crate) fn finish_fleet_close(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<(), ApiError> {
        let authority = self
            .placement_authority(tenant, session)?
            .ok_or_else(unavailable)?;
        let admission = self
            .actions
            .get_session_admission(authority.admission_key())
            .map_err(action_coordination_api_error)?
            .ok_or_else(unavailable)?;
        if admission.state() == GatewaySessionAdmissionState::Released {
            return Ok(());
        }
        let reservation = admission.reservation().ok_or_else(unavailable)?;
        let token = self.reservation_token(reservation)?;
        let response = self
            .client_for_placement(
                &authority
                    .authority()
                    .action_placement()
                    .map_err(action_coordination_api_error)?,
            )?
            .request(WorkerRpcRequest::InspectSessionReservation(token))
            .map_err(worker_api_error)?;
        let WorkerRpcResponse::SessionReservation(receipt) = response else {
            return Err(unavailable());
        };
        self.validate_reservation(reservation, &receipt)?;
        if receipt.phase != WorkerReservationPhase::Released
            || receipt.session.as_ref().is_none_or(|created| {
                created.session_id != *session
                    || created.tenant_id != *tenant
                    || created.worker_epoch != authority.entry().fence().worker_epoch()
                    || created.placement_version != authority.entry().fence().placement_version()
                    || created.session_incarnation
                        != authority.entry().fence().session_incarnation()
            })
        {
            return Err(unavailable());
        }
        if !self.release_terminal_reservation(&admission, &receipt)? {
            return Err(unavailable());
        }
        Ok(())
    }

    fn observe_fleet_workers(&self, limit: usize) -> Result<usize, ApiError> {
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let peers: Vec<_> = fleet.inventory.peers.values().collect();
        let mut cursor = fleet.worker_cursor.lock().map_err(|_| unavailable())?;
        let mut successes = 0;
        for offset in 0..limit.min(peers.len()).min(32) {
            let peer = peers[(*cursor + offset) % peers.len()];
            if let Ok(receipt) = self.capacity_status(peer)
                && self.observe_capacity(peer, &receipt).is_ok()
                && receipt.ready
                && !receipt.draining
            {
                successes += 1;
            }
        }
        *cursor = (*cursor + limit.min(peers.len()).min(32)) % peers.len();
        Ok(successes)
    }

    /// A bounded lease pass runs independently of create scheduling and worker readiness.
    /// Provider cursors move over every examined record, including unavailable or closing rows.
    pub fn maintain_fleet_leases(&self, limit: usize) -> Result<GatewayFleetPass, ApiError> {
        if !(1..=64).contains(&limit) {
            return Err(ApiError::invalid_request("invalid fleet pass limit"));
        }
        let Some(fleet) = &self.fleet else {
            return Ok(GatewayFleetPass::default());
        };
        if fleet
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(GatewayFleetPass::default());
        }
        struct Reset<'a>(&'a AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _running = Reset(&fleet.running);
        let mut cursor = fleet.cursor.lock().map_err(|_| unavailable())?;
        let page = self
            .actions
            .scan_session_admissions(cursor.clone(), limit.min(16))
            .map_err(action_coordination_api_error)?;
        let mut report = GatewayFleetPass {
            admissions_examined: page.examined(),
            ..GatewayFleetPass::default()
        };
        for admission in page.admissions() {
            if let Some(placement) = admission.placement() {
                if admission.state() == GatewaySessionAdmissionState::Active
                    && placement.status() == GatewaySessionPlacementStatus::Ready
                    && self.renew_fleet_authority(placement).is_ok()
                {
                    report.leases_renewed += 1;
                }
                if admission.state() == GatewaySessionAdmissionState::Closing {
                    let d = placement.entry().fence();
                    let fence = WorkerSessionFence {
                        tenant_id: placement.entry().key().tenant_id().clone(),
                        session_id: placement.entry().key().session_id().clone(),
                        worker_epoch: d.worker_epoch(),
                        placement_version: d.placement_version(),
                        session_incarnation: d.session_incarnation(),
                    };
                    // Close is an exact, idempotent cleanup command; no create/action is replayed.
                    let _ = self.request_worker(WorkerRpcRequest::CloseSession {
                        fence,
                        now_unix_millis: current_unix_millis()?,
                    });
                    let _ = self.finish_fleet_close(
                        placement.entry().key().tenant_id(),
                        placement.entry().key().session_id(),
                    );
                }
                if admission.pending_create_projection()
                    && let Ok(Some(operation)) = fleet.creates.get(
                        admission.request().key().tenant_id(),
                        admission.request().key().operation_id(),
                    )
                    && operation.state() == browserd_core::CreateOperationState::Succeeded
                    && operation.result().is_some_and(|result| {
                        result.session_id() == placement.entry().key().session_id()
                    })
                {
                    let _ = self.actions.ack_session_create_projection(admission);
                }
            }
        }
        *cursor = if page.is_complete() {
            GatewaySessionAdmissionCursor::default()
        } else {
            page.next_cursor().clone()
        };
        Ok(report)
    }

    pub fn refresh_fleet_workers(&self, limit: usize) -> Result<usize, ApiError> {
        if self.fleet.is_none() {
            return Ok(0);
        }
        self.observe_fleet_workers(limit)
    }
}

// Keep the immutable operation identity and placement protocol fields explicit at both callers.
#[allow(clippy::too_many_arguments)]
pub(super) fn worker_create_request(
    operation_id: browserd_core::OperationId,
    tenant_id: TenantId,
    idempotency_key: String,
    canonical_request_hash: [u8; 32],
    expected_worker_epoch: u64,
    placement_version: u64,
    now_unix_millis: u64,
    request: &SessionCreateRequest,
) -> WorkerCreateSessionRequest {
    WorkerCreateSessionRequest {
        operation_id,
        tenant_id,
        idempotency_key,
        canonical_request_hash,
        expected_worker_epoch,
        placement_version,
        session_incarnation: 1,
        requested_isolation: match request.isolation {
            IsolationRequest::SharedContext => WorkerIsolationProfile::SharedContext,
            IsolationRequest::TenantDedicatedShard => WorkerIsolationProfile::TenantDedicatedShard,
            IsolationRequest::DedicatedProcess => WorkerIsolationProfile::DedicatedProcess,
            IsolationRequest::DedicatedWorker => WorkerIsolationProfile::DedicatedWorker,
        },
        options_version: WORKER_SESSION_OPTIONS_VERSION,
        options: WorkerSessionOptionsV1 {
            workload_class_hint: request.workload_class_hint.clone(),
            viewport: WorkerViewport {
                width: request.viewport.width,
                height: request.viewport.height,
                device_scale_factor: request.viewport.device_scale_factor,
            },
            locale: request.locale.clone(),
            timezone: request.timezone.clone(),
            user_agent: request.user_agent.clone(),
            network_policy_id: request.network_policy_id.clone(),
            network_class: request.network_class.clone(),
            checkpoint_ref: request.checkpoint_ref.clone(),
            dialog_policy: request.dialog_policy.clone(),
            feature_profile: request.feature_profile.clone(),
            ttl_seconds: request.ttl_seconds,
            idle_timeout_seconds: request.idle_timeout_seconds,
            metadata: request.metadata.clone(),
        },
        now_unix_millis,
    }
}
