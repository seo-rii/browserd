//! Durable routing hints require fresh authenticated worker proof before admitting effects.
use super::*;
use browserd_coordination::{
    GatewayDirectoryLifecycle as Phase, GatewaySessionDirectoryRecord as Record,
    GatewaySessionIsolation as Isolation,
};

fn isolation(value: IsolationProfile) -> Isolation {
    match value {
        IsolationProfile::SharedContext => Isolation::SharedContext,
        IsolationProfile::TenantDedicatedShard => Isolation::TenantDedicatedShard,
        IsolationProfile::DedicatedProcess => Isolation::DedicatedProcess,
        IsolationProfile::DedicatedWorker => Isolation::DedicatedWorker,
    }
}
fn public_isolation(value: Isolation) -> IsolationProfile {
    match value {
        Isolation::SharedContext => IsolationProfile::SharedContext,
        Isolation::TenantDedicatedShard => IsolationProfile::TenantDedicatedShard,
        Isolation::DedicatedProcess => IsolationProfile::DedicatedProcess,
        Isolation::DedicatedWorker => IsolationProfile::DedicatedWorker,
    }
}
fn phase(value: WorkerSessionLifecycle) -> Phase {
    match value {
        WorkerSessionLifecycle::Creating => Phase::Creating,
        WorkerSessionLifecycle::Ready => Phase::Ready,
        WorkerSessionLifecycle::Closing => Phase::Closing,
        WorkerSessionLifecycle::Closed => Phase::Closed,
        WorkerSessionLifecycle::Failed => Phase::Failed,
    }
}
fn resource(record: &Record) -> SessionResource {
    SessionResource {
        id: record.session_id().clone(),
        incarnation: record.placement().directory_fence().session_incarnation(),
        lifecycle: match record.lifecycle() {
            Phase::Creating => SessionLifecycle::Creating,
            Phase::Ready => SessionLifecycle::Ready,
            Phase::Closing => SessionLifecycle::Closing,
            Phase::Closed => SessionLifecycle::Closed,
            Phase::Failed => SessionLifecycle::Failed,
        },
        requested_isolation: public_isolation(record.requested_isolation()),
        effective_isolation: public_isolation(record.effective_isolation()),
        metadata: record.metadata().clone(),
    }
}
impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// Listing exposes the last positively confirmed durable lifecycle, including old terminal
    /// fences. It grants no live admission; GET/new effects still verify the configured owner.
    pub(super) fn list_durable_sessions(
        &self,
        tenant: &TenantId,
        query: &browserd_api::SessionListQuery,
    ) -> Result<browserd_api::SessionListPage, ApiError> {
        let cursor = query.cursor_for(tenant)?;
        let page = self
            .actions
            .list_single_host_directory(
                tenant,
                cursor.after(),
                cursor.ceiling(),
                browserd_coordination::MAX_SESSION_DIRECTORY_PAGE,
            )
            .map_err(action_coordination_api_error)?;
        if page.records().iter().any(|record| {
            record.tenant_id() != tenant
                || record.placement().directory_fence().worker_id() != &self.placement.worker_id
        }) {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "durable listing escaped its tenant or configured worker",
            ));
        }
        browserd_api::SessionListPage::from_bounded_resources(
            tenant,
            query,
            page.records().iter().map(resource).collect(),
            page.ceiling().cloned(),
            page.has_more(),
        )
    }
    pub(super) fn verify_single_host_worker_ready(
        &self,
        record: &GatewaySessionRecord,
    ) -> Result<(), ApiError> {
        match self
            .request_worker(WorkerRpcRequest::Probe {
                expected_worker_epoch: record.fence.worker_epoch,
            })
            .map_err(worker_api_error)?
        {
            WorkerRpcResponse::Probe(proof)
                if proof.worker_id == *record.action_placement.directory_fence().worker_id()
                    && proof.worker_epoch == record.fence.worker_epoch
                    && proof.ready =>
            {
                Ok(())
            }
            WorkerRpcResponse::Probe(proof)
                if proof.worker_id != *record.action_placement.directory_fence().worker_id()
                    || proof.worker_epoch != record.fence.worker_epoch =>
            {
                Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "worker readiness proof has a different owner",
                ))
            }
            WorkerRpcResponse::Failure(failure) => {
                Err(worker_api_error(WorkerRpcError::Remote(failure)))
            }
            _ => Err(ApiError::new(
                ErrorCode::WorkerUnavailable,
                "worker is not ready for a new effect",
            )),
        }
    }
    pub(super) fn publish_durable_session(
        &self,
        tenant: &TenantId,
        placement: &GatewayActionPlacement,
        value: &SessionResource,
    ) -> Result<SessionResource, ApiError> {
        let record = Record::new(
            tenant.clone(),
            value.id.clone(),
            placement.clone(),
            Phase::Ready,
            isolation(value.requested_isolation),
            isolation(value.effective_isolation),
            value.metadata.clone(),
        )
        .map_err(action_coordination_api_error)?;
        self.actions
            .commit_single_host_directory(record, None)
            .map(|stored| resource(&stored))
            .map_err(action_coordination_api_error)
    }
    pub(super) fn persist_directory_phase(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &WorkerSessionFence,
        observed: WorkerSessionLifecycle,
    ) -> Result<Record, ApiError> {
        for _ in 0..4 {
            let stored = self
                .actions
                .get_single_host_directory(tenant, session)
                .map_err(action_coordination_api_error)?
                .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound, "session not found"))?;
            if !self.owns_session_placement(stored.placement(), fence)
                || stored.placement().directory_fence().session_incarnation()
                    != fence.session_incarnation
            {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "durable session placement mismatch",
                ));
            }
            // A stale positive read cannot resurrect a closing/terminal session.
            let Ok(next) = stored.with_lifecycle(phase(observed)) else {
                return Ok(stored);
            };
            if next == stored {
                return Ok(stored);
            }
            match self
                .actions
                .commit_single_host_directory(next, Some(stored.revision()))
            {
                Ok(next) => return Ok(next),
                Err(GatewayActionCoordinationError::SessionDirectoryConflict) => continue,
                Err(error) => return Err(action_coordination_api_error(error)),
            }
        }
        Err(ApiError::new(
            ErrorCode::WorkerUnavailable,
            "session directory update is contended",
        ))
    }
    pub(super) fn durable_session_record(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<GatewaySessionRecord, ApiError> {
        let stored = self
            .actions
            .get_single_host_directory(tenant, session)
            .map_err(action_coordination_api_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound, "session not found"))?;
        let directory = stored.placement().directory_fence();
        let fence = WorkerSessionFence {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            worker_epoch: directory.worker_epoch(),
            placement_version: directory.placement_version(),
            session_incarnation: directory.session_incarnation(),
        };
        if stored.tenant_id() != tenant
            || stored.session_id() != session
            || !self.owns_session_placement(stored.placement(), &fence)
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "durable session placement mismatch",
            ));
        }
        let stored = if stored.lifecycle().terminal() {
            stored
        } else {
            let proof = match self
                .request_worker(WorkerRpcRequest::InspectSession {
                    expected_worker_id: directory.worker_id().clone(),
                    fence: fence.clone(),
                })
                .map_err(worker_api_error)?
            {
                WorkerRpcResponse::SessionOwnership(proof)
                    if proof.worker_id == *directory.worker_id()
                        && proof.session.fence == fence =>
                {
                    proof
                }
                WorkerRpcResponse::SessionOwnership(_) => {
                    return Err(ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "worker returned a mismatched live session fence",
                    ));
                }
                WorkerRpcResponse::Failure(failure) => {
                    return Err(worker_api_error(WorkerRpcError::Remote(failure)));
                }
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::WorkerUnavailable,
                        "live session ownership unavailable",
                    ));
                }
            };
            if matches!(
                proof.session.lifecycle,
                WorkerSessionLifecycle::Closed | WorkerSessionLifecycle::Failed
            ) {
                self.record_terminal_session_proof(stored.placement(), &proof)?;
            }
            self.persist_directory_phase(tenant, session, &fence, proof.session.lifecycle)?
        };
        let value = resource(&stored);
        let mut sessions = self.sessions.lock().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
        })?;
        let key = (tenant.clone(), session.clone());
        if let Some(current) = sessions.get_mut(&key) {
            if current.fence != fence || current.action_placement != *stored.placement() {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "cached session placement mismatch",
                ));
            }
            current.resource = value.clone();
            current.retired_at = stored.lifecycle().terminal().then_some(stored.updated_at());
        } else {
            if sessions.len() >= 16_384 {
                return Err(ApiError::new(
                    ErrorCode::GlobalCapacityExceeded,
                    "session cache is full",
                ));
            }
            sessions.insert(
                key.clone(),
                GatewaySessionRecord {
                    fence,
                    action_placement: stored.placement().clone(),
                    resource: value.clone(),
                    admission_lane: Arc::new(SessionAdmissionLane::default()),
                    retired_at: stored.lifecycle().terminal().then_some(stored.updated_at()),
                },
            );
        }
        let result = sessions.get(&key).cloned().ok_or_else(|| {
            ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
        })?;
        drop(sessions);
        self.catalog
            .upsert(tenant.clone(), value, stored.updated_at())?;
        Ok(result)
    }
    pub(super) fn replay_durable_action(
        &self,
        tenant: &TenantId,
        command: &ActionSubmitCommand,
    ) -> Result<Option<GatewayActionSnapshot>, ApiError> {
        if command.idempotency_key.is_nil() {
            return Err(ApiError::invalid_request(
                "Idempotency-Key must not be the nil UUID",
            ));
        }
        let Some(stored) = self
            .actions
            .get_action_by_idempotency(
                tenant,
                &command.session_id,
                &command.idempotency_key.to_string(),
            )
            .map_err(action_coordination_api_error)?
        else {
            return Ok(None);
        };
        let canonical = serde_json::to_value(&command.body)
            .map_err(|_| ApiError::invalid_request("invalid action body"))?;
        let hash = browserd_operations::CanonicalRequestHash::from_json(&canonical);
        if stored.tenant_id() != tenant
            || stored.session_id() != &command.session_id
            || stored.idempotency_key() != command.idempotency_key.to_string()
            || stored.request_hash().as_bytes() != hash.as_bytes()
        {
            return Err(ApiError::new(
                ErrorCode::IdempotencyConflict,
                "idempotency key is already bound to another action",
            ));
        }
        if stored.placement().directory_fence().session_incarnation()
            != command.body.if_session_incarnation
        {
            return Err(ApiError::new(
                ErrorCode::GenerationMismatch,
                "session incarnation precondition failed",
            ));
        }
        Ok(Some(stored))
    }
}
