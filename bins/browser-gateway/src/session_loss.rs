//! Positive, fully fenced terminal-session observations. Read failures are never loss proof.

use browserd_api::ApiError;
use browserd_coordination::{GatewayActionPlacement, SessionLossClaim};
use browserd_core::{ErrorCode, SessionLifecycle};
use browserd_worker::{
    WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence, WorkerSessionLifecycle,
    WorkerSessionOwnershipReceipt,
};
use chrono::Utc;
use uuid::Uuid;

use super::{
    GatewaySessionRecord, GatewayWorkerClient, GatewayWorkerRuntime, action_coordination_api_error,
};

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    pub(super) fn owns_session_placement(
        &self,
        placement: &GatewayActionPlacement,
        fence: &WorkerSessionFence,
    ) -> bool {
        let directory = placement.directory_fence();
        (self.fleet.is_some() && self.client_for_placement(placement).is_ok()
            || (directory.worker_id() == &self.placement.worker_id
                && directory.worker_epoch() == self.placement.worker_epoch
                && directory.placement_version() == self.placement.placement_version
                && placement.directory_revision() == self.placement.directory_revision))
            && fence.worker_epoch == directory.worker_epoch()
            && fence.placement_version == directory.placement_version()
            && fence.session_incarnation == directory.session_incarnation()
            && fence.session_incarnation != 0
    }

    /// This endpoint authenticates worker identity even while the worker is draining/not ready.
    /// Absence, timeout and every identity mismatch leave durable state untouched.
    pub(super) fn inspect_owned_session(
        &self,
        placement: &GatewayActionPlacement,
        fence: &WorkerSessionFence,
    ) -> Option<WorkerSessionOwnershipReceipt> {
        if !self.owns_session_placement(placement, fence) {
            return None;
        }
        match self
            .client_for_placement(placement)
            .ok()?
            .request(WorkerRpcRequest::InspectSession {
                expected_worker_id: placement.directory_fence().worker_id().clone(),
                fence: fence.clone(),
            }) {
            Ok(WorkerRpcResponse::SessionOwnership(proof))
                if &proof.worker_id == placement.directory_fence().worker_id()
                    && proof.session.fence == *fence =>
            {
                Some(proof)
            }
            _ => None,
        }
    }

    /// Canonical identity is committed before bounded materialization. The durable loss/event
    /// source remains the retry owner if a later step or the optional notification sink fails.
    pub(super) fn record_terminal_session_proof(
        &self,
        placement: &GatewayActionPlacement,
        proof: &WorkerSessionOwnershipReceipt,
    ) -> Result<(), ApiError> {
        if &proof.worker_id != placement.directory_fence().worker_id()
            || !self.owns_session_placement(placement, &proof.session.fence)
            || !matches!(
                proof.session.lifecycle,
                WorkerSessionLifecycle::Closed | WorkerSessionLifecycle::Failed
            )
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "terminal session proof is invalid",
            ));
        }
        let proposed = SessionLossClaim::new(
            proof.session.fence.tenant_id.clone(),
            proof.session.fence.session_id.clone(),
            placement.clone(),
            Uuid::now_v7(),
        );
        let claim = self
            .actions
            .ensure_session_lost(&proposed, Utc::now())
            .map_err(action_coordination_api_error)?
            .into_claim();
        self.actions
            .materialize_session_loss(&claim, 1, Utc::now())
            .map_err(action_coordination_api_error)?;
        if self.outbox.is_some()
            && let Err(error) = self.relay_terminal_event(claim.tenant_id(), claim.session_id())
        {
            eprintln!("gateway session-loss projection remains pending: {error:?}");
        }
        Ok(())
    }

    /// Stop memory admission as soon as a terminal receipt is observed, before any potentially
    /// failing coordination write. Only the inspected exact worker proof can commit loss.
    pub(super) fn confirm_session_terminal(
        &self,
        record: &GatewaySessionRecord,
        lifecycle: WorkerSessionLifecycle,
    ) -> Result<(), ApiError> {
        if !matches!(
            lifecycle,
            WorkerSessionLifecycle::Closed | WorkerSessionLifecycle::Failed
        ) {
            return Ok(());
        }
        let resource = {
            let mut sessions = self.sessions.lock().map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
            })?;
            let current = sessions
                .get_mut(&(
                    record.fence.tenant_id.clone(),
                    record.fence.session_id.clone(),
                ))
                .filter(|current| {
                    current.fence == record.fence
                        && current.action_placement == record.action_placement
                })
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "session changed during terminal observation",
                    )
                })?;
            if matches!(
                current.resource.lifecycle,
                SessionLifecycle::Creating | SessionLifecycle::Ready
            ) {
                current.resource.lifecycle = SessionLifecycle::Closing;
            }
            current.resource.clone()
        };
        self.catalog
            .upsert(record.fence.tenant_id.clone(), resource, Utc::now())?;
        let proof = self
            .inspect_owned_session(&record.action_placement, &record.fence)
            .filter(|proof| proof.session.lifecycle == lifecycle)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "terminal worker ownership could not be confirmed",
                )
            })?;
        self.record_terminal_session_proof(&record.action_placement, &proof)
    }
}
