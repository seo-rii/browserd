//! Typed admission clients preserve exact token identity across lost responses.
use super::*;
use crate::{
    WorkerRpcBlockingClient, WorkerRpcClient, WorkerRpcError, WorkerRpcRequest, WorkerRpcResponse,
};
fn capacity_response(
    response: WorkerRpcResponse,
    epoch: u64,
) -> Result<WorkerCapacityReceipt, WorkerRpcError> {
    match response {
        WorkerRpcResponse::Capacity(r)
            if (epoch == 0 || r.worker_epoch == epoch)
                && r.worker_epoch > 0
                && r.capacity_revision > 0
                && r.capacity.contexts > 0
                && r.compatibility_digest != [0; 32]
                && !(r.ready && r.draining)
                && r.exclusive_assignment
                    .as_ref()
                    .is_none_or(|a| a.worker_id() == &r.worker_id)
                && r.raw_free.fits_within(r.capacity) =>
        {
            Ok(r)
        }
        WorkerRpcResponse::Failure(f) => Err(WorkerRpcError::Remote(f)),
        _ => Err(WorkerRpcError::Protocol),
    }
}
fn reservation_response(
    response: WorkerRpcResponse,
    request: &WorkerReservationRequest,
    token: Option<&WorkerReservationToken>,
) -> Result<WorkerReservationReceipt, WorkerRpcError> {
    match response {
        WorkerRpcResponse::SessionReservation(r)
            if r.token.request == *request
                && token.is_none_or(|t| t == &r.token)
                && r.token.worker_id == r.capacity.worker_id
                && r.capacity.worker_epoch == request.request.expected_worker_epoch
                && r.capacity.worker_boot_nonce == request.expected_worker_boot_nonce
                && r.token.debit_sequence > 0
                && r.capacity.acknowledged_debit_sequence >= r.token.debit_sequence
                && r.capacity.capacity_revision > 0
                && r.capacity.compatibility_digest == request.compatibility_digest
                && r.capacity.raw_free.fits_within(r.capacity.capacity)
                && !(r.capacity.ready && r.capacity.draining)
                && r.capacity.exclusive_assignment.as_ref().is_none_or(|a| {
                    a.worker_id() == &r.token.worker_id
                        && a.tenant_id() == &request.request.tenant_id
                })
                && r.remaining_ttl_millis <= request.ttl_millis
                && match r.phase {
                    WorkerReservationPhase::Active | WorkerReservationPhase::Released => {
                        (r.session.as_ref().is_some_and(|s| {
                            s.operation_id == request.request.operation_id
                                && s.tenant_id == request.request.tenant_id
                                && s.worker_epoch == request.request.expected_worker_epoch
                                && s.placement_version == request.request.placement_version
                                && s.session_incarnation == request.request.session_incarnation
                                && request
                                    .request
                                    .requested_isolation
                                    .satisfied_by(s.effective_isolation)
                                && s.restored_checkpoint
                                    .as_ref()
                                    .map(|c| c.checkpoint_ref.as_str())
                                    == request.request.options.checkpoint_ref.as_deref()
                        }) && r.disposed_session.is_none()
                            && (r.phase != WorkerReservationPhase::Active
                                || r.session_lease_remaining_millis.is_some()))
                            || (r.phase == WorkerReservationPhase::Released
                                && r.session.is_none()
                                && r.session_lease_remaining_millis.is_none()
                                && r.disposed_session.as_ref().is_some_and(|f| {
                                    f.tenant_id == request.request.tenant_id
                                        && f.worker_epoch == request.request.expected_worker_epoch
                                        && f.placement_version == request.request.placement_version
                                        && f.session_incarnation
                                            == request.request.session_incarnation
                                }))
                    }
                    _ => {
                        r.session.is_none()
                            && r.session_lease_remaining_millis.is_none()
                            && r.disposed_session.is_none()
                    }
                } =>
        {
            Ok(*r)
        }
        WorkerRpcResponse::Failure(f) => Err(WorkerRpcError::Remote(f)),
        _ => Err(WorkerRpcError::Protocol),
    }
}
fn renewal_response(
    response: WorkerRpcResponse,
    token: &WorkerReservationToken,
    nonce: &LeaseId,
    revision: u64,
    ttl: u64,
) -> Result<WorkerReservedSessionRenewReceipt, WorkerRpcError> {
    match response {
        WorkerRpcResponse::ReservedSessionRenewed(r)
            if r.token == *token
                && r.renewal_nonce == *nonce
                && r.expected_lease_revision == revision
                && r.granted_ttl_millis == ttl
                && r.session.fence.tenant_id == token.request.request.tenant_id
                && r.session.fence.worker_epoch == token.request.request.expected_worker_epoch
                && r.session.fence.placement_version == token.request.request.placement_version
                && r.session.fence.session_incarnation
                    == token.request.request.session_incarnation
                && r.session.lifecycle == crate::WorkerSessionLifecycle::Ready =>
        {
            Ok(*r)
        }
        WorkerRpcResponse::Failure(f) => Err(WorkerRpcError::Remote(f)),
        _ => Err(WorkerRpcError::Protocol),
    }
}
impl WorkerRpcClient {
    pub async fn ack_session_reservation(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response = self
            .exchange(WorkerRpcRequest::AckSessionReservation(token.clone()))
            .await?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub async fn capacity_status(
        &self,
        expected_worker_epoch: u64,
    ) -> Result<WorkerCapacityReceipt, WorkerRpcError> {
        capacity_response(
            self.exchange(WorkerRpcRequest::CapacityStatus {
                expected_worker_epoch,
            })
            .await?,
            expected_worker_epoch,
        )
    }
    pub async fn reserve_session(
        &self,
        request: WorkerReservationRequest,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response = self
            .exchange(WorkerRpcRequest::ReserveSession(request.clone()))
            .await?;
        reservation_response(response, &request, None)
    }
    pub async fn commit_reserved_session(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response = self
            .exchange(WorkerRpcRequest::CommitReservedSession(token.clone()))
            .await?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub async fn inspect_session_reservation(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response = self
            .exchange(WorkerRpcRequest::InspectSessionReservation(token.clone()))
            .await?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub async fn cancel_session_reservation(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response = self
            .exchange(WorkerRpcRequest::CancelSessionReservation(token.clone()))
            .await?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub async fn renew_reserved_session(
        &self,
        token: WorkerReservationToken,
        renewal_nonce: LeaseId,
        expected_lease_revision: u64,
        requested_ttl_millis: u64,
    ) -> Result<WorkerReservedSessionRenewReceipt, WorkerRpcError> {
        let response = self
            .exchange(WorkerRpcRequest::RenewReservedSession {
                token: token.clone(),
                renewal_nonce: renewal_nonce.clone(),
                expected_lease_revision,
                requested_ttl_millis,
            })
            .await?;
        renewal_response(
            response,
            &token,
            &renewal_nonce,
            expected_lease_revision,
            requested_ttl_millis,
        )
    }
}
impl WorkerRpcBlockingClient {
    pub fn ack_session_reservation(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response =
            self.request_blocking(WorkerRpcRequest::AckSessionReservation(token.clone()))?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub fn capacity_status(
        &self,
        expected_worker_epoch: u64,
    ) -> Result<WorkerCapacityReceipt, WorkerRpcError> {
        capacity_response(
            self.request_blocking(WorkerRpcRequest::CapacityStatus {
                expected_worker_epoch,
            })?,
            expected_worker_epoch,
        )
    }
    pub fn reserve_session(
        &self,
        request: WorkerReservationRequest,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response = self.request_blocking(WorkerRpcRequest::ReserveSession(request.clone()))?;
        reservation_response(response, &request, None)
    }
    pub fn commit_reserved_session(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response =
            self.request_blocking(WorkerRpcRequest::CommitReservedSession(token.clone()))?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub fn inspect_session_reservation(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response =
            self.request_blocking(WorkerRpcRequest::InspectSessionReservation(token.clone()))?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub fn cancel_session_reservation(
        &self,
        token: WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerRpcError> {
        let response =
            self.request_blocking(WorkerRpcRequest::CancelSessionReservation(token.clone()))?;
        reservation_response(response, &token.request, Some(&token))
    }
    pub fn renew_reserved_session(
        &self,
        token: WorkerReservationToken,
        renewal_nonce: LeaseId,
        expected_lease_revision: u64,
        requested_ttl_millis: u64,
    ) -> Result<WorkerReservedSessionRenewReceipt, WorkerRpcError> {
        let response = self.request_blocking(WorkerRpcRequest::RenewReservedSession {
            token: token.clone(),
            renewal_nonce: renewal_nonce.clone(),
            expected_lease_revision,
            requested_ttl_millis,
        })?;
        renewal_response(
            response,
            &token,
            &renewal_nonce,
            expected_lease_revision,
            requested_ttl_millis,
        )
    }
}
