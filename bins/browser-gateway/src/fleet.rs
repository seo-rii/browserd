//! Fixed authenticated peer inventory and durable fleet admission.
use super::*;
use browserd_coordination::{
    CoordinationBlockingClient, DirectoryKey, GatewayFleetAdmissionConfig,
    GatewayFleetWorkerIdentity, GatewaySessionAdmissionCursor, GatewaySessionAuthorityRef,
    GatewaySessionPlacementAuthority, GatewaySessionPlacementStatus,
};
use std::collections::BTreeMap;

mod saga;

pub struct GatewayFleetPeer<C> {
    worker_id: WorkerId,
    endpoint: String,
    expected_worker_epoch: u64,
    client: Arc<C>,
}
impl<C> GatewayFleetPeer<C> {
    pub fn new(
        worker_id: WorkerId,
        endpoint: String,
        expected_worker_epoch: u64,
        client: Arc<C>,
    ) -> Result<Self, GatewayConfigurationError> {
        if endpoint.is_empty() || expected_worker_epoch == 0 {
            return Err(GatewayConfigurationError::InvalidWorkerPlacement);
        }
        Ok(Self {
            worker_id,
            endpoint,
            expected_worker_epoch,
            client,
        })
    }
}

pub struct GatewayFleetInventory<C> {
    config: Arc<GatewayFleetAdmissionConfig>,
    peers: BTreeMap<WorkerId, GatewayFleetPeer<C>>,
}
impl<C> GatewayFleetInventory<C> {
    pub fn new(
        config: Arc<GatewayFleetAdmissionConfig>,
        peers: Vec<GatewayFleetPeer<C>>,
    ) -> Result<Self, GatewayConfigurationError> {
        if peers.is_empty() || peers.len() > 256 || peers.len() != config.workers().len() {
            return Err(GatewayConfigurationError::InvalidWorkerPlacement);
        }
        let mut by_id = BTreeMap::new();
        for peer in peers {
            if !config.workers().iter().any(|worker| {
                worker.worker_id() == &peer.worker_id && worker.endpoint() == peer.endpoint
            }) || by_id.insert(peer.worker_id.clone(), peer).is_some()
            {
                return Err(GatewayConfigurationError::InvalidWorkerPlacement);
            }
        }
        Ok(Self {
            config,
            peers: by_id,
        })
    }
}

pub(super) struct GatewayFleet<C> {
    inventory: GatewayFleetInventory<C>,
    creates: CoordinationBlockingClient,
    cursor: Mutex<GatewaySessionAdmissionCursor>,
    worker_cursor: Mutex<usize>,
    control_cursor: Mutex<usize>,
    running: AtomicBool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayFleetPass {
    pub workers_observed: usize,
    pub admissions_examined: usize,
    pub leases_renewed: usize,
}

pub(super) struct ServingWorker<C> {
    pub worker_id: WorkerId,
    pub epoch: u64,
    pub client: Arc<C>,
}

fn unavailable() -> ApiError {
    ApiError::new(ErrorCode::WorkerUnavailable, "fleet authority unavailable")
}
fn mismatched() -> ApiError {
    ApiError::new(ErrorCode::PlacementMismatch, "fleet authority mismatch")
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    pub(super) fn notification_worker_count(&self) -> usize {
        self.fleet
            .as_ref()
            .map_or(1, |fleet| fleet.inventory.peers.len())
    }

    pub(super) fn notification_worker_id(&self, index: usize) -> Result<WorkerId, ApiError> {
        match &self.fleet {
            Some(fleet) => fleet
                .inventory
                .peers
                .keys()
                .nth(index % fleet.inventory.peers.len())
                .cloned()
                .ok_or_else(unavailable),
            None => Ok(self.placement.worker_id.clone()),
        }
    }

    #[must_use]
    pub fn with_fleet(
        mut self,
        inventory: GatewayFleetInventory<C>,
        creates: CoordinationBlockingClient,
    ) -> Self {
        self.fleet = Some(Arc::new(GatewayFleet {
            inventory,
            creates,
            cursor: Mutex::new(GatewaySessionAdmissionCursor::default()),
            worker_cursor: Mutex::new(0),
            control_cursor: Mutex::new(0),
            running: AtomicBool::new(false),
        }));
        self
    }

    pub(super) fn placement_authority(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, ApiError> {
        if self.fleet.is_none() {
            return Ok(None);
        }
        self.actions
            .resolve_session_placement(&DirectoryKey::new(tenant.clone(), session.clone()))
            .map_err(action_coordination_api_error)?
            .map(Some)
            .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound, "session not found"))
    }

    /// Resolves a configured worker ID without live-session/readiness requirements. The current
    /// process identity is authenticated anew; neither endpoint text nor a foreign fence is dialed.
    pub(super) fn historical_worker(
        &self,
        worker_id: &WorkerId,
    ) -> Result<ServingWorker<C>, ApiError> {
        let Some(fleet) = &self.fleet else {
            if worker_id != &self.placement.worker_id {
                return Err(mismatched());
            }
            return Ok(ServingWorker {
                worker_id: worker_id.clone(),
                epoch: self.placement.worker_epoch,
                client: Arc::clone(&self.client),
            });
        };
        let peer = fleet
            .inventory
            .peers
            .get(worker_id)
            .ok_or_else(unavailable)?;
        let receipt = self.capacity_status(peer)?;
        Ok(ServingWorker {
            worker_id: worker_id.clone(),
            epoch: receipt.worker_epoch,
            client: Arc::clone(&peer.client),
        })
    }

    pub(super) fn client_for_fence(&self, fence: &WorkerSessionFence) -> Result<Arc<C>, ApiError> {
        let Some(authority) = self.placement_authority(&fence.tenant_id, &fence.session_id)? else {
            return Ok(Arc::clone(&self.client));
        };
        let directory = authority.entry().fence();
        if directory.worker_epoch() != fence.worker_epoch
            || directory.placement_version() != fence.placement_version
            || directory.session_incarnation() != fence.session_incarnation
        {
            return Err(mismatched());
        }
        let fleet = self.fleet.as_ref().ok_or_else(unavailable)?;
        let peer = fleet
            .inventory
            .peers
            .get(directory.worker_id())
            .ok_or_else(unavailable)?;
        if peer.endpoint != authority.entry().endpoint() {
            return Err(mismatched());
        }
        Ok(Arc::clone(&peer.client))
    }

    pub(super) fn client_for_placement(
        &self,
        placement: &GatewayActionPlacement,
    ) -> Result<Arc<C>, ApiError> {
        self.client_for_worker_id(placement.directory_fence().worker_id())
    }

    pub(super) fn client_for_worker_id(&self, worker_id: &WorkerId) -> Result<Arc<C>, ApiError> {
        if let Some(fleet) = &self.fleet {
            return fleet
                .inventory
                .peers
                .get(worker_id)
                .map(|peer| Arc::clone(&peer.client))
                .ok_or_else(unavailable);
        }
        if worker_id != &self.placement.worker_id {
            return Err(mismatched());
        }
        Ok(Arc::clone(&self.client))
    }

    pub(super) fn authority_ref(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<Option<GatewaySessionAuthorityRef>, ApiError> {
        let Some(authority) = self.placement_authority(tenant, session)? else {
            return Ok(None);
        };
        let authority = self.renew_fleet_authority(&authority)?;
        if authority.status() != GatewaySessionPlacementStatus::Ready {
            return Err(unavailable());
        }
        Ok(Some(authority.authority().clone()))
    }

    pub(super) fn request_worker(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let fence = match &request {
            WorkerRpcRequest::GetSession { fence }
            | WorkerRpcRequest::InspectSession { fence, .. }
            | WorkerRpcRequest::CloseSession { fence, .. }
            | WorkerRpcRequest::CreatePage { fence, .. }
            | WorkerRpcRequest::ListPages { fence }
            | WorkerRpcRequest::ActivatePage { fence, .. }
            | WorkerRpcRequest::ClosePage { fence, .. }
            | WorkerRpcRequest::SubmitAction { fence, .. }
            | WorkerRpcRequest::GetAction { fence, .. }
            | WorkerRpcRequest::CancelAction { fence, .. }
            | WorkerRpcRequest::ResolveAction { fence, .. }
            | WorkerRpcRequest::StoreArtifact { fence, .. }
            | WorkerRpcRequest::UploadNamedArtifact { fence, .. }
            | WorkerRpcRequest::ListArtifacts { fence, .. }
            | WorkerRpcRequest::GetArtifact { fence, .. }
            | WorkerRpcRequest::OpenArtifact { fence, .. }
            | WorkerRpcRequest::ReadArtifact { fence, .. }
            | WorkerRpcRequest::CloseArtifact { fence, .. }
            | WorkerRpcRequest::GetApproval { fence, .. }
            | WorkerRpcRequest::ListApprovals { fence }
            | WorkerRpcRequest::DecideApproval { fence, .. } => Some(fence),
            _ => None,
        };
        let client = match fence {
            Some(fence) => {
                if self.fleet.is_some()
                    && !matches!(
                        &request,
                        WorkerRpcRequest::GetSession { .. }
                            | WorkerRpcRequest::InspectSession { .. }
                            | WorkerRpcRequest::CloseSession { .. }
                            | WorkerRpcRequest::GetAction { .. }
                            | WorkerRpcRequest::CancelAction { .. }
                            | WorkerRpcRequest::ResolveAction { .. }
                            | WorkerRpcRequest::CloseArtifact { .. }
                    )
                {
                    let authority = self
                        .placement_authority(&fence.tenant_id, &fence.session_id)
                        .map_err(|_| WorkerRpcError::Protocol)?
                        .ok_or(WorkerRpcError::Protocol)?;
                    self.actions
                        .validate_session_authority(authority.authority())
                        .map_err(|_| WorkerRpcError::Protocol)?;
                }
                self.client_for_fence(fence)
                    .map_err(|_| WorkerRpcError::Protocol)?
            }
            None if self.fleet.is_none() => Arc::clone(&self.client),
            None => return Err(WorkerRpcError::Protocol),
        };
        client.request(request)
    }

    pub(super) fn next_control_event_client(&self) -> Result<Arc<C>, ApiError> {
        let Some(fleet) = &self.fleet else {
            return Ok(Arc::clone(&self.client));
        };
        let mut cursor = fleet.control_cursor.lock().map_err(|_| unavailable())?;
        let peer = fleet
            .inventory
            .peers
            .values()
            .nth(*cursor % fleet.inventory.peers.len())
            .ok_or_else(unavailable)?;
        *cursor = (*cursor + 1) % fleet.inventory.peers.len();
        Ok(Arc::clone(&peer.client))
    }
}
