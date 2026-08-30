use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::{EgressFence, TenantId};
use browserd_egress::{
    AcceptedIngressHandler, AttachmentManager, AttachmentManagerError, AttachmentState,
    AttachmentStatus, BindingDigest, DaemonEpoch, DataPlane, DataPlaneLimits, EgressPolicy,
    MonotonicMillis, PreparedAttachmentReceipt, QuotaLimits, RouteBinding, RouteRegistry,
    TcpConnector, TokioResolver,
};
use browserd_egress_control::{
    ActiveInstallResponse, ControlRequest, EpochProbeError, PendingInstall, ReceiveInstallError,
    ServerCommitError, receive_control_request, receive_install_request,
};
use tokio::net::UnixStream;

/// Bounded daemon-wide configuration shared by every dedicated attachment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonLimits {
    max_lease: Duration,
    max_plans: usize,
    quotas: QuotaLimits,
}

impl DaemonLimits {
    pub fn new(
        max_lease: Duration,
        max_plans: usize,
        quotas: QuotaLimits,
    ) -> Result<Self, DaemonControlError> {
        let lease_millis = max_lease.as_millis();
        if lease_millis == 0 || lease_millis > u128::from(u64::MAX) {
            return Err(DaemonControlError::InvalidLimits);
        }
        if max_plans == 0
            || quotas.max_concurrent_connections == 0
            || quotas.max_connection_starts_per_window == 0
            || quotas.max_dns_queries_per_window == 0
            || quotas.max_egress_bytes_per_window == 0
            || quotas.max_total_egress_bytes == 0
            || quotas.accounting_window.is_zero()
            || quotas.idle_connection_timeout.is_zero()
        {
            return Err(DaemonControlError::InvalidLimits);
        }
        Ok(Self {
            max_lease,
            max_plans,
            quotas,
        })
    }
}

/// Immutable preparation command. All duplicated identity is derived from the
/// full egress fence rather than trusted independently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRouteRequest {
    daemon_epoch: u64,
    tenant_id: TenantId,
    egress_fence: EgressFence,
    binding_digest: [u8; 32],
    profile: String,
    lease_ttl: Duration,
}

impl PreparedRouteRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        daemon_epoch: u64,
        tenant_id: TenantId,
        egress_fence: EgressFence,
        binding_digest: [u8; 32],
        profile: impl Into<String>,
        lease_ttl: Duration,
    ) -> Result<Self, DaemonControlError> {
        let profile = profile.into();
        if daemon_epoch == 0
            || binding_digest == [0; 32]
            || profile.is_empty()
            || lease_ttl.is_zero()
        {
            return Err(DaemonControlError::InvalidPrepareRequest);
        }
        Ok(Self {
            daemon_epoch,
            tenant_id,
            egress_fence,
            binding_digest,
            profile,
            lease_ttl,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRouteResponse {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    binding_digest: [u8; 32],
    prepare_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewRouteRequest {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    lease_ttl: Duration,
}

impl RenewRouteRequest {
    pub fn new(
        renewal_sequence: u64,
        daemon_epoch: u64,
        egress_fence: EgressFence,
        attachment_id: u64,
        activation_revision: u64,
        lease_ttl: Duration,
    ) -> Result<Self, DaemonControlError> {
        if renewal_sequence == 0
            || daemon_epoch == 0
            || attachment_id == 0
            || activation_revision == 0
            || lease_ttl.is_zero()
        {
            return Err(DaemonControlError::InvalidRenewRequest);
        }
        Ok(Self {
            renewal_sequence,
            daemon_epoch,
            egress_fence,
            attachment_id,
            activation_revision,
            lease_ttl,
        })
    }

    #[must_use]
    pub const fn renewal_sequence(&self) -> u64 {
        self.renewal_sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewedRouteResponse {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    expires_at_millis: u64,
}

impl RenewedRouteResponse {
    #[must_use]
    pub const fn renewal_sequence(&self) -> u64 {
        self.renewal_sequence
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn attachment_id(&self) -> u64 {
        self.attachment_id
    }

    #[must_use]
    pub const fn activation_revision(&self) -> u64 {
        self.activation_revision
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }
}

impl PreparedRouteResponse {
    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    #[must_use]
    pub const fn prepare_revision(&self) -> u64 {
        self.prepare_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentStatusView {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    state: AttachmentState,
    active: Option<ActiveInstallResponse>,
}

impl AttachmentStatusView {
    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn state(&self) -> AttachmentState {
        self.state
    }

    #[must_use]
    pub const fn active(&self) -> Option<&ActiveInstallResponse> {
        self.active.as_ref()
    }
}

#[derive(Clone)]
pub struct EgressDaemon {
    daemon_epoch: DaemonEpoch,
    limits: DaemonLimits,
    manager: AttachmentManager,
    plans: Arc<Mutex<HashMap<EgressFence, PreparedPlan>>>,
}

#[derive(Clone)]
struct PreparedPlan {
    request: PreparedRouteRequest,
    prepared: PreparedAttachmentReceipt,
    binding: Option<RouteBinding>,
    active: Option<ActiveInstallResponse>,
    last_renewal: Option<CommittedRenewal>,
}

#[derive(Clone)]
struct CommittedRenewal {
    request: RenewRouteRequest,
    response: RenewedRouteResponse,
}

impl EgressDaemon {
    pub fn new(
        daemon_epoch: DaemonEpoch,
        limits: DaemonLimits,
        data_plane_limits: DataPlaneLimits,
    ) -> Result<Self, DaemonControlError> {
        let routes = RouteRegistry::new(limits.max_lease);
        let data_plane = DataPlane::new(
            routes.clone(),
            TokioResolver,
            TcpConnector,
            data_plane_limits,
        )
        .map_err(|_| DaemonControlError::InvalidLimits)?;
        Ok(Self::with_registry_and_handler(
            daemon_epoch,
            limits,
            routes,
            Arc::new(data_plane),
        ))
    }

    pub fn with_handler(
        daemon_epoch: DaemonEpoch,
        limits: DaemonLimits,
        handler: Arc<dyn AcceptedIngressHandler>,
    ) -> Result<Self, DaemonControlError> {
        let routes = RouteRegistry::new(limits.max_lease);
        Ok(Self::with_registry_and_handler(
            daemon_epoch,
            limits,
            routes,
            handler,
        ))
    }

    fn with_registry_and_handler(
        daemon_epoch: DaemonEpoch,
        limits: DaemonLimits,
        routes: RouteRegistry,
        handler: Arc<dyn AcceptedIngressHandler>,
    ) -> Self {
        let manager = AttachmentManager::with_registry(daemon_epoch, routes, handler);
        Self {
            daemon_epoch,
            limits,
            manager,
            plans: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    pub fn prepare(
        &self,
        request: PreparedRouteRequest,
    ) -> Result<PreparedRouteResponse, DaemonControlError> {
        self.ensure_epoch(request.daemon_epoch)?;
        if request.profile != "public-web" || request.lease_ttl > self.limits.max_lease {
            return Err(DaemonControlError::UnsupportedPolicy);
        }
        let mut plans = self.lock_plans();
        if let Some(existing) = plans.get(&request.egress_fence) {
            if existing.request != request {
                return Err(DaemonControlError::PlanConflict);
            }
            return Ok(prepared_response(&existing.prepared));
        }
        if plans.len() >= self.limits.max_plans {
            return Err(DaemonControlError::PlanCapacityExceeded);
        }
        let prepared = self
            .manager
            .prepare(
                request.egress_fence.clone(),
                BindingDigest::new(request.binding_digest),
            )
            .map_err(DaemonControlError::Manager)?;
        let response = prepared_response(&prepared);
        plans.insert(
            request.egress_fence.clone(),
            PreparedPlan {
                request,
                prepared,
                binding: None,
                active: None,
                last_renewal: None,
            },
        );
        Ok(response)
    }

    pub fn status(
        &self,
        daemon_epoch: u64,
        fence: &EgressFence,
    ) -> Result<AttachmentStatusView, DaemonControlError> {
        self.ensure_epoch(daemon_epoch)?;
        let status = self
            .manager
            .status(self.daemon_epoch, fence)
            .map_err(DaemonControlError::Manager)?;
        let state = status.state();
        let active = matches!(
            state,
            AttachmentState::Active
                | AttachmentState::Revoking
                | AttachmentState::Revoked
                | AttachmentState::Drained
        )
        .then(|| {
            self.lock_plans()
                .get(fence)
                .and_then(|plan| plan.active.clone())
        })
        .flatten();
        Ok(AttachmentStatusView {
            daemon_epoch,
            egress_fence: fence.clone(),
            state,
            active,
        })
    }

    pub async fn install_stream(
        &self,
        stream: UnixStream,
        expected_peer_uid: u32,
    ) -> Result<ActiveInstallResponse, DaemonControlError> {
        let offer = receive_install_request(stream, expected_peer_uid)
            .await
            .map_err(DaemonControlError::Receive)?;
        self.validate_install_metadata(offer.request())?;
        let pending = offer
            .receive_listener()
            .await
            .map_err(DaemonControlError::Receive)?;
        self.install_pending(pending).await
    }

    pub async fn handle_control_stream(
        &self,
        stream: UnixStream,
        expected_peer_uid: u32,
    ) -> Result<Option<ActiveInstallResponse>, DaemonControlError> {
        match receive_control_request(stream, expected_peer_uid)
            .await
            .map_err(DaemonControlError::Receive)?
        {
            ControlRequest::EpochProbe(probe) => {
                probe
                    .respond(self.daemon_epoch.get())
                    .await
                    .map_err(DaemonControlError::EpochProbe)?;
                Ok(None)
            }
            ControlRequest::Install(offer) => {
                self.validate_install_metadata(offer.request())?;
                let pending = offer
                    .receive_listener()
                    .await
                    .map_err(DaemonControlError::Receive)?;
                self.install_pending(pending).await.map(Some)
            }
        }
    }

    pub async fn install_pending(
        &self,
        pending: PendingInstall,
    ) -> Result<ActiveInstallResponse, DaemonControlError> {
        let daemon = self.clone();
        tokio::spawn(async move { daemon.finish_pending_install(pending).await })
            .await
            .map_err(DaemonControlError::TransactionTask)?
    }

    async fn finish_pending_install(
        &self,
        mut pending: PendingInstall,
    ) -> Result<ActiveInstallResponse, DaemonControlError> {
        self.validate_install_metadata(pending.request())?;
        let request = pending.request().clone();
        let listener = pending
            .take_listener()
            .ok_or(DaemonControlError::MissingListener)?;
        let (prepared, binding) = self.install_material(&request)?;
        let active = self
            .manager
            .install(&prepared, binding, listener)
            .await
            .map_err(DaemonControlError::Manager)?;
        let response = ActiveInstallResponse::new(
            request.transfer_id().clone(),
            active.daemon_epoch().get(),
            active.fence().clone(),
            active.attachment_id().get(),
            active.proxy_address(),
            active.expires_at().daemon_millis(),
            active.activation_revision(),
        )
        .map_err(|_| DaemonControlError::InconsistentReceipt)?;
        if let Some(plan) = self.lock_plans().get_mut(active.fence()) {
            plan.active = Some(response.clone());
        }
        match pending.commit(response.clone()).await {
            Ok(response) => Ok(response),
            Err(error) => {
                if !error.commit_was_announced() {
                    self.manager
                        .revoke(&active)
                        .await
                        .map_err(DaemonControlError::Manager)?;
                }
                Err(DaemonControlError::Commit(error))
            }
        }
    }

    pub async fn revoke(
        &self,
        daemon_epoch: u64,
        fence: &EgressFence,
    ) -> Result<AttachmentStatusView, DaemonControlError> {
        self.ensure_epoch(daemon_epoch)?;
        match self
            .manager
            .status(self.daemon_epoch, fence)
            .map_err(DaemonControlError::Manager)?
        {
            AttachmentStatus::Absent => return Err(DaemonControlError::PlanNotFound),
            AttachmentStatus::Prepared(prepared) => {
                self.manager
                    .cancel(&prepared)
                    .await
                    .map_err(DaemonControlError::Manager)?;
            }
            AttachmentStatus::Installing(installing) => {
                self.manager
                    .cancel(installing.prepared())
                    .await
                    .map_err(DaemonControlError::Manager)?;
            }
            AttachmentStatus::Active(active)
            | AttachmentStatus::Revoking(active)
            | AttachmentStatus::Revoked(active)
            | AttachmentStatus::Drained(active) => {
                self.manager
                    .revoke(&active)
                    .await
                    .map_err(DaemonControlError::Manager)?;
            }
            AttachmentStatus::Cancelled(_) | AttachmentStatus::Released(_) => {}
        }
        self.status(daemon_epoch, fence)
    }

    pub fn renew(
        &self,
        request: RenewRouteRequest,
    ) -> Result<RenewedRouteResponse, DaemonControlError> {
        self.ensure_epoch(request.daemon_epoch)?;
        if request.lease_ttl > self.limits.max_lease {
            return Err(DaemonControlError::UnsupportedPolicy);
        }
        let lease_ttl_millis = u64::try_from(request.lease_ttl.as_millis())
            .map_err(|_| DaemonControlError::InvalidRenewRequest)?;
        let mut plans = self.lock_plans();
        let plan = plans
            .get_mut(&request.egress_fence)
            .ok_or(DaemonControlError::PlanNotFound)?;
        let wire_active = plan
            .active
            .clone()
            .ok_or(DaemonControlError::RenewalConflict)?;
        if wire_active.daemon_epoch() != request.daemon_epoch
            || wire_active.egress_fence() != &request.egress_fence
            || wire_active.attachment_id() != request.attachment_id
            || wire_active.activation_revision() != request.activation_revision
        {
            return Err(DaemonControlError::RenewalConflict);
        }
        let active = match self
            .manager
            .status(self.daemon_epoch, &request.egress_fence)
            .map_err(DaemonControlError::Manager)?
        {
            AttachmentStatus::Active(active) => active,
            _ => return Err(DaemonControlError::RenewalConflict),
        };
        if active.attachment_id().get() != request.attachment_id
            || active.activation_revision() != request.activation_revision
        {
            return Err(DaemonControlError::RenewalConflict);
        }

        if let Some(committed) = &plan.last_renewal {
            if request.renewal_sequence < committed.request.renewal_sequence {
                return Err(DaemonControlError::RenewalConflict);
            }
            if request.renewal_sequence == committed.request.renewal_sequence {
                if request != committed.request {
                    return Err(DaemonControlError::RenewalConflict);
                }
                self.manager
                    .renew(
                        &active,
                        MonotonicMillis::new(committed.response.expires_at_millis),
                    )
                    .map_err(DaemonControlError::Manager)?;
                return Ok(committed.response.clone());
            }
            if committed.request.renewal_sequence.checked_add(1) != Some(request.renewal_sequence) {
                return Err(DaemonControlError::RenewalConflict);
            }
        } else if request.renewal_sequence != 1 {
            return Err(DaemonControlError::RenewalConflict);
        }

        let expires_at_millis = self
            .manager
            .now()
            .value()
            .checked_add(lease_ttl_millis)
            .ok_or(DaemonControlError::InvalidRenewRequest)?;
        self.manager
            .renew(&active, MonotonicMillis::new(expires_at_millis))
            .map_err(DaemonControlError::Manager)?;
        let response = RenewedRouteResponse {
            renewal_sequence: request.renewal_sequence,
            daemon_epoch: request.daemon_epoch,
            egress_fence: request.egress_fence.clone(),
            attachment_id: request.attachment_id,
            activation_revision: request.activation_revision,
            expires_at_millis,
        };
        plan.active = Some(
            ActiveInstallResponse::new(
                wire_active.transfer_id().clone(),
                wire_active.daemon_epoch(),
                wire_active.egress_fence().clone(),
                wire_active.attachment_id(),
                wire_active.proxy_address(),
                expires_at_millis,
                wire_active.activation_revision(),
            )
            .map_err(|_| DaemonControlError::InconsistentReceipt)?,
        );
        plan.last_renewal = Some(CommittedRenewal {
            request,
            response: response.clone(),
        });
        Ok(response)
    }

    pub async fn shutdown(&self) -> Result<(), DaemonControlError> {
        self.manager
            .shutdown()
            .await
            .map_err(DaemonControlError::Manager)
    }

    fn ensure_epoch(&self, received: u64) -> Result<(), DaemonControlError> {
        if received != self.daemon_epoch.get() {
            return Err(DaemonControlError::DaemonEpochMismatch {
                expected: self.daemon_epoch.get(),
                received,
            });
        }
        Ok(())
    }

    fn validate_install_metadata(
        &self,
        request: &browserd_egress_control::InstallRequest,
    ) -> Result<(), DaemonControlError> {
        self.ensure_epoch(request.daemon_epoch())?;
        let plans = self.lock_plans();
        let plan = plans
            .get(request.egress_fence())
            .ok_or(DaemonControlError::PlanNotFound)?;
        if request.binding_digest() != &plan.request.binding_digest
            || request.prepare_revision() != plan.prepared.prepare_revision()
            || request.daemon_epoch() != plan.prepared.daemon_epoch().get()
        {
            return Err(DaemonControlError::InstallMetadataMismatch);
        }
        Ok(())
    }

    fn install_material(
        &self,
        request: &browserd_egress_control::InstallRequest,
    ) -> Result<(PreparedAttachmentReceipt, RouteBinding), DaemonControlError> {
        let mut plans = self.lock_plans();
        let plan = plans
            .get_mut(request.egress_fence())
            .ok_or(DaemonControlError::PlanNotFound)?;
        if plan.binding.is_none() {
            let ttl_millis = u64::try_from(plan.request.lease_ttl.as_millis())
                .map_err(|_| DaemonControlError::InvalidPrepareRequest)?;
            let expires_at = self
                .manager
                .now()
                .value()
                .checked_add(ttl_millis)
                .map(MonotonicMillis::new)
                .ok_or(DaemonControlError::InvalidPrepareRequest)?;
            plan.binding = Some(RouteBinding::new(
                plan.request.tenant_id.clone(),
                plan.request.egress_fence.session_id().clone(),
                plan.request.egress_fence.shard().shard_id().clone(),
                plan.request
                    .egress_fence
                    .shard()
                    .owner()
                    .worker_epoch()
                    .get(),
                EgressPolicy::public_web_default(),
                self.limits.quotas.clone(),
                expires_at,
            ));
        }
        Ok((
            plan.prepared.clone(),
            plan.binding
                .clone()
                .ok_or(DaemonControlError::InconsistentReceipt)?,
        ))
    }

    fn lock_plans(&self) -> MutexGuard<'_, HashMap<EgressFence, PreparedPlan>> {
        self.plans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn prepared_response(prepared: &PreparedAttachmentReceipt) -> PreparedRouteResponse {
    PreparedRouteResponse {
        daemon_epoch: prepared.daemon_epoch().get(),
        egress_fence: prepared.fence().clone(),
        binding_digest: *prepared.binding_digest().as_bytes(),
        prepare_revision: prepared.prepare_revision(),
    }
}

#[derive(Debug)]
pub enum DaemonControlError {
    InvalidLimits,
    InvalidPrepareRequest,
    InvalidRenewRequest,
    UnsupportedPolicy,
    DaemonEpochMismatch { expected: u64, received: u64 },
    PlanConflict,
    PlanCapacityExceeded,
    PlanNotFound,
    InstallMetadataMismatch,
    RenewalConflict,
    MissingListener,
    InconsistentReceipt,
    Manager(AttachmentManagerError),
    Receive(ReceiveInstallError),
    EpochProbe(EpochProbeError),
    Commit(ServerCommitError),
    TransactionTask(tokio::task::JoinError),
}

impl fmt::Display for DaemonControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("egress daemon limits are invalid"),
            Self::InvalidPrepareRequest => formatter.write_str("prepare request is invalid"),
            Self::InvalidRenewRequest => formatter.write_str("renew request is invalid"),
            Self::UnsupportedPolicy => formatter.write_str("egress policy is unsupported"),
            Self::DaemonEpochMismatch { expected, received } => write!(
                formatter,
                "daemon epoch mismatch: expected {expected}, received {received}"
            ),
            Self::PlanConflict => formatter.write_str("prepared route conflicts with its fence"),
            Self::PlanCapacityExceeded => formatter.write_str("prepared route capacity exceeded"),
            Self::PlanNotFound => formatter.write_str("prepared route does not exist"),
            Self::InstallMetadataMismatch => {
                formatter.write_str("install metadata does not match the prepared route")
            }
            Self::RenewalConflict => {
                formatter.write_str("route renewal conflicts with committed state")
            }
            Self::MissingListener => formatter.write_str("listener capability is missing"),
            Self::InconsistentReceipt => formatter.write_str("egress receipt is inconsistent"),
            Self::Manager(error) => write!(formatter, "attachment manager failed: {error}"),
            Self::Receive(error) => write!(formatter, "listener receipt failed: {error}"),
            Self::EpochProbe(error) => write!(formatter, "epoch probe failed: {error}"),
            Self::Commit(error) => write!(formatter, "listener commit failed: {error}"),
            Self::TransactionTask(error) => {
                write!(formatter, "listener transaction task failed: {error}")
            }
        }
    }
}

impl Error for DaemonControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manager(error) => Some(error),
            Self::Receive(error) => Some(error),
            Self::EpochProbe(error) => Some(error),
            Self::Commit(error) => Some(error),
            Self::TransactionTask(error) => Some(error),
            _ => None,
        }
    }
}
