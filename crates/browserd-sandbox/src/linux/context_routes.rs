use super::*;
use crate::{
    ContextEgressBinding, ContextEgressReleaseReceipt, ContextEgressRequest, ContextRoutePhase,
};
use tokio::time::Instant;

#[derive(Clone)]
pub(super) struct ContextRuntimeRoute {
    pub request: ContextEgressRequest,
    pub reservation: ShardEgressReservation,
    pub lease: Option<ShardIngressLease>,
    pub valid_until: Instant,
    pub phase: ContextRoutePhase,
}

impl<F: SandboxFilesystem, P: LinuxProcessBackend, E: EgressRouteBackend>
    LinuxSandboxBackend<F, P, E>
{
    pub(super) async fn context_journal_phase(
        &self,
        request: &ContextEgressRequest,
        phase: ContextRoutePhase,
        binding: Option<DedicatedEgressProxyBinding>,
    ) -> Result<(), SandboxError> {
        let journal = self
            .prepared_journal
            .clone()
            .ok_or_else(|| SandboxError::Backend("shared routes require durable journal".into()))?;
        let request = request.clone();
        tokio::task::spawn_blocking(move || {
            journal.set_context_route_phase(&request, phase, binding)
        })
        .await
        .map_err(|_| SandboxError::Backend("context journal task stopped".into()))?
        .map_err(|_| SandboxError::Backend("context journal phase failed".into()))
    }
    async fn context_reservation(
        &self,
        request: &ContextEgressRequest,
        cancelling: bool,
    ) -> Result<ShardEgressReservation, SandboxError> {
        let journal = self
            .prepared_journal
            .clone()
            .ok_or_else(|| SandboxError::Backend("shared routes require durable journal".into()))?;
        let epoch = self
            .egress_daemon_epoch
            .ok_or(SandboxError::LaunchFenceMismatch)?;
        let owned = request.clone();
        let row = tokio::task::spawn_blocking(move || {
            journal.reserve_context_route(owned, LeaseId::new(), epoch, cancelling)
        })
        .await
        .map_err(|_| SandboxError::Backend("context journal task stopped".into()))?
        .map_err(|_| SandboxError::Backend("context route reservation failed".into()))?;
        if !cancelling && row.phase() != ContextRoutePhase::Intent {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(ShardEgressReservation {
            shared: true,
            initial_ttl: None,
            fence: ShardEgressFence::new(
                request.egress().egress_fence().shard().shard_id().clone(),
                request.placement().worker_epoch,
            ),
            generation: row.reservation_generation().clone(),
            tenant_id: Some(request.tenant_id().clone()),
            dedicated_egress: Some(request.egress().clone()),
        })
    }
    fn context_runtime(
        &self,
        handle: &SandboxHandle,
        request: &ContextEgressRequest,
    ) -> Result<(LinuxRuntime, Option<ContextRuntimeRoute>), SandboxError> {
        let runtimes = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
        let runtime = runtimes
            .get(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        Self::validate_handle(runtime, handle)?;
        request.validate_for(&runtime.launch_spec)?;
        let existing = runtime
            .context_routes
            .get(request.egress().egress_fence())
            .cloned();
        if existing.as_ref().is_some_and(|row| &row.request != request) {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok((runtime.clone(), existing))
    }
    pub(super) fn save_context_runtime(
        &self,
        handle: &SandboxHandle,
        row: ContextRuntimeRoute,
    ) -> Result<(), SandboxError> {
        let mut runtimes = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
        let runtime = runtimes
            .get_mut(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        Self::validate_handle(runtime, handle)?;
        runtime
            .context_routes
            .insert(row.request.egress().egress_fence().clone(), row);
        Ok(())
    }
    pub(super) async fn attach_context_route(
        &self,
        handle: &SandboxHandle,
        request: &ContextEgressRequest,
        sandboxd_epoch: u64,
        max_ttl: Duration,
    ) -> Result<ContextEgressBinding, SandboxError> {
        let operation = self.runtime_cleanup_operation(handle)?;
        let _guard = operation.lock().await;
        let (runtime, existing) = self.context_runtime(handle, request)?;
        if !runtime.gate_released
            || runtime.egress_revoked
            || runtime.egress_released
            || runtime.process_released
            || runtime.namespaces_cleaned
        {
            return Err(SandboxError::ShardNotFound);
        }
        let namespace = runtime
            ._network_namespace
            .as_ref()
            .ok_or(SandboxError::ShardNotFound)?;
        if !self
            .process
            .identity_matches(&runtime.backend_token, runtime.identity)
            .await?
            || !self
                .process
                .network_namespace_matches(&runtime.backend_token, runtime.identity, namespace)
                .await?
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        let row = if let Some(row) = existing {
            if row.phase != ContextRoutePhase::Active || row.valid_until <= Instant::now() {
                return Err(SandboxError::InvalidEgressLease);
            }
            row
        } else {
            let mut reservation = self.context_reservation(request, false).await?;
            reservation.initial_ttl = Some(request.egress().initial_lease_ttl().min(max_ttl));
            let mut row = ContextRuntimeRoute {
                request: request.clone(),
                reservation,
                lease: None,
                valid_until: Instant::now() + request.egress().initial_lease_ttl().min(max_ttl),
                phase: ContextRoutePhase::Intent,
            };
            self.save_context_runtime(handle, row.clone())?;
            let install = async {
                self.egress.prepare(&row.reservation).await?;
                let receipt = self.egress.attach(&row.reservation, namespace).await?;
                let lease = ShardIngressLease::from_attachment(
                    row.reservation.clone(),
                    namespace.identity(),
                    receipt,
                );
                row.lease = Some(lease.clone());
                self.save_context_runtime(handle, row.clone())?;
                if !self.egress.is_active(&lease).await? || row.valid_until <= Instant::now() {
                    return Err(SandboxError::InvalidEgressLease);
                }
                let binding = DedicatedEgressProxyBinding::from_lease(&lease)?;
                self.context_journal_phase(request, ContextRoutePhase::Active, Some(binding))
                    .await?;
                row.phase = ContextRoutePhase::Active;
                self.save_context_runtime(handle, row.clone())?;
                Ok::<(), SandboxError>(())
            }
            .await;
            if let Err(error) = install {
                let _ = self.release_context_route_locked(handle, request).await;
                return Err(error);
            }
            row
        };
        let lease = row
            .lease
            .as_ref()
            .ok_or(SandboxError::LaunchFenceMismatch)?;
        if !self.egress.is_active(lease).await? {
            return Err(SandboxError::InvalidEgressLease);
        }
        ContextEgressBinding::new(
            request.clone(),
            sandboxd_epoch,
            self.egress_daemon_epoch
                .ok_or(SandboxError::LaunchFenceMismatch)?,
            DedicatedEgressProxyBinding::from_lease(lease)?,
            row.valid_until
                .saturating_duration_since(Instant::now())
                .min(max_ttl)
                .min(request.egress().initial_lease_ttl()),
        )
    }
    pub(super) async fn release_context_route_locked(
        &self,
        handle: &SandboxHandle,
        request: &ContextEgressRequest,
    ) -> Result<(), SandboxError> {
        let (_, existing) = self.context_runtime(handle, request)?;
        let mut row = if let Some(row) = existing {
            row
        } else {
            ContextRuntimeRoute {
                request: request.clone(),
                reservation: self.context_reservation(request, true).await?,
                lease: None,
                valid_until: Instant::now(),
                phase: ContextRoutePhase::Releasing,
            }
        };
        if row.phase == ContextRoutePhase::Released {
            return Ok(());
        }
        self.context_journal_phase(request, ContextRoutePhase::Releasing, None)
            .await?;
        row.phase = ContextRoutePhase::Releasing;
        self.save_context_runtime(handle, row.clone())?;
        if let Some(lease) = &row.lease {
            self.egress.revoke(lease).await?;
            self.egress.release(lease).await?;
        } else {
            self.egress.cancel_reservation(&row.reservation).await?;
            self.egress.release_reservation(&row.reservation).await?;
        }
        self.context_journal_phase(request, ContextRoutePhase::Released, None)
            .await?;
        row.phase = ContextRoutePhase::Released;
        self.save_context_runtime(handle, row)
    }
    pub(super) async fn release_context_route(
        &self,
        handle: &SandboxHandle,
        request: &ContextEgressRequest,
        sandboxd_epoch: u64,
    ) -> Result<ContextEgressReleaseReceipt, SandboxError> {
        let operation = self.runtime_cleanup_operation(handle)?;
        let _guard = operation.lock().await;
        self.release_context_route_locked(handle, request).await?;
        ContextEgressReleaseReceipt::new(
            request.clone(),
            sandboxd_epoch,
            self.egress_daemon_epoch
                .ok_or(SandboxError::LaunchFenceMismatch)?,
        )
    }
    pub(super) async fn renew_context_route(
        &self,
        handle: &SandboxHandle,
        binding: &ContextEgressBinding,
        ttl: Duration,
    ) -> Result<(), SandboxError> {
        let operation = self.runtime_cleanup_operation(handle)?;
        let _guard = operation.lock().await;
        let (_, row) = self.context_runtime(handle, binding.request())?;
        let mut row = row.ok_or(SandboxError::ShardNotFound)?;
        let lease = row.lease.as_ref().ok_or(SandboxError::ShardNotFound)?;
        if row.phase != ContextRoutePhase::Active
            || binding.egress_daemon_epoch()
                != self
                    .egress_daemon_epoch
                    .ok_or(SandboxError::LaunchFenceMismatch)?
            || DedicatedEgressProxyBinding::from_lease(lease)? != *binding.proxy_binding()
            || row.valid_until <= Instant::now()
            || ttl.is_zero()
            || ttl > MAX_DEDICATED_EGRESS_LEASE_TTL
        {
            return Err(SandboxError::InvalidEgressLease);
        }
        let deadline = Instant::now() + ttl;
        self.egress.renew(lease, ttl).await?;
        row.valid_until = deadline;
        self.save_context_runtime(handle, row)
    }
}
