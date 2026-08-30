use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::EgressFence;
use nix::sys::stat::fstat;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    AcceptedRouteIngress, ActiveAttachmentReceipt, AttachmentError, AttachmentExpiry,
    AttachmentRegistry, AttachmentStatus, BindingDigest, CancelledAttachmentReceipt, DaemonEpoch,
    InstallReceipt, InstallingAttachmentReceipt, MonotonicMillis, PreparedAttachmentReceipt,
    ReleasedAttachmentReceipt, RouteBinding, RouteClaim, RouteEndpoint, RouteError,
    RouteIngressError, RouteIngressListener, RouteRegistry,
};

pub type IngressHandlerError = Box<dyn Error + Send + Sync + 'static>;

#[async_trait]
pub trait AcceptedIngressHandler: Send + Sync + 'static {
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError>;
}

#[async_trait]
impl<R, C> AcceptedIngressHandler for crate::DataPlane<R, C>
where
    R: crate::Resolver,
    C: crate::Connector,
{
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
        self.serve_accepted_connection(ingress)
            .await
            .map_err(|error| Box::new(error) as IngressHandlerError)
    }
}

#[derive(Clone)]
pub struct AttachmentManager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    clock: ManagerClock,
    handler: Arc<dyn AcceptedIngressHandler>,
    routes: RouteRegistry,
    state: Mutex<ManagerState>,
}

struct ManagerState {
    attachments: AttachmentRegistry,
    records: HashMap<EgressFence, ManagedAttachment>,
    next_endpoint: u64,
    shutting_down: bool,
}

struct ManagedAttachment {
    prepared: PreparedAttachmentReceipt,
    phase: ManagedPhase,
    descriptor: Option<DescriptorIdentity>,
    claim: Option<RouteClaim>,
    binding: Option<RouteBinding>,
    installing: Option<InstallingAttachmentReceipt>,
    cancelled: Option<CancelledAttachmentReceipt>,
    active: Option<ActiveAttachmentReceipt>,
    released: Option<ReleasedAttachmentReceipt>,
    cancellation: CancellationToken,
    actor: Option<JoinHandle<()>>,
    lease_deadline: watch::Sender<MonotonicMillis>,
    changed: watch::Sender<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedPhase {
    Prepared,
    Adopting,
    Installing,
    Active,
    Cancelling,
    Revoking,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy)]
struct ManagerClock {
    origin: tokio::time::Instant,
}

impl ManagerClock {
    fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
        }
    }

    fn now(self) -> MonotonicMillis {
        let elapsed = self.origin.elapsed().as_millis();
        let elapsed = u64::try_from(elapsed).unwrap_or(u64::MAX);
        MonotonicMillis::new(elapsed)
    }
}

impl AttachmentManager {
    #[must_use]
    pub fn new(
        daemon_epoch: DaemonEpoch,
        max_lease: Duration,
        handler: Arc<dyn AcceptedIngressHandler>,
    ) -> Self {
        Self::with_registry(daemon_epoch, RouteRegistry::new(max_lease), handler)
    }

    /// Builds the lifecycle manager and data plane around one authoritative
    /// route registry.
    #[must_use]
    pub fn with_registry(
        daemon_epoch: DaemonEpoch,
        routes: RouteRegistry,
        handler: Arc<dyn AcceptedIngressHandler>,
    ) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                clock: ManagerClock::new(),
                handler,
                routes,
                state: Mutex::new(ManagerState {
                    attachments: AttachmentRegistry::new(daemon_epoch),
                    records: HashMap::new(),
                    next_endpoint: 1,
                    shutting_down: false,
                }),
            }),
        }
    }

    #[must_use]
    pub fn now(&self) -> MonotonicMillis {
        self.inner.clock.now()
    }

    pub fn prepare(
        &self,
        fence: EgressFence,
        binding_digest: BindingDigest,
    ) -> Result<PreparedAttachmentReceipt, AttachmentManagerError> {
        let mut state = self.inner.lock_state();
        if state.shutting_down {
            return Err(AttachmentManagerError::ShuttingDown);
        }
        let daemon_epoch = state.attachments.daemon_epoch();
        let prepared = state
            .attachments
            .prepare(daemon_epoch, fence.clone(), binding_digest)
            .map_err(AttachmentManagerError::Attachment)?;
        state
            .records
            .entry(fence)
            .or_insert_with(|| ManagedAttachment::new(prepared.clone()));
        Ok(prepared)
    }

    pub fn status(
        &self,
        daemon_epoch: DaemonEpoch,
        fence: &EgressFence,
    ) -> Result<AttachmentStatus, AttachmentManagerError> {
        self.inner
            .lock_state()
            .attachments
            .status(daemon_epoch, fence)
            .map_err(AttachmentManagerError::Attachment)
    }

    pub async fn install(
        &self,
        prepared: &PreparedAttachmentReceipt,
        binding: RouteBinding,
        descriptor: OwnedFd,
    ) -> Result<ActiveAttachmentReceipt, AttachmentManagerError> {
        let descriptor_identity = descriptor_identity(&descriptor)?;
        let fence = prepared.fence().clone();
        let (claim, cancellation) = loop {
            let action = {
                let mut state = self.inner.lock_state();
                if state.shutting_down {
                    return Err(AttachmentManagerError::ShuttingDown);
                }
                let phase = state
                    .records
                    .get(&fence)
                    .filter(|record| record.prepared == *prepared)
                    .map(|record| record.phase)
                    .ok_or(AttachmentManagerError::Attachment(
                        AttachmentError::StaleReceipt,
                    ))?;
                match phase {
                    ManagedPhase::Prepared => {
                        let endpoint = state.allocate_endpoint()?;
                        let claim = RouteClaim::new(endpoint, fence.clone());
                        let record = state
                            .records
                            .get_mut(&fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?;
                        record.phase = ManagedPhase::Adopting;
                        record.descriptor = Some(descriptor_identity);
                        record.claim = Some(claim.clone());
                        record.binding = Some(binding.clone());
                        record.signal();
                        InstallAction::Own(claim, record.cancellation.clone())
                    }
                    ManagedPhase::Adopting | ManagedPhase::Installing => {
                        let record = state
                            .records
                            .get(&fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?;
                        ensure_exact_install(record, descriptor_identity, &binding)?;
                        InstallAction::Wait(record.changed.subscribe())
                    }
                    ManagedPhase::Active => {
                        let record = state
                            .records
                            .get(&fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?;
                        ensure_exact_install(record, descriptor_identity, &binding)?;
                        InstallAction::Return(
                            record
                                .active
                                .clone()
                                .ok_or(AttachmentManagerError::InconsistentState)?,
                        )
                    }
                    ManagedPhase::Cancelling | ManagedPhase::Revoking | ManagedPhase::Released => {
                        InstallAction::Cancelled
                    }
                }
            };
            match action {
                InstallAction::Own(claim, cancellation) => break (claim, cancellation),
                InstallAction::Wait(mut changed) => {
                    let _ = changed.changed().await;
                }
                InstallAction::Return(active) => return Ok(active),
                InstallAction::Cancelled => {
                    return Err(AttachmentManagerError::InstallCancelled);
                }
            }
        };

        let listener = match RouteIngressListener::from_owned_fd(
            descriptor,
            claim.clone(),
            self.inner.routes.clone(),
        ) {
            Ok(listener) => listener,
            Err(error) => {
                self.inner.finish_cancelled_install(&fence, &claim);
                return Err(AttachmentManagerError::Ingress(error));
            }
        };
        let proxy_address = listener.local_addr();
        let expires_at = AttachmentExpiry::new(binding.expires_at().value());

        let begin_install = {
            let mut state = self.inner.lock_state();
            (|| {
                let phase = state
                    .records
                    .get(&fence)
                    .map(|record| record.phase)
                    .ok_or(AttachmentManagerError::InconsistentState)?;
                if phase != ManagedPhase::Adopting || cancellation.is_cancelled() {
                    return Err(AttachmentManagerError::InstallCancelled);
                }
                let install = state
                    .attachments
                    .begin_install(prepared, proxy_address, expires_at)
                    .map_err(AttachmentManagerError::Attachment)?;
                let InstallReceipt::Installing(installing) = install else {
                    return Err(AttachmentManagerError::InconsistentState);
                };
                let record = state
                    .records
                    .get_mut(&fence)
                    .ok_or(AttachmentManagerError::InconsistentState)?;
                record.installing = Some(installing);
                record.phase = ManagedPhase::Installing;
                record.signal();
                Ok(())
            })()
        };
        if let Err(error) = begin_install {
            drop(listener);
            self.inner.finish_cancelled_install(&fence, &claim);
            return Err(error);
        }

        if let Err(error) = self.inner.routes.prepare_shard(fence.shard()) {
            drop(listener);
            self.inner.finish_cancelled_install(&fence, &claim);
            return Err(AttachmentManagerError::Route(error));
        }
        if let Err(error) = self.inner.routes.bind(&claim, binding.clone(), self.now()) {
            drop(listener);
            self.inner.finish_cancelled_install(&fence, &claim);
            return Err(AttachmentManagerError::Route(error));
        }

        let has_remaining_lease = binding
            .expires_at()
            .value()
            .checked_sub(self.now().value())
            .is_some_and(|ttl| ttl > 0);
        if !has_remaining_lease {
            drop(listener);
            self.inner.finish_cancelled_install(&fence, &claim);
            return Err(AttachmentManagerError::InstallCancelled);
        }
        let mut listener = Some(listener);
        let result = {
            let mut state = self.inner.lock_state();
            let phase = state
                .records
                .get(&fence)
                .map(|record| record.phase)
                .ok_or(AttachmentManagerError::InconsistentState)?;
            if phase != ManagedPhase::Installing || cancellation.is_cancelled() {
                None
            } else {
                let installing = state
                    .records
                    .get(&fence)
                    .and_then(|record| record.installing.clone())
                    .ok_or(AttachmentManagerError::InconsistentState)?;
                let active = state
                    .attachments
                    .complete_install(&installing)
                    .map_err(AttachmentManagerError::Attachment)?;
                let listener = listener
                    .take()
                    .ok_or(AttachmentManagerError::InconsistentState)?;
                let record = state
                    .records
                    .get_mut(&fence)
                    .ok_or(AttachmentManagerError::InconsistentState)?;
                record.active = Some(active.clone());
                record.phase = ManagedPhase::Active;
                record.lease_deadline.send_replace(binding.expires_at());
                let lease_deadline = record.lease_deadline.subscribe();
                let actor = tokio::spawn(run_listener_actor(
                    Arc::downgrade(&self.inner),
                    fence.clone(),
                    active.clone(),
                    listener,
                    cancellation.clone(),
                    lease_deadline,
                ));
                record.actor = Some(actor);
                record.signal();
                Some(active)
            }
        };
        if let Some(active) = result {
            return Ok(active);
        }

        drop(listener);
        self.inner.finish_cancelled_install(&fence, &claim);
        Err(AttachmentManagerError::InstallCancelled)
    }

    pub fn renew(
        &self,
        active: &ActiveAttachmentReceipt,
        new_expires_at: MonotonicMillis,
    ) -> Result<(), AttachmentManagerError> {
        let fence = active.fence();
        let mut state = self.inner.lock_state();
        if state.shutting_down {
            return Err(AttachmentManagerError::ShuttingDown);
        }
        let phase = state
            .records
            .get(fence)
            .filter(|record| record.active.as_ref() == Some(active))
            .map(|record| record.phase)
            .ok_or(AttachmentManagerError::Attachment(
                AttachmentError::StaleReceipt,
            ))?;
        if phase != ManagedPhase::Active {
            return Err(AttachmentManagerError::Attachment(
                AttachmentError::InvalidTransition {
                    state: state
                        .attachments
                        .state(active.daemon_epoch(), fence)
                        .map_err(AttachmentManagerError::Attachment)?,
                    operation: "renew attachment",
                },
            ));
        }
        let claim = state
            .records
            .get(fence)
            .and_then(|record| record.claim.clone())
            .ok_or(AttachmentManagerError::InconsistentState)?;
        self.inner
            .routes
            .renew(&claim, self.inner.clock.now(), new_expires_at)
            .map_err(AttachmentManagerError::Route)?;
        let record = state
            .records
            .get_mut(fence)
            .ok_or(AttachmentManagerError::InconsistentState)?;
        record.lease_deadline.send_replace(new_expires_at);
        record.signal();
        Ok(())
    }

    pub async fn cancel(
        &self,
        prepared: &PreparedAttachmentReceipt,
    ) -> Result<ReleasedAttachmentReceipt, AttachmentManagerError> {
        let fence = prepared.fence();
        loop {
            let action = {
                let mut state = self.inner.lock_state();
                let phase = state
                    .records
                    .get(fence)
                    .filter(|record| record.prepared == *prepared)
                    .map(|record| record.phase)
                    .ok_or(AttachmentManagerError::Attachment(
                        AttachmentError::StaleReceipt,
                    ))?;
                match phase {
                    ManagedPhase::Prepared => {
                        let cancelled = state
                            .attachments
                            .cancel(prepared)
                            .map_err(AttachmentManagerError::Attachment)?;
                        let released = state
                            .attachments
                            .release_cancelled(&cancelled)
                            .map_err(AttachmentManagerError::Attachment)?;
                        let record = state
                            .records
                            .get_mut(fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?;
                        record.cancelled = Some(cancelled);
                        record.released = Some(released.clone());
                        record.phase = ManagedPhase::Released;
                        record.cancellation.cancel();
                        record.signal();
                        CancelAction::Return(released)
                    }
                    ManagedPhase::Adopting | ManagedPhase::Installing => {
                        let cancelled = state
                            .attachments
                            .cancel(prepared)
                            .map_err(AttachmentManagerError::Attachment)?;
                        let record = state
                            .records
                            .get_mut(fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?;
                        record.cancelled = Some(cancelled);
                        record.phase = ManagedPhase::Cancelling;
                        record.cancellation.cancel();
                        let changed = record.changed.subscribe();
                        record.signal();
                        CancelAction::Wait(changed)
                    }
                    ManagedPhase::Cancelling => CancelAction::Wait(
                        state
                            .records
                            .get(fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?
                            .changed
                            .subscribe(),
                    ),
                    ManagedPhase::Released => CancelAction::Return(
                        state
                            .records
                            .get(fence)
                            .and_then(|record| record.released.clone())
                            .ok_or(AttachmentManagerError::InconsistentState)?,
                    ),
                    ManagedPhase::Active | ManagedPhase::Revoking => {
                        return Err(AttachmentManagerError::Attachment(
                            AttachmentError::InvalidTransition {
                                state: state
                                    .attachments
                                    .state(prepared.daemon_epoch(), prepared.fence())
                                    .map_err(AttachmentManagerError::Attachment)?,
                                operation: "cancel active attachment",
                            },
                        ));
                    }
                }
            };
            match action {
                CancelAction::Return(released) => return Ok(released),
                CancelAction::Wait(mut changed) => {
                    let _ = changed.changed().await;
                }
            }
        }
    }

    pub async fn revoke(
        &self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<ReleasedAttachmentReceipt, AttachmentManagerError> {
        let fence = active.fence();
        loop {
            let action = {
                let mut state = self.inner.lock_state();
                let phase = state
                    .records
                    .get(fence)
                    .filter(|record| record.active.as_ref() == Some(active))
                    .map(|record| record.phase)
                    .ok_or(AttachmentManagerError::Attachment(
                        AttachmentError::StaleReceipt,
                    ))?;
                match phase {
                    ManagedPhase::Active => {
                        state
                            .attachments
                            .begin_revoke(active)
                            .map_err(AttachmentManagerError::Attachment)?;
                        let _ = self.inner.routes.revoke(
                            state
                                .records
                                .get(fence)
                                .and_then(|record| record.claim.as_ref())
                                .ok_or(AttachmentManagerError::InconsistentState)?,
                        );
                        let record = state
                            .records
                            .get_mut(fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?;
                        record.phase = ManagedPhase::Revoking;
                        record.cancellation.cancel();
                        record.signal();
                        RevokeAction::Own(record.actor.take())
                    }
                    ManagedPhase::Revoking => RevokeAction::Wait(
                        state
                            .records
                            .get(fence)
                            .ok_or(AttachmentManagerError::InconsistentState)?
                            .changed
                            .subscribe(),
                    ),
                    ManagedPhase::Released => {
                        return state
                            .records
                            .get(fence)
                            .and_then(|record| record.released.clone())
                            .ok_or(AttachmentManagerError::InconsistentState);
                    }
                    _ => {
                        return Err(AttachmentManagerError::Attachment(
                            AttachmentError::InvalidTransition {
                                state: state
                                    .attachments
                                    .state(active.daemon_epoch(), fence)
                                    .map_err(AttachmentManagerError::Attachment)?,
                                operation: "revoke attachment",
                            },
                        ));
                    }
                }
            };
            match action {
                RevokeAction::Own(actor) => {
                    if let Some(actor) = actor {
                        let _ = actor.await;
                    }
                    return self.inner.finish_active_revoke(fence, active);
                }
                RevokeAction::Wait(mut changed) => {
                    let _ = changed.changed().await;
                }
            }
        }
    }

    pub async fn shutdown(&self) -> Result<(), AttachmentManagerError> {
        {
            self.inner.lock_state().shutting_down = true;
        }
        loop {
            let pending = {
                let state = self.inner.lock_state();
                state
                    .records
                    .values()
                    .find_map(|record| match record.phase {
                        ManagedPhase::Prepared
                        | ManagedPhase::Adopting
                        | ManagedPhase::Installing
                        | ManagedPhase::Cancelling => {
                            Some(ShutdownTarget::Cancel(record.prepared.clone()))
                        }
                        ManagedPhase::Active | ManagedPhase::Revoking => {
                            record.active.clone().map(ShutdownTarget::Revoke)
                        }
                        ManagedPhase::Released => None,
                    })
            };
            match pending {
                Some(ShutdownTarget::Cancel(prepared)) => {
                    self.cancel(&prepared).await?;
                }
                Some(ShutdownTarget::Revoke(active)) => {
                    self.revoke(&active).await?;
                }
                None => return Ok(()),
            }
        }
    }
}

enum ShutdownTarget {
    Cancel(PreparedAttachmentReceipt),
    Revoke(ActiveAttachmentReceipt),
}

enum InstallAction {
    Own(RouteClaim, CancellationToken),
    Wait(watch::Receiver<u64>),
    Return(ActiveAttachmentReceipt),
    Cancelled,
}

enum CancelAction {
    Return(ReleasedAttachmentReceipt),
    Wait(watch::Receiver<u64>),
}

enum RevokeAction {
    Own(Option<JoinHandle<()>>),
    Wait(watch::Receiver<u64>),
}

enum ActorRevokeAction {
    Own,
    RetryExpiry,
    Stop,
}

impl ManagerInner {
    fn lock_state(&self) -> MutexGuard<'_, ManagerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn finish_cancelled_install(&self, fence: &EgressFence, claim: &RouteClaim) {
        let cancelled = {
            let mut state = self.lock_state();
            let Some(record) = state.records.get(fence) else {
                return;
            };
            if record.phase == ManagedPhase::Released {
                return;
            }
            let prepared = record.prepared.clone();
            let installing = record.installing.clone();
            let cancelled = match record.cancelled.clone() {
                Some(cancelled) => cancelled,
                None => match state.attachments.cancel(&prepared) {
                    Ok(cancelled) => cancelled,
                    Err(_) => return,
                },
            };
            if let Some(installing) = installing {
                let _ = state
                    .attachments
                    .acknowledge_cancelled_listener_closed(&installing);
            }
            cancelled
        };

        let _ = self.routes.revoke(claim);
        let _ = self.routes.revoke_shard(fence.shard());
        let _ = self.routes.release_shard(fence.shard());

        let mut state = self.lock_state();
        let Ok(released) = state.attachments.release_cancelled(&cancelled) else {
            return;
        };
        if let Some(record) = state.records.get_mut(fence) {
            record.cancelled = Some(cancelled);
            record.released = Some(released);
            record.phase = ManagedPhase::Released;
            record.cancellation.cancel();
            record.actor.take();
            record.signal();
        }
    }

    fn start_actor_revoke(
        &self,
        fence: &EgressFence,
        active: &ActiveAttachmentReceipt,
        observed_expiry: Option<MonotonicMillis>,
    ) -> ActorRevokeAction {
        let mut state = self.lock_state();
        let Some(record) = state.records.get(fence) else {
            return ActorRevokeAction::Stop;
        };
        if record.phase != ManagedPhase::Active || record.active.as_ref() != Some(active) {
            return ActorRevokeAction::Stop;
        }
        if let Some(observed_expiry) = observed_expiry {
            let current_expiry = *record.lease_deadline.borrow();
            if current_expiry != observed_expiry || current_expiry > self.clock.now() {
                return ActorRevokeAction::RetryExpiry;
            }
        }
        if state.attachments.begin_revoke(active).is_err() {
            return ActorRevokeAction::Stop;
        }
        if let Some(claim) = state
            .records
            .get(fence)
            .and_then(|record| record.claim.as_ref())
        {
            let _ = self.routes.revoke(claim);
        }
        let Some(record) = state.records.get_mut(fence) else {
            return ActorRevokeAction::Stop;
        };
        record.phase = ManagedPhase::Revoking;
        record.cancellation.cancel();
        record.actor.take();
        record.signal();
        ActorRevokeAction::Own
    }

    fn finish_active_revoke(
        &self,
        fence: &EgressFence,
        active: &ActiveAttachmentReceipt,
    ) -> Result<ReleasedAttachmentReceipt, AttachmentManagerError> {
        let claim = {
            let state = self.lock_state();
            let record = state
                .records
                .get(fence)
                .ok_or(AttachmentManagerError::InconsistentState)?;
            if record.phase == ManagedPhase::Released {
                return record
                    .released
                    .clone()
                    .ok_or(AttachmentManagerError::InconsistentState);
            }
            if record.phase != ManagedPhase::Revoking || record.active.as_ref() != Some(active) {
                return Err(AttachmentManagerError::InconsistentState);
            }
            record
                .claim
                .clone()
                .ok_or(AttachmentManagerError::InconsistentState)?
        };
        self.routes
            .revoke(&claim)
            .map_err(AttachmentManagerError::Route)?;
        self.routes
            .revoke_shard(fence.shard())
            .map_err(AttachmentManagerError::Route)?;
        self.routes
            .release_shard(fence.shard())
            .map_err(AttachmentManagerError::Route)?;

        let mut state = self.lock_state();
        state
            .attachments
            .acknowledge_listener_closed(active)
            .map_err(AttachmentManagerError::Attachment)?;
        state
            .attachments
            .mark_drained(active)
            .map_err(AttachmentManagerError::Attachment)?;
        let released = state
            .attachments
            .release(active)
            .map_err(AttachmentManagerError::Attachment)?;
        let record = state
            .records
            .get_mut(fence)
            .ok_or(AttachmentManagerError::InconsistentState)?;
        record.released = Some(released.clone());
        record.phase = ManagedPhase::Released;
        record.actor.take();
        record.signal();
        Ok(released)
    }
}

impl ManagerState {
    fn allocate_endpoint(&mut self) -> Result<RouteEndpoint, AttachmentManagerError> {
        let endpoint =
            RouteEndpoint::new(self.next_endpoint).map_err(AttachmentManagerError::Route)?;
        self.next_endpoint = self
            .next_endpoint
            .checked_add(1)
            .ok_or(AttachmentManagerError::EndpointExhausted)?;
        Ok(endpoint)
    }
}

impl ManagedAttachment {
    fn new(prepared: PreparedAttachmentReceipt) -> Self {
        Self {
            prepared,
            phase: ManagedPhase::Prepared,
            descriptor: None,
            claim: None,
            binding: None,
            installing: None,
            cancelled: None,
            active: None,
            released: None,
            cancellation: CancellationToken::new(),
            actor: None,
            lease_deadline: watch::channel(MonotonicMillis::default()).0,
            changed: watch::channel(0).0,
        }
    }

    fn signal(&self) {
        self.changed.send_modify(|revision| {
            *revision = revision.wrapping_add(1);
        });
    }
}

fn ensure_exact_install(
    record: &ManagedAttachment,
    descriptor: DescriptorIdentity,
    binding: &RouteBinding,
) -> Result<(), AttachmentManagerError> {
    if record.descriptor != Some(descriptor) {
        return Err(AttachmentManagerError::DescriptorConflict);
    }
    if record.binding.as_ref() != Some(binding) {
        return Err(AttachmentManagerError::BindingConflict);
    }
    Ok(())
}

fn descriptor_identity(descriptor: &OwnedFd) -> Result<DescriptorIdentity, AttachmentManagerError> {
    let metadata = fstat(descriptor)
        .map_err(|error| AttachmentManagerError::InvalidDescriptor(io::Error::from(error)))?;
    Ok(DescriptorIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

async fn run_listener_actor(
    inner: Weak<ManagerInner>,
    fence: EgressFence,
    active: ActiveAttachmentReceipt,
    listener: RouteIngressListener,
    cancellation: CancellationToken,
    mut lease_deadline: watch::Receiver<MonotonicMillis>,
) {
    let Some(manager) = inner.upgrade() else {
        return;
    };
    let mut handlers = JoinSet::new();
    let actor_owns_revoke = 'actor: loop {
        let observed_expiry = *lease_deadline.borrow_and_update();
        let ttl = observed_expiry
            .value()
            .saturating_sub(manager.clock.now().value());
        let expiry = tokio::time::sleep(Duration::from_millis(ttl));
        tokio::pin!(expiry);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break false,
            changed = lease_deadline.changed() => {
                if changed.is_err() {
                    break false;
                }
                continue;
            }
            () = &mut expiry => {
                match manager.start_actor_revoke(&fence, &active, Some(observed_expiry)) {
                    ActorRevokeAction::Own => break true,
                    ActorRevokeAction::RetryExpiry => continue,
                    ActorRevokeAction::Stop => break false,
                }
            }
            completed = handlers.join_next(), if !handlers.is_empty() => {
                if matches!(completed, Some(Err(_))) {
                    break 'actor matches!(
                        manager.start_actor_revoke(&fence, &active, None),
                        ActorRevokeAction::Own
                    );
                }
            }
            accepted = listener.accept(|| manager.clock.now()) => {
                match accepted {
                    Ok(ingress) => {
                        let handler = manager.handler.clone();
                        handlers.spawn(async move { handler.handle(ingress).await });
                    }
                    Err(_) => {
                        break 'actor matches!(
                            manager.start_actor_revoke(&fence, &active, None),
                            ActorRevokeAction::Own
                        );
                    }
                }
            }
        }
    };
    drop(listener);
    while handlers.join_next().await.is_some() {}
    if actor_owns_revoke {
        let _ = manager.finish_active_revoke(&fence, &active);
    }
}

#[derive(Debug)]
pub enum AttachmentManagerError {
    Attachment(AttachmentError),
    Route(RouteError),
    Ingress(RouteIngressError),
    InvalidDescriptor(io::Error),
    DescriptorConflict,
    BindingConflict,
    InstallCancelled,
    ShuttingDown,
    EndpointExhausted,
    InconsistentState,
}

impl fmt::Display for AttachmentManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attachment(error) => write!(formatter, "attachment lifecycle failed: {error}"),
            Self::Route(error) => write!(formatter, "attachment route failed: {error:?}"),
            Self::Ingress(error) => write!(formatter, "attachment ingress failed: {error}"),
            Self::InvalidDescriptor(error) => {
                write!(
                    formatter,
                    "attachment descriptor inspection failed: {error}"
                )
            }
            Self::DescriptorConflict => {
                formatter.write_str("attachment listener descriptor conflicts with first install")
            }
            Self::BindingConflict => {
                formatter.write_str("attachment route binding conflicts with first install")
            }
            Self::InstallCancelled => formatter.write_str("attachment install was cancelled"),
            Self::ShuttingDown => formatter.write_str("attachment manager is shutting down"),
            Self::EndpointExhausted => formatter.write_str("attachment endpoint space exhausted"),
            Self::InconsistentState => {
                formatter.write_str("attachment manager state is inconsistent")
            }
        }
    }
}

impl Error for AttachmentManagerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Attachment(error) => Some(error),
            Self::Ingress(error) => Some(error),
            Self::InvalidDescriptor(error) => Some(error),
            Self::Route(_)
            | Self::DescriptorConflict
            | Self::BindingConflict
            | Self::InstallCancelled
            | Self::ShuttingDown
            | Self::EndpointExhausted
            | Self::InconsistentState => None,
        }
    }
}
