use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

use browserd_core::{ActionId, PageId, SessionId, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_sandbox::CleanupReason;
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ApprovedActionError, ArtifactStoreReceipt, ArtifactStoreRequest,
    ChromiumDriver, DependencyError, LiveApprovalContext, SandboxClient,
};

pub trait SessionShardLifecycle: Send + Sync + 'static {
    fn qualify(&self) -> Result<(), DependencyError>;

    fn heartbeat(&self) -> Result<(), DependencyError>;

    fn terminate(&self, fence: &OwnershipFence) -> Result<(), DependencyError>;
}

pub trait SessionShardFactory: Send + Sync + 'static {
    fn qualify_daemon(&self) -> Result<(), DependencyError>;

    fn heartbeat_daemon(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<(), DependencyError>;

    fn create(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError>;
}

pub trait RoutedArtifactStore: Send + Sync + 'static {
    fn store(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError>;
}

#[derive(Clone)]
pub struct ProvisionedSessionShard {
    primary_page_id: PageId,
    driver: Arc<dyn ChromiumDriver>,
    lifecycle: Arc<dyn SessionShardLifecycle>,
}

impl ProvisionedSessionShard {
    #[must_use]
    pub fn new(
        primary_page_id: PageId,
        driver: Arc<dyn ChromiumDriver>,
        lifecycle: Arc<dyn SessionShardLifecycle>,
    ) -> Self {
        Self {
            primary_page_id,
            driver,
            lifecycle,
        }
    }
}

pub struct SessionShardRouter<F, A> {
    worker_id: WorkerId,
    worker_epoch: u64,
    factory: Arc<F>,
    artifacts: Arc<A>,
    state: Mutex<RouterState>,
}

struct RouterState {
    entries: HashMap<SessionId, Arc<SessionEntry>>,
    occupied: usize,
    max_sessions: usize,
}

struct SessionEntry {
    tenant_id: TenantId,
    fence: OwnershipFence,
    state: Mutex<EntryState>,
    changed: Condvar,
}

enum EntryState {
    Provisioning,
    Active {
        shard: ProvisionedSessionShard,
        in_flight: usize,
    },
    Draining {
        shard: ProvisionedSessionShard,
        in_flight: usize,
    },
    Closing,
    Tombstone,
    CreateFailed(DependencyError),
    CloseFailed(DependencyError),
}

struct ActiveCall {
    entry: Arc<SessionEntry>,
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        let mut state = match self.entry.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let in_flight = match &mut *state {
            EntryState::Active { in_flight, .. } | EntryState::Draining { in_flight, .. } => {
                in_flight
            }
            EntryState::Provisioning
            | EntryState::Closing
            | EntryState::Tombstone
            | EntryState::CreateFailed(_)
            | EntryState::CloseFailed(_) => return,
        };
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            self.entry.changed.notify_all();
        }
    }
}

impl<F, A> SessionShardRouter<F, A>
where
    F: SessionShardFactory,
    A: RoutedArtifactStore,
{
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        factory: Arc<F>,
        artifacts: Arc<A>,
        max_sessions: usize,
    ) -> Result<Self, DependencyError> {
        if worker_epoch == 0 || max_sessions == 0 {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            worker_id,
            worker_epoch,
            factory,
            artifacts,
            state: Mutex::new(RouterState {
                entries: HashMap::new(),
                occupied: 0,
                max_sessions,
            }),
        })
    }

    fn validate_fence(&self, fence: &OwnershipFence) -> Result<(), DependencyError> {
        if fence.worker_id() != &self.worker_id
            || fence.worker_epoch() != self.worker_epoch
            || fence.placement_version() == 0
            || fence.session_incarnation() == 0
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    fn entry(&self, session_id: &SessionId) -> Result<Arc<SessionEntry>, DependencyError> {
        self.state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .entries
            .get(session_id)
            .cloned()
            .ok_or(DependencyError::Rejected)
    }

    fn entries(&self) -> Result<Vec<Arc<SessionEntry>>, DependencyError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .entries
            .values()
            .cloned()
            .collect())
    }

    fn pin_active(
        entry: Arc<SessionEntry>,
    ) -> Result<Option<(ProvisionedSessionShard, ActiveCall)>, DependencyError> {
        let shard = {
            let mut state = entry
                .state
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            match &mut *state {
                EntryState::Active { shard, in_flight } => {
                    *in_flight = in_flight
                        .checked_add(1)
                        .ok_or(DependencyError::Unavailable)?;
                    shard.clone()
                }
                EntryState::Provisioning
                | EntryState::Draining { .. }
                | EntryState::Closing
                | EntryState::Tombstone
                | EntryState::CreateFailed(_)
                | EntryState::CloseFailed(_) => return Ok(None),
            }
        };
        Ok(Some((shard, ActiveCall { entry })))
    }

    fn routed_driver(
        &self,
        session_id: &SessionId,
    ) -> Result<(Arc<dyn ChromiumDriver>, ActiveCall), DependencyError> {
        let entry = self.entry(session_id)?;
        let Some((shard, active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        Ok((shard.driver, active))
    }

    fn qualify_all(&self) -> Result<(), DependencyError> {
        self.factory.qualify_daemon()?;
        for entry in self.entries()? {
            let Some((shard, _active)) = Self::pin_active(entry)? else {
                continue;
            };
            shard.lifecycle.qualify()?;
        }
        Ok(())
    }

    fn heartbeat_all(&self) -> Result<(), DependencyError> {
        self.factory
            .heartbeat_daemon(&self.worker_id, self.worker_epoch)?;
        for entry in self.entries()? {
            let Some((shard, _active)) = Self::pin_active(entry)? else {
                continue;
            };
            shard.lifecycle.heartbeat()?;
        }
        Ok(())
    }

    fn await_create(entry: &Arc<SessionEntry>) -> Result<PageId, DependencyError> {
        let mut state = entry
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        loop {
            match &*state {
                EntryState::Provisioning => {
                    state = entry
                        .changed
                        .wait(state)
                        .map_err(|_| DependencyError::Unavailable)?;
                }
                EntryState::Active { shard, .. } => return Ok(shard.primary_page_id.clone()),
                EntryState::CreateFailed(error) | EntryState::CloseFailed(error) => {
                    return Err(*error);
                }
                EntryState::Draining { .. } | EntryState::Closing | EntryState::Tombstone => {
                    return Err(DependencyError::Rejected);
                }
            }
        }
    }

    fn publish_create(
        entry: &Arc<SessionEntry>,
        shard: ProvisionedSessionShard,
    ) -> Result<PageId, DependencyError> {
        let page_id = shard.primary_page_id.clone();
        let mut state = entry
            .state
            .lock()
            .map_err(|_| DependencyError::OutcomeUncertain)?;
        if !matches!(*state, EntryState::Provisioning) {
            return Err(DependencyError::OutcomeUncertain);
        }
        *state = EntryState::Active {
            shard,
            in_flight: 0,
        };
        entry.changed.notify_all();
        Ok(page_id)
    }

    fn publish_create_failure(
        &self,
        session_id: &SessionId,
        entry: &Arc<SessionEntry>,
        error: DependencyError,
    ) {
        if error == DependencyError::OutcomeUncertain {
            if let Ok(mut state) = entry.state.lock() {
                *state = EntryState::CreateFailed(error);
                entry.changed.notify_all();
            }
            return;
        }

        let Ok(mut router) = self.state.lock() else {
            if let Ok(mut state) = entry.state.lock() {
                *state = EntryState::CreateFailed(DependencyError::OutcomeUncertain);
                entry.changed.notify_all();
            }
            return;
        };
        let Ok(mut state) = entry.state.lock() else {
            return;
        };
        *state = EntryState::CreateFailed(error);
        if router
            .entries
            .get(session_id)
            .is_some_and(|stored| Arc::ptr_eq(stored, entry))
        {
            router.entries.remove(session_id);
            router.occupied = router.occupied.saturating_sub(1);
        }
        entry.changed.notify_all();
    }

    fn create_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        self.validate_fence(fence)?;
        let (entry, creator) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            if let Some(entry) = state.entries.get(session_id) {
                (Arc::clone(entry), false)
            } else {
                if state.occupied >= state.max_sessions {
                    return Err(DependencyError::Unavailable);
                }
                let entry = Arc::new(SessionEntry {
                    tenant_id: tenant_id.clone(),
                    fence: fence.clone(),
                    state: Mutex::new(EntryState::Provisioning),
                    changed: Condvar::new(),
                });
                state.entries.insert(session_id.clone(), Arc::clone(&entry));
                state.occupied += 1;
                (entry, true)
            }
        };

        if entry.tenant_id != *tenant_id || entry.fence != *fence {
            return Err(DependencyError::Rejected);
        }
        if !creator {
            return Self::await_create(&entry);
        }

        match self.factory.create(tenant_id, session_id, fence) {
            Ok(shard) => Self::publish_create(&entry, shard),
            Err(error) => {
                self.publish_create_failure(session_id, &entry, error);
                Err(error)
            }
        }
    }

    fn close_fenced(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.validate_fence(fence)?;
        let entry = self.entry(session_id)?;
        if entry.fence != *fence {
            return Err(DependencyError::Rejected);
        }

        let lifecycle = {
            let mut state = entry
                .state
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            loop {
                match &*state {
                    EntryState::Provisioning
                    | EntryState::Draining { .. }
                    | EntryState::Closing => {
                        if let EntryState::Draining {
                            shard,
                            in_flight: 0,
                        } = &*state
                        {
                            let lifecycle = Arc::clone(&shard.lifecycle);
                            *state = EntryState::Closing;
                            break lifecycle;
                        }
                        state = entry
                            .changed
                            .wait(state)
                            .map_err(|_| DependencyError::Unavailable)?;
                    }
                    EntryState::Active { shard, in_flight } => {
                        let lifecycle = Arc::clone(&shard.lifecycle);
                        if *in_flight == 0 {
                            *state = EntryState::Closing;
                            break lifecycle;
                        }
                        *state = EntryState::Draining {
                            shard: shard.clone(),
                            in_flight: *in_flight,
                        };
                    }
                    EntryState::Tombstone => return Ok(()),
                    EntryState::CreateFailed(error) | EntryState::CloseFailed(error) => {
                        return Err(*error);
                    }
                }
            }
        };

        let termination = lifecycle.terminate(&entry.fence);
        match termination {
            Ok(()) => {
                let mut router = self
                    .state
                    .lock()
                    .map_err(|_| DependencyError::OutcomeUncertain)?;
                let mut state = entry
                    .state
                    .lock()
                    .map_err(|_| DependencyError::OutcomeUncertain)?;
                if !matches!(*state, EntryState::Closing) {
                    return Err(DependencyError::OutcomeUncertain);
                }
                *state = EntryState::Tombstone;
                router.occupied = router.occupied.saturating_sub(1);
                entry.changed.notify_all();
                Ok(())
            }
            Err(error) => {
                let mut state = entry
                    .state
                    .lock()
                    .map_err(|_| DependencyError::OutcomeUncertain)?;
                *state = EntryState::CloseFailed(error);
                entry.changed.notify_all();
                Err(error)
            }
        }
    }

    fn map_approved_route_error(error: DependencyError) -> ApprovedActionError {
        match error {
            DependencyError::Rejected => ApprovedActionError::DispatchRevoked,
            DependencyError::Unavailable => ApprovedActionError::Unavailable,
            DependencyError::OutcomeUncertain => ApprovedActionError::OutcomeUncertain,
        }
    }
}

impl<F, A> ChromiumDriver for SessionShardRouter<F, A>
where
    F: SessionShardFactory,
    A: RoutedArtifactStore,
{
    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualify_all()
    }

    fn effective_isolation(&self) -> browserd_worker::WorkerIsolationProfile {
        browserd_worker::WorkerIsolationProfile::DedicatedProcess
    }

    fn shard_managed_contexts(&self) -> bool {
        true
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_fenced(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        self.create_owned(tenant_id, session_id, fence)
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn close_context_fenced(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.close_fenced(session_id, fence)
    }

    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        let (driver, _active) = self.routed_driver(session_id)?;
        driver.create_page(session_id)
    }

    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError> {
        let (driver, _active) = self.routed_driver(session_id)?;
        driver.close_page(session_id, page_id)
    }

    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError> {
        let (driver, _active) = self.routed_driver(session_id)?;
        driver.activate_page(session_id, page_id)
    }

    fn execute_action(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        let Ok((driver, _active)) = self.routed_driver(session_id) else {
            return ActionExecutionResult::OutcomeUnknown;
        };
        driver.execute_action(session_id, page_id, payload)
    }

    fn inspect_approval_context(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        let (driver, _active) = self.routed_driver(session_id)?;
        driver.inspect_approval_context(session_id, page_id, proposal)
    }

    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let (driver, _active) = self
            .routed_driver(session_id)
            .map_err(Self::map_approved_route_error)?;
        driver.execute_approved_action(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            authorize_and_commit,
        )
    }

    fn cancel_action(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        let (driver, _active) = self.routed_driver(session_id)?;
        driver.cancel_action(session_id, action_id)
    }
}

impl<F, A> SandboxClient for SessionShardRouter<F, A>
where
    F: SessionShardFactory,
    A: RoutedArtifactStore,
{
    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualify_all()
    }

    fn provision(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn cleanup(
        &self,
        _session_id: &SessionId,
        _reason: CleanupReason,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn heartbeat(&self, worker_id: &WorkerId, worker_epoch: u64) -> Result<(), DependencyError> {
        if worker_id != &self.worker_id || worker_epoch != self.worker_epoch {
            return Err(DependencyError::Rejected);
        }
        self.heartbeat_all()
    }

    fn store_artifact(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.validate_fence(request.fence())?;
        let entry = self.entry(request.key().session_id())?;
        if entry.tenant_id != *request.key().tenant_id() || entry.fence != *request.fence() {
            return Err(DependencyError::Rejected);
        }
        let Some((_shard, _active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        self.artifacts.store(request)
    }
}
