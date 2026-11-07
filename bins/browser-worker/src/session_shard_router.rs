use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use browserd_artifacts::{ArtifactKey, ArtifactReadLimits};
use browserd_core::{ActionId, ArtifactId, PageId, SessionId, ShardFence, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_sandbox::CleanupReason;
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ApprovedActionError, ArtifactPublication, ArtifactReadRequest,
    ArtifactReadStream, ArtifactStoreReceipt, ArtifactStoreRequest, ChromiumDriver,
    CreatedSessionContext, DependencyError, GeneratedArtifactRequest, GeneratedArtifactSink,
    LiveApprovalContext, SandboxClient, WorkerIsolationProfile, WorkerSessionOptionsV1,
};

const MAX_PARALLEL_SHARD_RENEWALS: usize = 8;

pub trait SessionShardLifecycle: Send + Sync + 'static {
    fn cleanup_failure_summary(&self) -> Option<serde_json::Value> {
        None
    }

    fn shard_fence(&self) -> Option<ShardFence> {
        None
    }
    fn qualify(&self) -> Result<(), DependencyError>;

    fn heartbeat(&self) -> Result<(), DependencyError>;

    fn dispose_context_verified_until(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _deadline: Instant,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn terminate(&self, fence: &OwnershipFence) -> Result<(), DependencyError>;
}

pub trait SessionShardFactory: Send + Sync + 'static {
    fn supports_requested_isolation(&self, requested: WorkerIsolationProfile) -> bool {
        requested != WorkerIsolationProfile::DedicatedWorker
    }

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

    fn create_with_options(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _options: &WorkerSessionOptionsV1,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_with_placement(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        requested: WorkerIsolationProfile,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if !requested.satisfied_by(WorkerIsolationProfile::DedicatedProcess) {
            return Err(DependencyError::Rejected);
        }
        match options {
            Some(options) => self.create_with_options(tenant_id, session_id, fence, options),
            None => self.create(tenant_id, session_id, fence),
        }
    }
}

pub trait RoutedArtifactStore: Send + Sync + 'static {
    fn pending_notifications(
        &self,
        _cursor: Option<&str>,
        _max_scopes: usize,
        _max_descriptors: usize,
    ) -> Result<browserd_worker::WorkerNotificationPage, DependencyError> {
        Ok(browserd_worker::WorkerNotificationPage::empty())
    }
    fn acknowledge_notifications(
        &self,
        _ack: &browserd_core::NotificationAck,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn store(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError>;

    /// Deletes only the object generation identified by this storage receipt.
    fn discard(&self, _receipt: &ArtifactStoreReceipt) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn open_read(
        &self,
        _request: &ArtifactReadRequest,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn publish_artifact(&self, _publication: &ArtifactPublication) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn withdraw_artifact(&self, _publication: &ArtifactPublication) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn get_retained_artifact(
        &self,
        _key: &ArtifactKey,
        _now: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn list_retained_artifacts(
        &self,
        _tenant: &TenantId,
        _session: &SessionId,
        _after: Option<&ArtifactId>,
        _limit: usize,
        _now: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn open_retained_artifact(
        &self,
        _publication: &ArtifactPublication,
        _limits: ArtifactReadLimits,
        _now: u64,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn begin_generated(
        &self,
        _request: &GeneratedArtifactRequest,
    ) -> Result<Box<dyn GeneratedArtifactSink>, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

struct RoutedArtifactReader {
    inner: Box<dyn ArtifactReadStream>,
    _active: ActiveCall,
}

impl ArtifactReadStream for RoutedArtifactReader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
        self.inner.next_chunk()
    }
}

struct RoutedGeneratedSink {
    inner: Box<dyn GeneratedArtifactSink>,
    _active: ActiveCall,
}

#[async_trait::async_trait]
impl GeneratedArtifactSink for RoutedGeneratedSink {
    fn max_chunk_bytes(&self) -> usize {
        self.inner.max_chunk_bytes()
    }

    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DependencyError> {
        self.inner.write_chunk(chunk).await
    }
    async fn finish(&mut self) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.inner.finish().await
    }
    async fn abort(&mut self) -> Result<(), DependencyError> {
        self.inner.abort().await
    }
}

#[derive(Clone)]
pub struct ProvisionedSessionShard {
    primary_page_id: PageId,
    driver: Arc<dyn ChromiumDriver>,
    lifecycle: Arc<dyn SessionShardLifecycle>,
    effective_isolation: WorkerIsolationProfile,
}

impl ProvisionedSessionShard {
    #[must_use]
    pub fn new(
        primary_page_id: PageId,
        driver: Arc<dyn ChromiumDriver>,
        lifecycle: Arc<dyn SessionShardLifecycle>,
    ) -> Self {
        Self::with_isolation(
            primary_page_id,
            driver,
            lifecycle,
            WorkerIsolationProfile::DedicatedProcess,
        )
    }

    #[must_use]
    pub fn with_isolation(
        primary_page_id: PageId,
        driver: Arc<dyn ChromiumDriver>,
        lifecycle: Arc<dyn SessionShardLifecycle>,
        effective_isolation: WorkerIsolationProfile,
    ) -> Self {
        Self {
            primary_page_id,
            driver,
            lifecycle,
            effective_isolation,
        }
    }

    pub(crate) fn lifecycle(&self) -> Arc<dyn SessionShardLifecycle> {
        Arc::clone(&self.lifecycle)
    }
    pub(crate) fn primary_page_id(&self) -> &PageId {
        &self.primary_page_id
    }
}

pub struct SessionShardRouter<F, A> {
    worker_id: WorkerId,
    worker_epoch: u64,
    factory: Arc<F>,
    artifacts: Arc<A>,
    state: Mutex<RouterState>,
    heartbeat_round: Mutex<()>,
}

struct RouterState {
    entries: HashMap<SessionId, Arc<SessionEntry>>,
    occupied: usize,
    max_sessions: usize,
}

struct SessionEntry {
    tenant_id: TenantId,
    fence: OwnershipFence,
    options: Option<WorkerSessionOptionsV1>,
    requested_isolation: Option<WorkerIsolationProfile>,
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
    CloseFailed {
        error: DependencyError,
        diagnostic: Option<serde_json::Value>,
    },
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
            | EntryState::CloseFailed { .. } => return,
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
            heartbeat_round: Mutex::new(()),
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
                | EntryState::CloseFailed { .. } => return Ok(None),
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
        let mut shards = HashSet::new();
        for entry in self.entries()? {
            let Some((shard, _active)) = Self::pin_active(entry)? else {
                continue;
            };
            if shard
                .lifecycle
                .shard_fence()
                .is_none_or(|fence| shards.insert(fence))
            {
                shard.lifecycle.qualify()?;
            }
        }
        Ok(())
    }

    fn routed_fenced_driver(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(Arc<dyn ChromiumDriver>, ActiveCall), DependencyError> {
        self.validate_fence(fence)?;
        let entry = self.entry(session_id)?;
        if entry.fence != *fence {
            return Err(DependencyError::Rejected);
        }
        let Some((shard, active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        Ok((shard.driver, active))
    }

    fn routed_typed_driver(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(Arc<dyn ChromiumDriver>, ActiveCall), ApprovedActionError> {
        self.validate_fence(fence)
            .map_err(Self::map_approved_route_error)?;
        let entry = self
            .entry(session)
            .map_err(Self::map_approved_route_error)?;
        if entry.tenant_id != *tenant || entry.fence != *fence {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let Some((shard, active)) =
            Self::pin_active(entry).map_err(Self::map_approved_route_error)?
        else {
            return Err(ApprovedActionError::DispatchRevoked);
        };
        Ok((shard.driver, active))
    }

    pub(crate) fn dispose_context_verified_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        deadline: Instant,
    ) -> Result<(), DependencyError> {
        self.validate_fence(fence)?;
        if Instant::now() >= deadline {
            return Err(DependencyError::Rejected);
        }
        let entry = self.entry(session_id)?;
        if entry.tenant_id != *tenant_id || entry.fence != *fence {
            return Err(DependencyError::Rejected);
        }
        let Some((shard, _active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        // Keep the exact live route pinned until its production owner has observed disposal.
        // Final shard termination remains a separate operation, including on proof failure.
        shard
            .lifecycle
            .dispose_context_verified_until(tenant_id, session_id, fence, deadline)
    }

    pub(crate) fn cleanup_failure_summary(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<Option<serde_json::Value>, DependencyError> {
        self.validate_fence(fence)?;
        let entry = self.entry(session_id)?;
        if entry.tenant_id != *tenant_id || entry.fence != *fence {
            return Err(DependencyError::Rejected);
        }
        let state = entry
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        Ok(match &*state {
            EntryState::CloseFailed { diagnostic, .. } => diagnostic.clone(),
            _ => None,
        })
    }

    fn heartbeat_all(&self) -> Result<(), DependencyError> {
        let _round = self
            .heartbeat_round
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.factory
            .heartbeat_daemon(&self.worker_id, self.worker_epoch)?;
        let entries = self.entries()?;
        let worker_count = entries.len().min(MAX_PARALLEL_SHARD_RENEWALS);
        let pending = Mutex::new(entries.into_iter());
        let shards = Mutex::new(HashSet::new());
        std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(worker_count);
            let mut first_error = None;
            for _ in 0..worker_count {
                let work = || {
                    let mut first_error = None;
                    loop {
                        let next = pending
                            .lock()
                            .map_err(|_| DependencyError::Unavailable)?
                            .next();
                        let Some(entry) = next else {
                            break;
                        };
                        let renewal = catch_unwind(AssertUnwindSafe(|| {
                            let Some((shard, _active)) = Self::pin_active(entry)? else {
                                return Ok(());
                            };
                            let first_for_shard = match shard.lifecycle.shard_fence() {
                                Some(fence) => shards
                                    .lock()
                                    .map_err(|_| DependencyError::Unavailable)?
                                    .insert(fence),
                                None => true,
                            };
                            if first_for_shard {
                                shard.lifecycle.heartbeat()
                            } else {
                                Ok(())
                            }
                        }))
                        .unwrap_or(Err(DependencyError::OutcomeUncertain));
                        if let Err(error) = renewal {
                            let _ = first_error.get_or_insert(error);
                        }
                    }
                    first_error.map_or(Ok(()), Err)
                };
                match std::thread::Builder::new()
                    .name("browserd-shard-renewal".to_owned())
                    .spawn_scoped(scope, work)
                {
                    Ok(worker) => workers.push(worker),
                    Err(_) => {
                        let _ = first_error.get_or_insert(DependencyError::Unavailable);
                    }
                }
            }
            // Every lane takes the next available entry; a slow lane never
            // delays scheduling healthy shards behind a fixed batch join.
            for worker in workers {
                let result = worker
                    .join()
                    .unwrap_or(Err(DependencyError::OutcomeUncertain));
                if let Err(error) = result {
                    let _ = first_error.get_or_insert(error);
                }
            }
            first_error.map_or(Ok(()), Err)
        })
    }

    fn await_create(entry: &Arc<SessionEntry>) -> Result<CreatedSessionContext, DependencyError> {
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
                EntryState::Active { shard, .. } => {
                    return Ok(CreatedSessionContext {
                        primary_page_id: shard.primary_page_id.clone(),
                        effective_isolation: shard.effective_isolation,
                    });
                }
                EntryState::CreateFailed(error) | EntryState::CloseFailed { error, .. } => {
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
    ) -> Result<CreatedSessionContext, DependencyError> {
        let receipt = CreatedSessionContext {
            primary_page_id: shard.primary_page_id.clone(),
            effective_isolation: shard.effective_isolation,
        };
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
        Ok(receipt)
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
        options: Option<&WorkerSessionOptionsV1>,
        requested_isolation: Option<WorkerIsolationProfile>,
    ) -> Result<CreatedSessionContext, DependencyError> {
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
                    options: options.cloned(),
                    requested_isolation,
                    state: Mutex::new(EntryState::Provisioning),
                    changed: Condvar::new(),
                });
                state.entries.insert(session_id.clone(), Arc::clone(&entry));
                state.occupied += 1;
                (entry, true)
            }
        };

        if entry.tenant_id != *tenant_id
            || entry.fence != *fence
            || entry.options.as_ref() != options
            || entry.requested_isolation != requested_isolation
        {
            return Err(DependencyError::Rejected);
        }
        if !creator {
            return Self::await_create(&entry);
        }

        let created = match (requested_isolation, options) {
            (Some(requested), options) => self
                .factory
                .create_with_placement(tenant_id, session_id, fence, options, requested),
            (None, Some(options)) => self
                .factory
                .create_with_options(tenant_id, session_id, fence, options),
            (None, None) => self.factory.create(tenant_id, session_id, fence),
        };
        match created {
            Ok(shard)
                if requested_isolation
                    .is_none_or(|requested| requested.satisfied_by(shard.effective_isolation)) =>
            {
                Self::publish_create(&entry, shard)
            }
            Ok(shard) => {
                let error = if shard.lifecycle.terminate(fence).is_ok() {
                    DependencyError::Rejected
                } else {
                    DependencyError::OutcomeUncertain
                };
                self.publish_create_failure(session_id, &entry, error);
                Err(error)
            }
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
                            let lifecycle = shard.lifecycle();
                            *state = EntryState::Closing;
                            break lifecycle;
                        }
                        state = entry
                            .changed
                            .wait(state)
                            .map_err(|_| DependencyError::Unavailable)?;
                    }
                    EntryState::Active { shard, in_flight } => {
                        let lifecycle = shard.lifecycle();
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
                    EntryState::CreateFailed(error) | EntryState::CloseFailed { error, .. } => {
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
                *state = EntryState::CloseFailed {
                    error,
                    diagnostic: lifecycle.cleanup_failure_summary(),
                };
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
    #[allow(clippy::too_many_arguments)]
    fn inspect_typed_approval_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: Option<&PageId>,
        fence: &OwnershipFence,
        action: &browserd_worker::WorkerActionCommand,
        deadline: Instant,
    ) -> Result<browserd_worker::TypedApprovalObservation, ApprovedActionError> {
        let (driver, _active) = self.routed_typed_driver(tenant, session, fence)?;
        // The pinned route forwards the original deadline; its owner validates the optional page.
        driver.inspect_typed_approval_until(tenant, session, page, fence, action, deadline)
    }

    fn execute_typed_browser_until(
        &self,
        expected: &browserd_worker::TypedApprovalObservation,
        payload: &[u8],
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &browserd_worker::TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let (driver, _active) =
            self.routed_typed_driver(&expected.tenant_id, &expected.session_id, &expected.fence)?;
        driver.execute_typed_browser_until(expected, payload, deadline, authorize_and_commit)
    }

    fn execute_typed_secret_until(
        &self,
        expected: &browserd_worker::TypedApprovalObservation,
        secret: browserd_worker::ResolvedSecret,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &browserd_worker::TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let (driver, _active) =
            self.routed_typed_driver(&expected.tenant_id, &expected.session_id, &expected.fence)?;
        driver.execute_typed_secret_until(expected, secret, deadline, authorize_and_commit)
    }

    fn execute_typed_files_until(
        &self,
        expected: &browserd_worker::TypedApprovalObservation,
        files: Vec<browserd_worker::BrowserFileAttachment>,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &browserd_worker::TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let (driver, _active) =
            self.routed_typed_driver(&expected.tenant_id, &expected.session_id, &expected.fence)?;
        driver.execute_typed_files_until(expected, files, deadline, authorize_and_commit)
    }

    fn capture_typed_checkpoint_until(
        &self,
        expected: &browserd_worker::TypedApprovalObservation,
        origins: &[String],
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &browserd_worker::TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<browserd_worker::CheckpointSnapshot, ApprovedActionError> {
        let (driver, _active) =
            self.routed_typed_driver(&expected.tenant_id, &expected.session_id, &expected.fence)?;
        driver.capture_typed_checkpoint_until(expected, origins, deadline, authorize_and_commit)
    }

    fn execute_typed_capture_until(
        &self,
        expected: &browserd_worker::TypedApprovalObservation,
        command: browserd_features::CaptureCommand,
        request: browserd_worker::GeneratedArtifactRequest,
        store: Arc<dyn browserd_worker::SandboxClient>,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &browserd_worker::TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<browserd_worker::GeneratedCaptureResult, ApprovedActionError> {
        let (driver, _active) =
            self.routed_typed_driver(&expected.tenant_id, &expected.session_id, &expected.fence)?;
        driver.execute_typed_capture_until(
            expected,
            command,
            request,
            store,
            deadline,
            authorize_and_commit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_privileged_evaluate_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        payload: &[u8],
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let (driver, _active) = self
            .routed_fenced_driver(session_id, fence)
            .map_err(|_| ApprovedActionError::DispatchRevoked)?;
        driver.execute_privileged_evaluate_until(
            tenant_id,
            session_id,
            page_id,
            fence,
            payload,
            deadline,
            authorize_and_commit,
        )
    }

    fn capture_checkpoint_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        origins: &[String],
        deadline: Instant,
    ) -> Result<browserd_worker::CheckpointSnapshot, browserd_worker::CheckpointError> {
        let (driver, _active) = self
            .routed_fenced_driver(session_id, fence)
            .map_err(|error| match error {
                DependencyError::Rejected => browserd_worker::CheckpointError::Rejected,
                DependencyError::Unavailable => browserd_worker::CheckpointError::Unavailable,
                DependencyError::OutcomeUncertain => {
                    browserd_worker::CheckpointError::OutcomeUncertain
                }
            })?;
        driver.capture_checkpoint_until(tenant_id, session_id, fence, origins, deadline)
    }

    fn restore_checkpoint_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        primary_page: &PageId,
        fence: &OwnershipFence,
        snapshot: browserd_worker::CheckpointSnapshot,
        deadline: Instant,
    ) -> Result<(), browserd_worker::CheckpointError> {
        let (driver, _active) = self
            .routed_fenced_driver(session_id, fence)
            .map_err(|error| match error {
                DependencyError::Rejected => browserd_worker::CheckpointError::Rejected,
                DependencyError::Unavailable => browserd_worker::CheckpointError::Unavailable,
                DependencyError::OutcomeUncertain => {
                    browserd_worker::CheckpointError::OutcomeUncertain
                }
            })?;
        driver.restore_checkpoint_until(
            tenant_id,
            session_id,
            primary_page,
            fence,
            snapshot,
            deadline,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_secret_fill_target_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        deadline: Instant,
    ) -> Result<browserd_worker::SecretFillTarget, browserd_worker::SecretFillError> {
        let (driver, _active) = self
            .routed_fenced_driver(session_id, fence)
            .map_err(|error| match error {
                DependencyError::Rejected => browserd_worker::SecretFillError::Rejected,
                DependencyError::Unavailable => browserd_worker::SecretFillError::Unavailable,
                DependencyError::OutcomeUncertain => {
                    browserd_worker::SecretFillError::OutcomeUncertain
                }
            })?;
        driver.inspect_secret_fill_target_until(
            tenant_id, session_id, page_id, fence, node_ref, deadline,
        )
    }

    fn execute_secret_fill_until(
        &self,
        target: &browserd_worker::SecretFillTarget,
        secret: browserd_worker::ResolvedSecret,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &browserd_worker::SecretFillTarget,
        )
            -> Result<(), browserd_worker::SecretFillError>,
    ) -> Result<ActionExecutionResult, browserd_worker::SecretFillError> {
        let (driver, _active) = self
            .routed_fenced_driver(&target.session_id, &target.fence)
            .map_err(|error| match error {
                DependencyError::Rejected => browserd_worker::SecretFillError::Rejected,
                DependencyError::Unavailable => browserd_worker::SecretFillError::Unavailable,
                DependencyError::OutcomeUncertain => {
                    browserd_worker::SecretFillError::OutcomeUncertain
                }
            })?;
        driver.execute_secret_fill_until(target, secret, deadline, authorize_and_commit)
    }

    fn execute_file_attachment_until(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        files: Vec<browserd_worker::BrowserFileAttachment>,
        deadline: Instant,
    ) -> ActionExecutionResult {
        let (driver, _active) = match self.routed_fenced_driver(session_id, fence) {
            Ok(route) => route,
            Err(DependencyError::OutcomeUncertain) => return ActionExecutionResult::OutcomeUnknown,
            Err(_) => return ActionExecutionResult::FailedKnown("files_rejected".to_owned()),
        };
        driver.execute_file_attachment_until(session_id, page_id, fence, node_ref, files, deadline)
    }

    fn pending_browser_downloads(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        limit: usize,
    ) -> Result<Vec<browserd_worker::BrowserDownloadCompletion>, DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.pending_browser_downloads(session_id, fence, limit)
    }

    fn open_browser_download(
        &self,
        completion: &browserd_worker::BrowserDownloadCompletion,
    ) -> Result<browserd_worker::BrowserDownloadFile, DependencyError> {
        let (driver, _active) =
            self.routed_fenced_driver(&completion.session_id, &completion.fence)?;
        driver.open_browser_download(completion)
    }

    fn ack_browser_download(
        &self,
        completion: &browserd_worker::BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        let (driver, _active) =
            self.routed_fenced_driver(&completion.session_id, &completion.fence)?;
        driver.ack_browser_download(completion)
    }

    fn reject_browser_download(
        &self,
        completion: &browserd_worker::BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        let (driver, _active) =
            self.routed_fenced_driver(&completion.session_id, &completion.fence)?;
        driver.reject_browser_download(completion)
    }

    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualify_all()
    }

    fn effective_isolation(&self) -> browserd_worker::WorkerIsolationProfile {
        browserd_worker::WorkerIsolationProfile::DedicatedProcess
    }
    fn supports_requested_isolation(&self, requested: WorkerIsolationProfile) -> bool {
        self.factory.supports_requested_isolation(requested)
    }

    fn create_context_owned_with_placement(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        requested: WorkerIsolationProfile,
    ) -> Result<CreatedSessionContext, DependencyError> {
        self.create_owned(tenant, session, fence, options, Some(requested))
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
        self.create_owned(tenant_id, session_id, fence, None, None)
            .map(|context| context.primary_page_id)
    }

    fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        self.create_owned(tenant_id, session_id, fence, Some(options), None)
            .map(|context| context.primary_page_id)
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

    fn execute_capture_until(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        command: browserd_features::CaptureCommand,
        request: GeneratedArtifactRequest,
        store: Arc<dyn SandboxClient>,
        deadline: Instant,
    ) -> Result<browserd_worker::GeneratedCaptureResult, DependencyError> {
        let (driver, _active) = self.routed_driver(session_id)?;
        driver.execute_capture_until(session_id, page_id, command, request, store, deadline)
    }

    fn viewer_start(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.viewer_start(session_id, page_id, fence)
    }

    fn viewer_stop(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.viewer_stop(session_id, page_id, fence)
    }

    fn viewer_frame(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<Option<browserd_worker::WorkerViewerFrame>, DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.viewer_frame(session_id, page_id, fence)
    }

    fn viewer_rebind(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<u64, DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.viewer_rebind(session_id, page_id, fence)
    }

    fn viewer_input(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        transform_epoch: u64,
        message: &browserd_worker::ViewerClientMessage,
    ) -> Result<(), DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.viewer_input(session_id, page_id, fence, transform_epoch, message)
    }

    fn viewer_cleanup(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        cleanup: &browserd_viewer::InputCleanup,
    ) -> Result<(), DependencyError> {
        let (driver, _active) = self.routed_fenced_driver(session_id, fence)?;
        driver.viewer_cleanup(session_id, page_id, fence, cleanup)
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

    fn execute_action_until(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
        deadline: Instant,
    ) -> ActionExecutionResult {
        let Ok((driver, _active)) = self.routed_driver(session_id) else {
            return ActionExecutionResult::OutcomeUnknown;
        };
        driver.execute_action_until(session_id, page_id, payload, deadline)
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

    #[allow(clippy::too_many_arguments)]
    fn execute_approved_action_until(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let (driver, _active) = self
            .routed_driver(session_id)
            .map_err(Self::map_approved_route_error)?;
        driver.execute_approved_action_until(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            deadline,
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

    fn pending_artifact_notifications(
        &self,
        cursor: Option<&str>,
        max_scopes: usize,
        max_descriptors: usize,
    ) -> Result<browserd_worker::WorkerNotificationPage, DependencyError> {
        self.artifacts
            .pending_notifications(cursor, max_scopes, max_descriptors)
    }
    fn ack_artifact_notification(
        &self,
        ack: &browserd_core::NotificationAck,
    ) -> Result<(), DependencyError> {
        self.artifacts.acknowledge_notifications(ack)
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

    fn discard_artifact(
        &self,
        receipt: &ArtifactStoreReceipt,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.validate_fence(fence)?;
        let entry = self.entry(receipt.key().session_id())?;
        if entry.tenant_id != *receipt.key().tenant_id() || entry.fence != *fence {
            return Err(DependencyError::Rejected);
        }
        let Some((_shard, _active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        self.artifacts.discard(receipt)
    }

    fn publish_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        self.validate_fence(publication.original_fence())?;
        let entry = self.entry(publication.key().session_id())?;
        if entry.tenant_id != *publication.key().tenant_id()
            || entry.fence != *publication.original_fence()
        {
            return Err(DependencyError::Rejected);
        }
        let Some((_shard, _active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        self.artifacts.publish_artifact(publication)
    }
    fn withdraw_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        self.validate_fence(publication.original_fence())?;
        let entry = self.entry(publication.key().session_id())?;
        if entry.tenant_id != *publication.key().tenant_id()
            || entry.fence != *publication.original_fence()
        {
            return Err(DependencyError::Rejected);
        }
        let Some((_shard, _active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        self.artifacts.withdraw_artifact(publication)
    }
    fn get_retained_artifact(
        &self,
        key: &ArtifactKey,
        now: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        self.artifacts.get_retained_artifact(key, now)
    }
    fn list_retained_artifacts(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        after: Option<&ArtifactId>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        self.artifacts
            .list_retained_artifacts(tenant, session, after, limit, now)
    }
    fn open_retained_artifact(
        &self,
        publication: &ArtifactPublication,
        limits: ArtifactReadLimits,
        now: u64,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        self.artifacts
            .open_retained_artifact(publication, limits, now)
    }

    fn open_artifact(
        &self,
        request: &ArtifactReadRequest,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        self.validate_fence(request.fence())?;
        let entry = self.entry(request.key().session_id())?;
        if entry.tenant_id != *request.key().tenant_id() || entry.fence != *request.fence() {
            return Err(DependencyError::Rejected);
        }
        let Some((_shard, active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        Ok(Box::new(RoutedArtifactReader {
            inner: self.artifacts.open_read(request)?,
            _active: active,
        }))
    }

    fn begin_generated_artifact(
        &self,
        request: &GeneratedArtifactRequest,
    ) -> Result<Box<dyn GeneratedArtifactSink>, DependencyError> {
        self.validate_fence(request.fence())?;
        let entry = self.entry(request.key().session_id())?;
        if entry.tenant_id != *request.key().tenant_id() || entry.fence != *request.fence() {
            return Err(DependencyError::Rejected);
        }
        let Some((_shard, active)) = Self::pin_active(entry)? else {
            return Err(DependencyError::Rejected);
        };
        Ok(Box::new(RoutedGeneratedSink {
            inner: self.artifacts.begin_generated(request)?,
            _active: active,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod disposal_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    struct DisposalLifecycle {
        calls: Mutex<Vec<(TenantId, SessionId, OwnershipFence, Instant)>>,
        terminations: AtomicUsize,
        error: Option<DependencyError>,
        termination_error: Option<DependencyError>,
        gate: Option<(mpsc::Sender<()>, Mutex<mpsc::Receiver<()>>)>,
    }

    impl SessionShardLifecycle for DisposalLifecycle {
        fn cleanup_failure_summary(&self) -> Option<serde_json::Value> {
            self.termination_error.map(|_| {
                serde_json::json!({"stage":"owner_verification",
                "final_error":"OutcomeUncertain","owner_joined_after_exact":false})
            })
        }
        fn qualify(&self) -> Result<(), DependencyError> {
            Ok(())
        }
        fn heartbeat(&self) -> Result<(), DependencyError> {
            Ok(())
        }
        fn dispose_context_verified_until(
            &self,
            tenant: &TenantId,
            session: &SessionId,
            fence: &OwnershipFence,
            deadline: Instant,
        ) -> Result<(), DependencyError> {
            self.calls
                .lock()
                .map_err(|_| DependencyError::Unavailable)?
                .push((tenant.clone(), session.clone(), fence.clone(), deadline));
            if let Some((entered, released)) = &self.gate {
                entered.send(()).map_err(|_| DependencyError::Unavailable)?;
                released
                    .lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| DependencyError::Unavailable)?;
            }
            self.error.map_or(Ok(()), Err)
        }
        fn terminate(&self, _fence: &OwnershipFence) -> Result<(), DependencyError> {
            self.terminations.fetch_add(1, Ordering::SeqCst);
            self.termination_error.map_or(Ok(()), Err)
        }
    }

    struct DisposalFactory(Arc<DisposalLifecycle>);
    impl SessionShardFactory for DisposalFactory {
        fn qualify_daemon(&self) -> Result<(), DependencyError> {
            Ok(())
        }
        fn heartbeat_daemon(&self, _worker: &WorkerId, _epoch: u64) -> Result<(), DependencyError> {
            Ok(())
        }
        fn create(
            &self,
            _tenant: &TenantId,
            _session: &SessionId,
            _fence: &OwnershipFence,
        ) -> Result<ProvisionedSessionShard, DependencyError> {
            Ok(ProvisionedSessionShard::new(
                PageId::new(),
                Arc::new(browserd_worker::UnavailableChromiumDriver),
                self.0.clone(),
            ))
        }
    }
    struct NoArtifacts;
    impl RoutedArtifactStore for NoArtifacts {
        fn store(
            &self,
            _request: &ArtifactStoreRequest,
        ) -> Result<ArtifactStoreReceipt, DependencyError> {
            Err(DependencyError::Rejected)
        }
    }
    type DisposalRouter = SessionShardRouter<DisposalFactory, NoArtifacts>;
    fn open(
        lifecycle: Arc<DisposalLifecycle>,
    ) -> (Arc<DisposalRouter>, TenantId, SessionId, OwnershipFence) {
        let worker = WorkerId::new("kernel-live-disposal").expect("worker");
        let router = Arc::new(
            SessionShardRouter::new(
                worker.clone(),
                7,
                Arc::new(DisposalFactory(lifecycle)),
                Arc::new(NoArtifacts),
                2,
            )
            .expect("router"),
        );
        let tenant = TenantId::new();
        let session = SessionId::new();
        let fence = OwnershipFence::new(worker, 7, 1, 1);
        router
            .create_context_owned(&tenant, &session, &fence)
            .expect("owned route");
        (router, tenant, session, fence)
    }
    fn lifecycle(error: Option<DependencyError>) -> Arc<DisposalLifecycle> {
        Arc::new(DisposalLifecycle {
            calls: Mutex::new(Vec::new()),
            terminations: AtomicUsize::new(0),
            error,
            termination_error: None,
            gate: None,
        })
    }

    #[test]
    fn live_disposal_requires_exact_owner_and_precedes_independent_final_termination() {
        let lifecycle = lifecycle(None);
        let (router, tenant, session, fence) = open(lifecycle.clone());
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(
            router
                .dispose_context_verified_until(&TenantId::new(), &session, &fence, deadline)
                .is_err()
        );
        let stale = OwnershipFence::new(fence.worker_id().clone(), 7, 1, 2);
        assert!(
            router
                .dispose_context_verified_until(&tenant, &session, &stale, deadline)
                .is_err()
        );
        assert!(
            router
                .dispose_context_verified_until(&tenant, &session, &fence, Instant::now())
                .is_err()
        );
        assert!(lifecycle.calls.lock().expect("calls").is_empty());
        router
            .dispose_context_verified_until(&tenant, &session, &fence, deadline)
            .expect("live disposal");
        assert_eq!(
            lifecycle.calls.lock().expect("calls").as_slice(),
            &[(tenant.clone(), session.clone(), fence.clone(), deadline)]
        );
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 0);
        router
            .close_context_fenced(&session, &fence)
            .expect("final cleanup");
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 1);
        assert!(
            router
                .dispose_context_verified_until(&tenant, &session, &fence, deadline)
                .is_err()
        );
        assert_eq!(lifecycle.calls.lock().expect("calls").len(), 1);
    }

    #[test]
    fn failed_live_disposal_preserves_final_cleanup_and_never_becomes_success() {
        let lifecycle = lifecycle(Some(DependencyError::OutcomeUncertain));
        let (router, tenant, session, fence) = open(lifecycle.clone());
        assert_eq!(
            router.dispose_context_verified_until(
                &tenant,
                &session,
                &fence,
                Instant::now() + Duration::from_secs(2),
            ),
            Err(DependencyError::OutcomeUncertain)
        );
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 0);
        router
            .close_context_fenced(&session, &fence)
            .expect("error cleanup");
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn final_close_waits_for_the_pinned_live_disposal_operation() {
        let (entered, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let lifecycle = Arc::new(DisposalLifecycle {
            calls: Mutex::new(Vec::new()),
            terminations: AtomicUsize::new(0),
            error: None,
            termination_error: None,
            gate: Some((entered, Mutex::new(released))),
        });
        let (router, tenant, session, fence) = open(lifecycle.clone());
        let disposer = {
            let router = router.clone();
            let session = session.clone();
            let fence = fence.clone();
            std::thread::spawn(move || {
                router.dispose_context_verified_until(
                    &tenant,
                    &session,
                    &fence,
                    Instant::now() + Duration::from_secs(2),
                )
            })
        };
        observed
            .recv_timeout(Duration::from_secs(2))
            .expect("disposal entered");
        let closer = {
            let router = router.clone();
            let session = session.clone();
            let fence = fence.clone();
            std::thread::spawn(move || router.close_context_fenced(&session, &fence))
        };
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            let entry = router.entry(&session).expect("active entry");
            if matches!(
                *entry.state.lock().expect("state"),
                EntryState::Draining { .. }
            ) {
                break;
            }
            assert!(
                Instant::now() < until,
                "close did not wait for live disposal"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 0);
        release.send(()).expect("release disposal");
        assert_eq!(disposer.join().expect("dispose thread"), Ok(()));
        assert_eq!(closer.join().expect("close thread"), Ok(()));
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_close_retains_exact_owner_diagnostic_without_retrying_or_changing_error() {
        let lifecycle = Arc::new(DisposalLifecycle {
            calls: Mutex::new(Vec::new()),
            terminations: AtomicUsize::new(0),
            error: None,
            termination_error: Some(DependencyError::OutcomeUncertain),
            gate: None,
        });
        let (router, tenant, session, fence) = open(lifecycle.clone());
        assert_eq!(
            router.cleanup_failure_summary(&tenant, &session, &fence),
            Ok(None)
        );
        assert_eq!(
            router.close_context_fenced(&session, &fence),
            Err(DependencyError::OutcomeUncertain)
        );
        let summary = router
            .cleanup_failure_summary(&tenant, &session, &fence)
            .expect("diagnostic lookup");
        assert_eq!(summary, lifecycle.cleanup_failure_summary());
        assert!(
            router
                .cleanup_failure_summary(&TenantId::new(), &session, &fence)
                .is_err()
        );
        let stale = OwnershipFence::new(fence.worker_id().clone(), 7, 1, 2);
        assert!(
            router
                .cleanup_failure_summary(&tenant, &session, &stale)
                .is_err()
        );
        assert_eq!(
            router.close_context_fenced(&session, &fence),
            Err(DependencyError::OutcomeUncertain)
        );
        assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 1);
        assert_eq!(
            router.cleanup_failure_summary(&tenant, &session, &fence),
            Ok(summary)
        );
    }
}
