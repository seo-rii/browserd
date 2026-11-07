//! Session-owned viewer leases. Lock order: cleanup owner, viewer lane, session state.
use super::*;
use browserd_session::SessionControl;
use browserd_viewer::{
    ConnectionId, ControlInput, ControlManager, InputCleanup, InputDecision, ViewerConnection,
};

const MAX_VIEWER_CONNECTIONS: usize = 4;
const MAX_CONNECTION_NONCES: usize = 256;
const VIEWER_LEASE_MILLIS: u64 = 30_000;
const OBSERVER_IDLE_MILLIS: u64 = 30_000;

struct Observer {
    connection: ViewerConnection,
    page: PageId,
    expires: u64,
}

pub(super) struct ViewerSession {
    control: ControlManager,
    observers: HashMap<ConnectionId, Observer>,
    seen: std::collections::HashSet<ConnectionId>,
    transforms: HashMap<PageId, u64>,
    pending_cleanup: Option<(PageId, InputCleanup)>,
}

impl ViewerSession {
    fn new(fence: &WorkerSessionFence) -> Result<Self, WorkerError> {
        Ok(Self {
            control: ControlManager::new(
                fence.tenant_id.clone(),
                fence.session_id.clone(),
                fence.session_incarnation,
                Duration::from_millis(VIEWER_LEASE_MILLIS),
            )
            .map_err(|_| WorkerError::InvalidConfiguration)?,
            observers: HashMap::new(),
            seen: std::collections::HashSet::new(),
            transforms: HashMap::new(),
            pending_cleanup: None,
        })
    }
}

fn control_error(error: browserd_viewer::ControlError) -> WorkerError {
    if error == browserd_viewer::ControlError::DurabilityUnavailable {
        WorkerError::DurabilityUnavailable
    } else {
        WorkerError::InvalidActionTransition
    }
}
fn dependency(_: DependencyError) -> WorkerError {
    WorkerError::DependencyUnavailable
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    fn viewer_scope(
        &self,
        peer: &AuthenticatedPeer,
        fence: &WorkerSessionFence,
    ) -> Result<(Arc<SessionExecutor>, OwnershipFence), WorkerError> {
        self.authorize(peer)?;
        if !fence.is_valid() || fence.worker_epoch != self.config.worker_epoch {
            return Err(WorkerError::StaleFence);
        }
        let executor = self.session(&fence.session_id)?;
        let ownership = OwnershipFence::new(
            self.config.worker_id.clone(),
            fence.worker_epoch,
            fence.placement_version,
            fence.session_incarnation,
        );
        {
            let state = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&state, &ownership)?;
            if state.tenant_id != fence.tenant_id {
                return Err(WorkerError::StaleFence);
            }
        }
        Ok((executor, ownership))
    }

    fn viewer_live_page(
        &self,
        executor: &SessionExecutor,
        fence: &OwnershipFence,
        page: Option<&PageId>,
    ) -> Result<PageId, WorkerError> {
        let state = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&state, fence)?;
        if state.machine.lifecycle() != SessionLifecycle::Ready || !state.occupies_capacity {
            return Err(WorkerError::NotReady);
        }
        let page = page.unwrap_or(&state.active_page_id);
        if !state.pages.contains(page) {
            return Err(WorkerError::PageNotFound);
        }
        Ok(page.clone())
    }

    fn viewer_audit(
        &self,
        fence: &WorkerSessionFence,
        connection: &ConnectionId,
        kind: &str,
        lease_epoch: u64,
        sequence: u64,
    ) -> Result<(), WorkerError> {
        let Some(wal) = &self.audit_wal else {
            return Ok(());
        };
        let id = AuditEventId::new(format!(
            "viewer:{connection:?}:{kind}:{lease_epoch}:{sequence}"
        ))
        .map_err(|_| WorkerError::DurabilityUnavailable)?;
        let payload = serde_json::to_vec(&serde_json::json!({"tenant_id":fence.tenant_id,"session_id":fence.session_id,"worker_epoch":fence.worker_epoch,"session_incarnation":fence.session_incarnation,"lease_epoch":lease_epoch,"sequence":sequence})).map_err(|_| WorkerError::StateUnavailable)?;
        match wal
            .append(AuditEvent::new(id, kind, payload, true))
            .map_err(|_| WorkerError::DurabilityUnavailable)?
        {
            AppendOutcome::Durable(_) | AppendOutcome::Existing(_) => Ok(()),
            AppendOutcome::DroppedNonCritical => Err(WorkerError::DurabilityUnavailable),
        }
    }

    fn finish_viewer_cleanup(
        &self,
        executor: &SessionExecutor,
        fence: &WorkerSessionFence,
        ownership: &OwnershipFence,
        viewer: &mut ViewerSession,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        let Some((page, cleanup)) = viewer.pending_cleanup.as_ref() else {
            return Ok(());
        };
        self.driver
            .viewer_cleanup(&fence.session_id, page, ownership, cleanup)
            .map_err(dependency)?;
        let mut state = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&state, ownership)?;
        if state.machine.snapshot().control == SessionControl::Human
            && state.machine.lifecycle() == SessionLifecycle::Ready
        {
            let now = now.max(state.machine.last_observed_at());
            let mut machine = state.machine.clone();
            machine
                .release_human_control(ownership, now)
                .map_err(map_session_error)?;
            self.control_event_journal.record(
                fence.clone(),
                viewer.control.snapshot().map_err(control_error)?.epoch(),
                false,
                None,
            )?;
            state.machine = machine;
        }
        viewer.pending_cleanup = None;
        let _ = viewer
            .control
            .drain_cleanup_events()
            .map_err(control_error)?;
        Ok(())
    }

    fn release_viewer_control(
        &self,
        executor: &SessionExecutor,
        fence: &WorkerSessionFence,
        ownership: &OwnershipFence,
        viewer: &mut ViewerSession,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        if viewer.pending_cleanup.is_some() {
            return self.finish_viewer_cleanup(executor, fence, ownership, viewer, now);
        }
        let snapshot = viewer.control.snapshot().map_err(control_error)?;
        if let Some(lease) = snapshot.lease() {
            self.viewer_audit(
                fence,
                lease.connection_id(),
                "viewer.control.release",
                lease.epoch(),
                0,
            )?;
            let cleanup = viewer
                .control
                .release(lease.connection_id(), lease.epoch())
                .map_err(control_error)?;
            viewer.pending_cleanup = Some((lease.page_id().clone(), cleanup));
            self.finish_viewer_cleanup(executor, fence, ownership, viewer, now)?;
        }
        Ok(())
    }

    fn expire_viewer_state(
        &self,
        executor: &SessionExecutor,
        fence: &WorkerSessionFence,
        ownership: &OwnershipFence,
        viewer: &mut ViewerSession,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        self.finish_viewer_cleanup(executor, fence, ownership, viewer, now)?;
        let control = viewer.control.snapshot().map_err(control_error)?;
        if control
            .lease()
            .is_some_and(|lease| now.get() >= lease.expires_at_millis())
        {
            self.release_viewer_control(executor, fence, ownership, viewer, now)?;
        }
        let expired = viewer
            .observers
            .iter()
            .filter(|(_, observer)| observer.expires <= now.get())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            self.detach_viewer(executor, fence, ownership, viewer, &id, now)?;
        }
        Ok(())
    }

    fn detach_viewer(
        &self,
        executor: &SessionExecutor,
        fence: &WorkerSessionFence,
        ownership: &OwnershipFence,
        viewer: &mut ViewerSession,
        connection: &ConnectionId,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        if viewer
            .control
            .snapshot()
            .map_err(control_error)?
            .lease()
            .is_some_and(|lease| lease.connection_id() == connection)
        {
            self.release_viewer_control(executor, fence, ownership, viewer, now)?;
        }
        if let Some(observer) = viewer.observers.get(connection) {
            let page = observer.page.clone();
            let cleanup = viewer
                .control
                .disconnect(connection)
                .map_err(control_error)?;
            if let Some(cleanup) = cleanup {
                viewer.pending_cleanup = Some((page.clone(), cleanup));
                self.finish_viewer_cleanup(executor, fence, ownership, viewer, now)?;
            }
            viewer.observers.remove(connection);
            if !viewer
                .observers
                .values()
                .any(|observer| observer.page == page)
            {
                self.driver
                    .viewer_stop(&fence.session_id, &page, ownership)
                    .map_err(dependency)?;
            }
        }
        Ok(())
    }

    fn viewer_snapshot(
        &self,
        executor: &SessionExecutor,
        fence: &WorkerSessionFence,
        ownership: &OwnershipFence,
        viewer: &mut ViewerSession,
        connection: &ConnectionId,
        after_frame_id: u64,
    ) -> Result<WorkerViewerSnapshot, WorkerError> {
        if viewer.pending_cleanup.is_some() {
            return Err(WorkerError::DependencyUnavailable);
        }
        let page = viewer
            .observers
            .get(connection)
            .ok_or(WorkerError::InvalidActionTransition)?
            .page
            .clone();
        self.viewer_live_page(executor, ownership, Some(&page))?;
        let frame = self
            .driver
            .viewer_frame(&fence.session_id, &page, ownership)
            .map_err(dependency)?;
        if let Some(frame) = &frame {
            if frame.page_id != page
                || frame.frame_id == 0
                || frame.frame_transform_id == 0
                || frame.metadata.len() > MAX_VIEWER_METADATA_BYTES
                || frame.jpeg_base64.len() > MAX_VIEWER_JPEG_BYTES.div_ceil(3) * 4
            {
                return Err(WorkerError::DependencyUnavailable);
            }
            viewer
                .control
                .observe_transform(page.clone(), frame.frame_transform_id)
                .map_err(control_error)?;
            viewer
                .transforms
                .insert(page.clone(), frame.frame_transform_id);
        }
        let control = viewer.control.snapshot().map_err(control_error)?;
        let controller = match control.lease() {
            Some(lease) if lease.connection_id() == connection => {
                WorkerViewerController::ThisConnection
            }
            Some(_) => WorkerViewerController::OtherConnection,
            None => WorkerViewerController::Agent,
        };
        Ok(WorkerViewerSnapshot {
            fence: fence.clone(),
            connection_id: connection.clone(),
            page_id: page.clone(),
            frame_transform_id: viewer.transforms.get(&page).copied().unwrap_or(0),
            frame: frame.filter(|frame| frame.frame_id > after_frame_id),
            control: WorkerViewerControl {
                controller,
                lease_epoch: control
                    .lease()
                    .map_or(control.epoch(), |lease| lease.epoch()),
            },
        })
    }

    pub fn viewer_open(
        &self,
        peer: &AuthenticatedPeer,
        request: &WorkerViewerOpenRequest,
        now: SessionTime,
    ) -> Result<WorkerViewerSnapshot, WorkerError> {
        let fence = &request.fence;
        let (executor, ownership) = self.viewer_scope(peer, fence)?;
        if request.connection.tenant_id() != &fence.tenant_id
            || request.connection.session_id() != &fence.session_id
            || request.connection.session_incarnation() != fence.session_incarnation
            || !request.connection.scopes().can_read()
        {
            return Err(WorkerError::StaleFence);
        }
        let _cleanup = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let mut slot = executor
            .viewer
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        if slot.is_none() {
            *slot = Some(ViewerSession::new(fence)?);
        }
        let viewer = slot.as_mut().ok_or(WorkerError::StateUnavailable)?;
        self.expire_viewer_state(&executor, fence, &ownership, viewer, now)?;
        if viewer.seen.contains(request.connection.id()) {
            return Err(WorkerError::InvalidActionTransition);
        }
        if viewer.observers.len() >= MAX_VIEWER_CONNECTIONS
            || viewer.seen.len() >= MAX_CONNECTION_NONCES
        {
            return Err(WorkerError::CapacityExceeded);
        }
        let page = self.viewer_live_page(&executor, &ownership, None)?;
        viewer.seen.insert(request.connection.id().clone());
        let shared = viewer
            .observers
            .values()
            .any(|observer| observer.page == page);
        if !shared {
            self.driver
                .viewer_start(&fence.session_id, &page, &ownership)
                .map_err(dependency)?;
        }
        let transform = match self
            .driver
            .viewer_rebind(&fence.session_id, &page, &ownership)
        {
            Ok(transform) if transform > 0 => transform,
            _ => {
                if !shared {
                    let _ = self
                        .driver
                        .viewer_stop(&fence.session_id, &page, &ownership);
                }
                return Err(WorkerError::DependencyUnavailable);
            }
        };
        viewer
            .control
            .observe_transform(page.clone(), transform)
            .map_err(control_error)?;
        viewer.transforms.insert(page.clone(), transform);
        viewer
            .control
            .attach(request.connection.clone())
            .map_err(control_error)?;
        viewer.observers.insert(
            request.connection.id().clone(),
            Observer {
                connection: request.connection.clone(),
                page,
                expires: now.get().saturating_add(OBSERVER_IDLE_MILLIS),
            },
        );
        let snapshot = self.viewer_snapshot(
            &executor,
            fence,
            &ownership,
            viewer,
            request.connection.id(),
            0,
        );
        if snapshot.is_err() {
            let _ = self.detach_viewer(
                &executor,
                fence,
                &ownership,
                viewer,
                request.connection.id(),
                now,
            );
        }
        snapshot
    }

    pub fn viewer_poll(
        &self,
        peer: &AuthenticatedPeer,
        request: &WorkerViewerPollRequest,
        now: SessionTime,
    ) -> Result<WorkerViewerSnapshot, WorkerError> {
        let (executor, ownership) = self.viewer_scope(peer, &request.fence)?;
        let _cleanup = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let mut slot = executor
            .viewer
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let viewer = slot.as_mut().ok_or(WorkerError::InvalidActionTransition)?;
        self.expire_viewer_state(&executor, &request.fence, &ownership, viewer, now)?;
        viewer
            .observers
            .get_mut(&request.connection_id)
            .ok_or(WorkerError::InvalidActionTransition)?
            .expires = now.get().saturating_add(OBSERVER_IDLE_MILLIS);
        self.viewer_snapshot(
            &executor,
            &request.fence,
            &ownership,
            viewer,
            &request.connection_id,
            request.after_frame_id,
        )
    }

    pub fn viewer_message(
        &self,
        peer: &AuthenticatedPeer,
        request: &WorkerViewerMessageRequest,
        now: SessionTime,
    ) -> Result<WorkerViewerSnapshot, WorkerError> {
        if !request.message.is_valid() {
            return Err(WorkerError::InvalidConfiguration);
        }
        let fence = &request.fence;
        let (executor, ownership) = self.viewer_scope(peer, fence)?;
        if matches!(request.message, ViewerClientMessage::RequestControl { .. }) {
            let state = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            if state.machine.snapshot().execution != SessionExecution::Idle {
                return Err(WorkerError::InvalidActionTransition);
            }
        }
        let _cleanup = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let mut slot = executor
            .viewer
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let viewer = slot.as_mut().ok_or(WorkerError::InvalidActionTransition)?;
        self.expire_viewer_state(&executor, fence, &ownership, viewer, now)?;
        let observer = viewer
            .observers
            .get_mut(&request.connection_id)
            .ok_or(WorkerError::InvalidActionTransition)?;
        observer.expires = now.get().saturating_add(OBSERVER_IDLE_MILLIS);
        let page = observer.page.clone();
        self.viewer_live_page(&executor, &ownership, Some(&page))?;
        match &request.message {
            ViewerClientMessage::RequestControl { force } => {
                self.admit_runtime_operation(
                    &fence.tenant_id,
                    &fence.session_id,
                    "browser:viewer_control",
                )?;
                let scopes = viewer
                    .observers
                    .get(&request.connection_id)
                    .ok_or(WorkerError::InvalidActionTransition)?
                    .connection
                    .scopes();
                if !scopes.can_control() || (*force && !scopes.can_admin()) {
                    return Err(WorkerError::UnauthorizedPeer);
                }
                let control = viewer.control.snapshot().map_err(control_error)?;
                if let Some(lease) = control.lease()
                    && lease.connection_id() != &request.connection_id
                {
                    if !force {
                        return Err(WorkerError::InvalidActionTransition);
                    }
                    self.release_viewer_control(&executor, fence, &ownership, viewer, now)?;
                }
                if viewer
                    .control
                    .snapshot()
                    .map_err(control_error)?
                    .lease()
                    .is_none()
                {
                    let mut state = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    validate_fence(&state, &ownership)?;
                    let mut machine = state.machine.clone();
                    machine
                        .acquire_human_control(&ownership, now.max(machine.last_observed_at()))
                        .map_err(map_session_error)?;
                    let epoch = viewer
                        .control
                        .snapshot()
                        .map_err(control_error)?
                        .epoch()
                        .checked_add(1)
                        .ok_or(WorkerError::StateUnavailable)?;
                    self.viewer_audit(
                        fence,
                        &request.connection_id,
                        "viewer.control.acquire",
                        epoch,
                        0,
                    )?;
                    self.admit_runtime_operation(
                        &state.tenant_id,
                        &fence.session_id,
                        "browser:viewer_control",
                    )?;
                    viewer
                        .control
                        .acquire_with_commit(
                            &request.connection_id,
                            page.clone(),
                            now.get(),
                            |outcome| {
                                self.control_event_journal
                                    .record(
                                        fence.clone(),
                                        outcome.lease().epoch(),
                                        true,
                                        Some(page.clone()),
                                    )
                                    .map(|_| ())
                                    .map_err(|_| {
                                        browserd_viewer::ControlError::DurabilityUnavailable
                                    })
                            },
                        )
                        .map_err(control_error)?;
                    state.machine = machine;
                }
            }
            ViewerClientMessage::ReleaseControl {} => {
                if !viewer
                    .control
                    .snapshot()
                    .map_err(control_error)?
                    .lease()
                    .is_some_and(|lease| lease.connection_id() == &request.connection_id)
                {
                    return Err(WorkerError::InvalidActionTransition);
                }
                self.release_viewer_control(&executor, fence, &ownership, viewer, now)?;
            }
            ViewerClientMessage::Ping {} => {
                let control = viewer.control.snapshot().map_err(control_error)?;
                if let Some(lease) = control
                    .lease()
                    .filter(|lease| lease.connection_id() == &request.connection_id)
                {
                    viewer
                        .control
                        .heartbeat(&request.connection_id, lease.epoch(), now.get())
                        .map_err(control_error)?;
                }
            }
            ViewerClientMessage::SelectPage { page_id } => {
                if viewer
                    .control
                    .snapshot()
                    .map_err(control_error)?
                    .lease()
                    .is_some_and(|lease| lease.connection_id() == &request.connection_id)
                {
                    return Err(WorkerError::InvalidActionTransition);
                }
                self.viewer_live_page(&executor, &ownership, Some(page_id))?;
                if page_id != &page {
                    if !viewer
                        .observers
                        .values()
                        .any(|observer| &observer.page == page_id)
                    {
                        self.driver
                            .viewer_start(&fence.session_id, page_id, &ownership)
                            .map_err(dependency)?;
                    }
                    let transform = self
                        .driver
                        .viewer_rebind(&fence.session_id, page_id, &ownership)
                        .map_err(dependency)?;
                    viewer
                        .control
                        .observe_transform(page_id.clone(), transform)
                        .map_err(control_error)?;
                    viewer.transforms.insert(page_id.clone(), transform);
                    viewer
                        .observers
                        .get_mut(&request.connection_id)
                        .ok_or(WorkerError::StateUnavailable)?
                        .page = page_id.clone();
                    if !viewer
                        .observers
                        .values()
                        .any(|observer| observer.page == page)
                    {
                        self.driver
                            .viewer_stop(&fence.session_id, &page, &ownership)
                            .map_err(dependency)?;
                    }
                }
            }
            ViewerClientMessage::Ack { .. } | ViewerClientMessage::ResizeViewOnly { .. } => {}
            input => {
                self.viewer_snapshot(
                    &executor,
                    fence,
                    &ownership,
                    viewer,
                    &request.connection_id,
                    u64::MAX,
                )?;
                let (epoch, sequence, input_page, transform) = input
                    .input_meta()
                    .ok_or(WorkerError::InvalidConfiguration)?;
                let kind = input
                    .input_kind()
                    .ok_or(WorkerError::InvalidConfiguration)?;
                let decision = viewer
                    .control
                    .process_input(
                        &request.connection_id,
                        ControlInput::new(epoch, sequence, input_page.clone(), transform, kind),
                        now.get(),
                    )
                    .map_err(control_error)?;
                if !matches!(decision, InputDecision::Accepted(_)) {
                    return Err(WorkerError::InvalidActionTransition);
                }
                self.viewer_audit(
                    fence,
                    &request.connection_id,
                    "viewer.input",
                    epoch,
                    sequence,
                )?;
                self.admit_runtime_operation(
                    &fence.tenant_id,
                    &fence.session_id,
                    "browser:viewer_control",
                )?;
                self.driver
                    .viewer_input(&fence.session_id, input_page, &ownership, transform, input)
                    .map_err(dependency)?;
            }
        }
        {
            let mut state = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let now = now.max(state.machine.last_observed_at());
            state
                .machine
                .record_activity(&ownership, now)
                .map_err(map_session_error)?;
        }
        self.viewer_snapshot(
            &executor,
            fence,
            &ownership,
            viewer,
            &request.connection_id,
            0,
        )
    }

    pub fn viewer_close(
        &self,
        peer: &AuthenticatedPeer,
        request: &WorkerViewerCloseRequest,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        let (executor, ownership) = self.viewer_scope(peer, &request.fence)?;
        let _cleanup = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let mut slot = executor
            .viewer
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        if slot.is_none() {
            *slot = Some(ViewerSession::new(&request.fence)?);
        }
        let viewer = slot.as_mut().ok_or(WorkerError::StateUnavailable)?;
        if !viewer.seen.contains(&request.connection_id)
            && viewer.seen.len() >= MAX_CONNECTION_NONCES
        {
            return Err(WorkerError::CapacityExceeded);
        }
        viewer.seen.insert(request.connection_id.clone());
        self.detach_viewer(
            &executor,
            &request.fence,
            &ownership,
            viewer,
            &request.connection_id,
            now,
        )
    }

    pub fn expire_viewers(
        &self,
        peer: &AuthenticatedPeer,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        let sessions = self
            .lock_worker()?
            .sessions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut failed = false;
        for executor in sessions {
            if executor
                .viewer
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?
                .is_none()
            {
                continue;
            }
            let _cleanup = executor
                .cleanup_owner
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let mut slot = executor
                .viewer
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let Some(viewer) = slot.as_mut() else {
                continue;
            };
            let (fence, ownership) = {
                let state = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                if !state.occupies_capacity && state.machine.lifecycle() != SessionLifecycle::Ready
                {
                    *slot = None;
                    continue;
                }
                let ownership = state.machine.snapshot().owner_fence;
                let fence = WorkerSessionFence {
                    tenant_id: state.tenant_id.clone(),
                    session_id: state.machine.session_id().clone(),
                    worker_epoch: ownership.worker_epoch(),
                    placement_version: ownership.placement_version(),
                    session_incarnation: ownership.session_incarnation(),
                };
                (fence, ownership)
            };
            if self
                .expire_viewer_state(&executor, &fence, &ownership, viewer, now)
                .is_err()
            {
                failed = true;
            }
        }
        if failed {
            Err(WorkerError::DependencyUnavailable)
        } else {
            Ok(())
        }
    }
}
