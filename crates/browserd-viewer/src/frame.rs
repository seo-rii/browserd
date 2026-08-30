use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use browserd_core::{PageId, SessionId, TenantId};

use crate::{ConnectionId, ViewerConnection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramePolicy {
    max_observers: usize,
    queue_depth: usize,
    max_metadata_bytes: usize,
    max_payload_bytes: usize,
}

impl FramePolicy {
    pub const fn new(
        max_observers: usize,
        queue_depth: usize,
        max_metadata_bytes: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, FrameError> {
        if max_observers == 0
            || queue_depth == 0
            || queue_depth > 2
            || max_metadata_bytes == 0
            || max_payload_bytes == 0
        {
            return Err(FrameError::InvalidPolicy);
        }
        Ok(Self {
            max_observers,
            queue_depth,
            max_metadata_bytes,
            max_payload_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewerFrame {
    frame_id: u64,
    page_id: PageId,
    transform_epoch: u64,
    metadata: Arc<[u8]>,
    jpeg_payload: Arc<[u8]>,
}

impl ViewerFrame {
    #[must_use]
    pub fn new(
        frame_id: u64,
        page_id: PageId,
        transform_epoch: u64,
        metadata: Vec<u8>,
        jpeg_payload: Vec<u8>,
    ) -> Self {
        Self {
            frame_id,
            page_id,
            transform_epoch,
            metadata: metadata.into(),
            jpeg_payload: jpeg_payload.into(),
        }
    }

    #[must_use]
    pub const fn frame_id(&self) -> u64 {
        self.frame_id
    }

    #[must_use]
    pub const fn page_id(&self) -> &PageId {
        &self.page_id
    }

    #[must_use]
    pub const fn transform_epoch(&self) -> u64 {
        self.transform_epoch
    }

    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    #[must_use]
    pub fn jpeg_payload(&self) -> &[u8] {
        &self.jpeg_payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishOutcome {
    observer_count: usize,
    dropped_frames: usize,
}

impl PublishOutcome {
    #[must_use]
    pub const fn observer_count(self) -> usize {
        self.observer_count
    }

    #[must_use]
    pub const fn dropped_frames(self) -> usize {
        self.dropped_frames
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidPolicy,
    StateUnavailable,
    ConnectionBindingMismatch,
    ReadScopeRequired,
    ConnectionAlreadyAttached,
    ObserverLimitExceeded,
    ObserverNotFound,
    MetadataTooLarge,
    PayloadTooLarge,
    PageMismatch,
    StaleTransform,
    ReplayedFrame,
    ChromiumAckFailed,
    TransformEpochExhausted,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "viewer frame error: {self:?}")
    }
}

impl std::error::Error for FrameError {}

struct FrameState {
    page_id: PageId,
    transform_epoch: u64,
    last_frame_id: Option<u64>,
    queues: HashMap<ConnectionId, VecDeque<ViewerFrame>>,
}

pub struct FrameBroadcaster {
    tenant_id: TenantId,
    session_id: SessionId,
    session_incarnation: u64,
    policy: FramePolicy,
    ingest_order: Mutex<()>,
    state: Mutex<FrameState>,
}

impl FrameBroadcaster {
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        transform_epoch: u64,
        policy: FramePolicy,
    ) -> Self {
        Self {
            tenant_id,
            session_id,
            session_incarnation,
            policy,
            ingest_order: Mutex::new(()),
            state: Mutex::new(FrameState {
                page_id,
                transform_epoch,
                last_frame_id: None,
                queues: HashMap::new(),
            }),
        }
    }

    pub fn attach(&self, connection: &ViewerConnection) -> Result<(), FrameError> {
        if connection.tenant_id() != &self.tenant_id
            || connection.session_id() != &self.session_id
            || connection.session_incarnation() != self.session_incarnation
        {
            return Err(FrameError::ConnectionBindingMismatch);
        }
        if !connection.scopes().can_read() {
            return Err(FrameError::ReadScopeRequired);
        }
        let mut state = self.lock_state()?;
        if state.queues.contains_key(connection.id()) {
            return Err(FrameError::ConnectionAlreadyAttached);
        }
        if state.queues.len() >= self.policy.max_observers {
            return Err(FrameError::ObserverLimitExceeded);
        }
        state
            .queues
            .insert(connection.id().clone(), VecDeque::new());
        Ok(())
    }

    pub fn detach(&self, connection_id: &ConnectionId) -> Result<(), FrameError> {
        if self.lock_state()?.queues.remove(connection_id).is_none() {
            return Err(FrameError::ObserverNotFound);
        }
        Ok(())
    }

    pub fn ingest<F>(
        &self,
        frame: ViewerFrame,
        acknowledge_chromium: F,
    ) -> Result<PublishOutcome, FrameError>
    where
        F: FnOnce(u64) -> Result<(), FrameError>,
    {
        if frame.metadata.len() > self.policy.max_metadata_bytes {
            return Err(FrameError::MetadataTooLarge);
        }
        if frame.jpeg_payload.len() > self.policy.max_payload_bytes {
            return Err(FrameError::PayloadTooLarge);
        }

        // This mutex protects only callback ordering, not broadcaster state. A callback panic
        // therefore leaves no protected data inconsistent and its poison can be safely cleared.
        let _ingest_order = self
            .ingest_order
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        {
            let state = self.lock_state()?;
            if frame.page_id != state.page_id {
                return Err(FrameError::PageMismatch);
            }
            if frame.transform_epoch != state.transform_epoch {
                return Err(FrameError::StaleTransform);
            }
            if state
                .last_frame_id
                .is_some_and(|last_frame_id| frame.frame_id <= last_frame_id)
            {
                return Err(FrameError::ReplayedFrame);
            }
        }

        acknowledge_chromium(frame.frame_id)?;

        let mut state = self.lock_state()?;
        if frame.page_id != state.page_id {
            return Err(FrameError::PageMismatch);
        }
        if frame.transform_epoch != state.transform_epoch {
            return Err(FrameError::StaleTransform);
        }
        if state
            .last_frame_id
            .is_some_and(|last_frame_id| frame.frame_id <= last_frame_id)
        {
            return Err(FrameError::ReplayedFrame);
        }
        state.last_frame_id = Some(frame.frame_id);
        let mut dropped_frames = 0;
        for queue in state.queues.values_mut() {
            if queue.len() == self.policy.queue_depth {
                queue.pop_front();
                dropped_frames += 1;
            }
            queue.push_back(frame.clone());
        }
        Ok(PublishOutcome {
            observer_count: state.queues.len(),
            dropped_frames,
        })
    }

    pub fn next_frame(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<Option<ViewerFrame>, FrameError> {
        self.lock_state()?
            .queues
            .get_mut(connection_id)
            .map(VecDeque::pop_front)
            .ok_or(FrameError::ObserverNotFound)
    }

    pub fn advance_transform(&self, page_id: PageId) -> Result<u64, FrameError> {
        let mut state = self.lock_state()?;
        let next_epoch = state
            .transform_epoch
            .checked_add(1)
            .ok_or(FrameError::TransformEpochExhausted)?;
        state.page_id = page_id;
        state.transform_epoch = next_epoch;
        state.last_frame_id = None;
        for queue in state.queues.values_mut() {
            queue.clear();
        }
        Ok(next_epoch)
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, FrameState>, FrameError> {
        self.state.lock().map_err(|_| FrameError::StateUnavailable)
    }
}
