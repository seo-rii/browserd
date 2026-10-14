use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::Duration;

use browserd_core::{PlacementFence, SessionId, TenantId, WorkerId};

use crate::{
    DocumentEpoch, FlattenedSessionId, FrameId, PageId, SessionIncarnation, TargetIncarnation,
    TargetTime, UrlRevision,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BackendNodeId(u64);

impl BackendNodeId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotId(u64);

impl SnapshotId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Ownership captured when a node token is minted; every full fence component must match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeOwnerBinding {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub worker_id: WorkerId,
    pub placement_fence: PlacementFence,
}

/// A parent document and its exact internal route at node-token creation.
///
/// The owner registry must allocate globally monotonic document epochs on attachment,
/// reattachment, navigation, target swap and default execution-realm replacement. Reusing
/// a FrameId or a numeric execution-context ID must never revive an earlier epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameEpochFence {
    pub frame_id: FrameId,
    pub target_incarnation: TargetIncarnation,
    pub frame_document_epoch: DocumentEpoch,
    pub cdp_session_id: FlattenedSessionId,
}

/// Internal provenance only. Public APIs expose the opaque node token, never these routes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeFrameScope {
    pub owner: NodeOwnerBinding,
    pub page_id: PageId,
    pub frame_id: FrameId,
    pub cdp_session_id: FlattenedSessionId,
    /// The exact ordered path from the owning page's root frame to the leaf's parent.
    /// A main-document node has an empty path.
    pub ancestors: Vec<FrameEpochFence>,
}

impl NodeFrameScope {
    fn same_route(&self, current: &Self) -> bool {
        self.owner == current.owner
            && self.page_id == current.page_id
            && self.frame_id == current.frame_id
            && self.cdp_session_id == current.cdp_session_id
            && self.ancestors.len() == current.ancestors.len()
            && self
                .ancestors
                .iter()
                .zip(&current.ancestors)
                .all(|(old, new)| {
                    old.frame_id == new.frame_id
                        && old.target_incarnation == new.target_incarnation
                        && old.cdp_session_id == new.cdp_session_id
                })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBinding {
    pub frame_scope: NodeFrameScope,
    pub session_incarnation: SessionIncarnation,
    pub target_incarnation: TargetIncarnation,
    pub frame_document_epoch: DocumentEpoch,
    pub backend_node_id: BackendNodeId,
    pub snapshot_id: SnapshotId,
    pub url_revision: UrlRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeResolutionContext {
    pub frame_scope: NodeFrameScope,
    pub session_incarnation: SessionIncarnation,
    pub target_incarnation: TargetIncarnation,
    pub frame_document_epoch: DocumentEpoch,
    pub required_snapshot_id: Option<SnapshotId>,
    pub current_url_revision: UrlRevision,
    pub attached: bool,
    pub visible: bool,
    pub obscured: bool,
    pub disabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeResolutionError {
    StaleNodeRef,
    StaleDocumentRef,
    NodeDetached,
    NodeNotVisible,
    NodeDisabled,
    NodeObscured,
    AmbiguousSelector,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NodeHandle(String);

impl NodeHandle {
    /// Reconstructs a handle from a caller-presented token. Resolution still validates the
    /// binding, so this cannot forge access to a node the token was not minted for.
    #[must_use]
    pub fn from_token(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    #[must_use]
    pub fn as_token(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedNode {
    backend_node_id: BackendNodeId,
}

impl ResolvedNode {
    #[must_use]
    pub const fn backend_node_id(self) -> BackendNodeId {
        self.backend_node_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpandingCounter(Vec<u64>);

impl ExpandingCounter {
    fn take_and_increment(&mut self) -> Self {
        let current = self.clone();
        for word in &mut self.0 {
            if let Some(next) = word.checked_add(1) {
                *word = next;
                return current;
            }
            *word = 0;
        }
        self.0.push(1);
        current
    }
}

impl Ord for ExpandingCounter {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.iter().rev().cmp(other.0.iter().rev()))
    }
}

impl PartialOrd for ExpandingCounter {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
struct NodeEntry {
    binding: NodeBinding,
    created_at: TargetTime,
    last_access: ExpandingCounter,
}

/// A session-local, single-writer TTL/LRU store.
#[derive(Debug)]
pub struct NodeHandleStore {
    capacity: usize,
    ttl_millis: Option<u64>,
    last_observed: TargetTime,
    next_handle: ExpandingCounter,
    next_access: ExpandingCounter,
    entries: BTreeMap<NodeHandle, NodeEntry>,
}

impl NodeHandleStore {
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let ttl_millis = {
            let millis = ttl.as_millis();
            if millis == 0 || millis > u128::from(u64::MAX) {
                None
            } else {
                u64::try_from(millis).ok()
            }
        };
        Self {
            capacity,
            ttl_millis,
            last_observed: TargetTime::new(0),
            next_handle: ExpandingCounter(vec![1]),
            next_access: ExpandingCounter(vec![1]),
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, binding: NodeBinding, now: TargetTime) -> NodeHandle {
        let handle_sequence = self.next_handle.take_and_increment();
        let mut token = String::new();
        for word in handle_sequence.0.iter().rev() {
            token.push_str(&format!("{word:016x}"));
        }
        let handle = NodeHandle(token);
        if self.ttl_millis.is_none() || self.capacity == 0 || now < self.last_observed {
            return handle;
        }
        self.last_observed = now;
        self.purge_expired(now);
        if self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by(|(left_handle, left), (right_handle, right)| {
                    left.last_access
                        .cmp(&right.last_access)
                        .then_with(|| left_handle.cmp(right_handle))
                })
                .map(|(handle, _)| handle.clone());
            if let Some(handle) = oldest {
                self.entries.remove(&handle);
            }
        }
        let access = self.next_access.take_and_increment();
        self.entries.insert(
            handle.clone(),
            NodeEntry {
                binding,
                created_at: now,
                last_access: access,
            },
        );
        handle
    }

    /// Looks up internal provenance so the owner can locate the frame's current route.
    /// This performs TTL and clock checks only: it neither authorizes a node operation
    /// nor refreshes LRU recency. Callers must validate ownership and call `resolve` with
    /// a context rebuilt from the current frame registry before issuing any node command.
    pub fn lookup_binding(
        &mut self,
        handle: &NodeHandle,
        now: TargetTime,
    ) -> Result<NodeBinding, NodeResolutionError> {
        Ok(self.live_entry(handle, now)?.binding.clone())
    }

    pub fn resolve(
        &mut self,
        handle: &NodeHandle,
        context: &NodeResolutionContext,
        now: TargetTime,
    ) -> Result<ResolvedNode, NodeResolutionError> {
        let entry = self.live_entry(handle, now)?;

        if !entry.binding.frame_scope.same_route(&context.frame_scope)
            || entry.binding.session_incarnation != context.session_incarnation
            || entry.binding.target_incarnation != context.target_incarnation
            || context
                .required_snapshot_id
                .is_some_and(|snapshot| snapshot != entry.binding.snapshot_id)
        {
            return Err(NodeResolutionError::StaleNodeRef);
        }
        if entry.binding.frame_document_epoch != context.frame_document_epoch
            || entry
                .binding
                .frame_scope
                .ancestors
                .iter()
                .zip(&context.frame_scope.ancestors)
                .any(|(old, new)| old.frame_document_epoch != new.frame_document_epoch)
        {
            return Err(NodeResolutionError::StaleDocumentRef);
        }
        if !context.attached {
            return Err(NodeResolutionError::NodeDetached);
        }
        if !context.visible {
            return Err(NodeResolutionError::NodeNotVisible);
        }
        if context.obscured {
            return Err(NodeResolutionError::NodeObscured);
        }
        if context.disabled {
            return Err(NodeResolutionError::NodeDisabled);
        }
        let backend_node_id = entry.binding.backend_node_id;
        let access = self.next_access.take_and_increment();
        let Some(entry) = self.entries.get_mut(handle) else {
            return Err(NodeResolutionError::StaleNodeRef);
        };
        entry.last_access = access;
        Ok(ResolvedNode { backend_node_id })
    }

    fn live_entry(
        &mut self,
        handle: &NodeHandle,
        now: TargetTime,
    ) -> Result<&NodeEntry, NodeResolutionError> {
        if self.ttl_millis.is_none() || now < self.last_observed {
            return Err(NodeResolutionError::StaleNodeRef);
        }
        self.last_observed = now;
        self.purge_expired(now);
        self.entries
            .get(handle)
            .ok_or(NodeResolutionError::StaleNodeRef)
    }

    fn purge_expired(&mut self, now: TargetTime) {
        let Some(ttl_millis) = self.ttl_millis else {
            self.entries.clear();
            return;
        };
        self.entries.retain(|_, entry| {
            now.milliseconds()
                .saturating_sub(entry.created_at.milliseconds())
                < ttl_millis
        });
    }
}

pub const fn classify_selector_match_count(count: usize) -> Result<(), NodeResolutionError> {
    match count {
        1 => Ok(()),
        2.. => Err(NodeResolutionError::AmbiguousSelector),
        0 => Err(NodeResolutionError::NodeDetached),
    }
}
