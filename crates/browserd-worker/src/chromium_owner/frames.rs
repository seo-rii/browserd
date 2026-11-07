//! Frame identities and execution realms are independent of DevTools target IDs.
//! Only this actor-owned registry may connect the two namespaces.
use super::*;
use browserd_targets::{
    FlattenedSessionId, FrameEpochFence, FrameId, NodeFrameScope, NodeOwnerBinding,
};

const MAX_FRAMES: usize = 4096;
const MAX_CONTEXT_FRAMES: usize = 1024;
const MAX_DEPTH: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Realm {
    pub(super) id: i64,
    pub(super) unique_id: String,
    frame_id: String,
    session_id: String,
}

#[derive(Clone, Debug)]
struct Frame {
    context_id: String,
    parent: Option<String>,
    page_id: Option<PageId>,
    target_id: String,
    target_incarnation: u64,
    session_id: String,
    epoch: u64,
    realm: Option<Realm>,
    swapping: bool,
}

#[derive(Default)]
pub(super) struct FrameRegistry {
    frames: BTreeMap<String, Frame>,
    roots: BTreeMap<String, String>,
    realms: BTreeMap<(String, i64), Realm>,
    next_epoch: u64,
    ready_targets: BTreeSet<String>,
}

#[derive(Clone)]
pub(super) struct FrameGuard {
    pub(super) scope: NodeFrameScope,
    target_id: String,
    target_incarnation: u64,
    pub(super) epoch: u64,
    pub(super) realm: Realm,
}

impl FrameGuard {
    pub(super) fn target_incarnation(&self) -> u64 {
        self.target_incarnation
    }
}
impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) fn approval_route_revisions(
        &self,
        guard: &FrameGuard,
    ) -> Result<Vec<(String, u64)>, OwnerActorError> {
        self.validate_frame_guard(guard)?;
        self.frames
            .chain(guard.scope.frame_id.as_str())?
            .into_iter()
            .map(|(_, frame)| {
                let route = self
                    .routes
                    .get(&frame.target_id)
                    .ok_or(OwnerActorError::Rejected)?;
                Ok((frame.target_id.clone(), route.url_revision))
            })
            .collect()
    }

    pub(super) fn approval_frame_material(
        &self,
        guard: &FrameGuard,
    ) -> Result<Value, OwnerActorError> {
        self.validate_frame_guard(guard)?;
        let chain = self.frames.chain(guard.scope.frame_id.as_str())?;
        let mut frames = Vec::with_capacity(chain.len());
        for (id, frame) in chain {
            let realm = frame.realm.as_ref().ok_or(OwnerActorError::Rejected)?;
            let route = self
                .routes
                .get(&frame.target_id)
                .ok_or(OwnerActorError::Rejected)?;
            frames.push(json!({"frame_id":id,"target":frame.target_id,"target_incarnation":frame.target_incarnation,
                "document_epoch":frame.epoch,"session":frame.session_id,"realm_id":realm.id,"realm_unique":realm.unique_id,"url_revision":route.url_revision}));
        }
        Ok(json!({"page":guard.scope.page_id,"chain":frames}))
    }
}

impl FrameRegistry {
    pub(super) fn mark_ready(&mut self, target: &str) {
        self.ready_targets.insert(target.to_owned());
    }
    fn epoch(&mut self) -> Result<u64, OwnerActorError> {
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(OwnerActorError::StateOverflow)?;
        Ok(self.next_epoch)
    }

    fn remove_descendants(&mut self, frame_id: &str) {
        let mut removed = BTreeSet::from([frame_id.to_owned()]);
        loop {
            let before = removed.len();
            for (id, frame) in &self.frames {
                if frame
                    .parent
                    .as_ref()
                    .is_some_and(|parent| removed.contains(parent))
                {
                    removed.insert(id.clone());
                }
            }
            if before == removed.len() {
                break;
            }
        }
        removed.remove(frame_id);
        self.frames.retain(|id, _| !removed.contains(id));
        self.roots.retain(|_, id| !removed.contains(id));
        self.realms
            .retain(|_, realm| !removed.contains(&realm.frame_id));
    }

    pub(super) fn retire_target(&mut self, target: &str) -> Result<(), OwnerActorError> {
        let ids: Vec<_> = self
            .frames
            .iter()
            .filter(|(_, frame)| frame.target_id == target)
            .map(|(id, _)| id.clone())
            .collect();
        self.roots.remove(target);
        self.ready_targets.remove(target);
        for id in ids {
            let epoch = self.epoch()?;
            if let Some(frame) = self.frames.get_mut(&id) {
                frame.epoch = epoch;
                frame.realm = None;
                frame.swapping = true;
                let session = frame.session_id.clone();
                self.realms.retain(|(flat, _), _| flat != &session);
            }
        }
        Ok(())
    }

    pub(super) fn retire_context(&mut self, context: &str) {
        let targets: BTreeSet<_> = self
            .frames
            .values()
            .filter(|frame| frame.context_id == context)
            .map(|frame| frame.target_id.clone())
            .collect();
        let sessions: BTreeSet<_> = self
            .frames
            .values()
            .filter(|frame| frame.context_id == context)
            .map(|frame| frame.session_id.clone())
            .collect();
        self.frames.retain(|_, frame| frame.context_id != context);
        self.roots.retain(|target, _| !targets.contains(target));
        self.ready_targets
            .retain(|target| !targets.contains(target));
        self.realms.retain(|(flat, _), _| !sessions.contains(flat));
    }

    fn register(
        &mut self,
        id: String,
        parent: Option<String>,
        target: &str,
        route: &TargetRouteEntry,
        root: bool,
        committed: bool,
    ) -> Result<(), OwnerActorError> {
        if !valid_identifier(&id)
            || parent
                .as_ref()
                .is_some_and(|p| !valid_identifier(p) || p == &id)
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let old = self.frames.get(&id).cloned();
        if let Some(old) = &old {
            if old.context_id != route.route.browser_context_id {
                return Err(OwnerActorError::UnknownOwnership);
            }
            if old.parent.is_some() && parent.is_some() && old.parent != parent {
                return Err(OwnerActorError::UnknownOwnership);
            }
            // Parent frame-tree snapshots can include a remote child. They do not
            // transfer that child's live execution route back to the parent.
            if old.target_id != target && !root && !old.swapping {
                return Ok(());
            }
        } else if self.frames.len() >= MAX_FRAMES
            || self
                .frames
                .values()
                .filter(|f| f.context_id == route.route.browser_context_id)
                .count()
                >= MAX_CONTEXT_FRAMES
        {
            return Err(OwnerActorError::StateOverflow);
        }
        let parent = parent.or_else(|| old.as_ref().and_then(|f| f.parent.clone()));
        if let Some(parent) = parent.as_ref().and_then(|id| self.frames.get(id))
            && parent.context_id != route.route.browser_context_id
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if committed {
            self.remove_descendants(&id);
        }
        let changed = committed
            || old
                .as_ref()
                .is_none_or(|old| old.target_id != target || old.swapping);
        let epoch = if changed {
            self.epoch()?
        } else {
            old.as_ref().map_or(0, |f| f.epoch)
        };
        let realm = self
            .realms
            .values()
            .find(|realm| realm.frame_id == id && realm.session_id == route.route.session_id)
            .cloned();
        let page_id = if root { route.page_id.clone() } else { None }
            .or_else(|| old.as_ref().and_then(|f| f.page_id.clone()));
        self.frames.insert(
            id.clone(),
            Frame {
                context_id: route.route.browser_context_id.clone(),
                parent,
                page_id,
                target_id: target.to_owned(),
                target_incarnation: route.target_incarnation,
                session_id: route.route.session_id.clone(),
                epoch,
                realm,
                swapping: false,
            },
        );
        if root {
            self.roots.insert(target.to_owned(), id);
        }
        Ok(())
    }

    fn chain(&self, id: &str) -> Result<Vec<(String, Frame)>, OwnerActorError> {
        let mut chain = Vec::new();
        let mut current = id;
        let mut seen = BTreeSet::new();
        loop {
            if chain.len() > MAX_DEPTH || !seen.insert(current.to_owned()) {
                return Err(OwnerActorError::Rejected);
            }
            let frame = self.frames.get(current).ok_or(OwnerActorError::Rejected)?;
            if frame.swapping || frame.realm.is_none() {
                return Err(OwnerActorError::Rejected);
            }
            chain.push((current.to_owned(), frame.clone()));
            match frame.parent.as_deref() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        chain.reverse();
        Ok(chain)
    }
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) async fn seed_frames(
        &mut self,
        target: &str,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        let route = self
            .routes
            .get(target)
            .cloned()
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let tree = self
            .command_event_first(
                "Page.getFrameTree",
                json!({}),
                Some(route.route.session_id.clone()),
                None,
                None,
                deadline,
            )
            .await?;
        let tree = tree
            .get("frameTree")
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let mut pending = vec![(tree, None, 0usize)];
        let mut count = 0;
        while let Some((tree, parent, depth)) = pending.pop() {
            count += 1;
            if count > MAX_CONTEXT_FRAMES {
                return Err(OwnerActorError::StateOverflow);
            }
            let frame = tree
                .get("frame")
                .and_then(Value::as_object)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            let id = required_string(frame, "id")?;
            let parent = optional_string(frame, "parentId")?.or(parent);
            self.frames
                .register(id.clone(), parent, target, &route, depth == 0, false)?;
            if let Some(children) = tree.get("childFrames") {
                for child in children
                    .as_array()
                    .ok_or(OwnerActorError::OutcomeUncertain)?
                {
                    pending.push((child, Some(id.clone()), depth + 1));
                }
            }
        }
        Ok(())
    }

    pub(super) fn frame_event(
        &mut self,
        method: &str,
        session: Option<&str>,
        params: &Value,
    ) -> Result<(), OwnerActorError> {
        let session = session
            .filter(|s| valid_identifier(s))
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let Some((target, route)) = self
            .routes
            .iter()
            .find(|(_, r)| r.route.session_id == session)
            .map(|(target, route)| (target.clone(), route.clone()))
        else {
            return if self.retired_targets.values().any(|s| s == session) {
                Ok(())
            } else {
                Err(OwnerActorError::UnknownOwnership)
            };
        };
        // Worker execution contexts have no document/frame namespace. Their
        // lifecycle still belongs to TargetManager, never the page registry.
        if !matches!(route.kind, TargetKind::Page | TargetKind::Iframe) {
            return Ok(());
        }
        let params = params
            .as_object()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        match method {
            "Runtime.executionContextCreated" => {
                let context = params
                    .get("context")
                    .and_then(Value::as_object)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let Some(aux) = context.get("auxData").and_then(Value::as_object) else {
                    return Ok(());
                };
                if aux.get("isDefault").and_then(Value::as_bool) != Some(true) {
                    return Ok(());
                }
                let frame_id = required_string(aux, "frameId")?;
                let id = context
                    .get("id")
                    .and_then(Value::as_i64)
                    .filter(|id| *id > 0)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let realm = Realm {
                    id,
                    unique_id: required_string(context, "uniqueId")?,
                    frame_id: frame_id.clone(),
                    session_id: session.to_owned(),
                };
                self.frames
                    .realms
                    .retain(|(flat, _), old| flat != session || old.frame_id != frame_id);
                let same_context_realms = self
                    .frames
                    .realms
                    .values()
                    .filter(|realm| {
                        self.routes.values().any(|candidate| {
                            candidate.route.session_id == realm.session_id
                                && candidate.route.browser_context_id
                                    == route.route.browser_context_id
                        })
                    })
                    .count();
                if self.frames.realms.len() >= MAX_FRAMES
                    || same_context_realms >= MAX_CONTEXT_FRAMES
                {
                    return Err(OwnerActorError::StateOverflow);
                }
                self.frames
                    .realms
                    .insert((session.to_owned(), id), realm.clone());
                if self
                    .frames
                    .frames
                    .get(&frame_id)
                    .is_some_and(|f| f.session_id == session)
                {
                    let epoch = self.frames.epoch()?;
                    if let Some(frame) = self.frames.frames.get_mut(&frame_id) {
                        frame.realm = Some(realm);
                        frame.epoch = epoch;
                    }
                }
            }
            "Runtime.executionContextDestroyed" | "Runtime.executionContextsCleared" => {
                let id = params.get("executionContextId").and_then(Value::as_i64);
                let unique = params
                    .get("executionContextUniqueId")
                    .and_then(Value::as_str);
                let matches = |realm: &Realm| {
                    realm.session_id == session
                        && (method.ends_with("Cleared")
                            || (id == Some(realm.id)
                                && unique.is_none_or(|u| u == realm.unique_id)))
                };
                self.frames.realms.retain(|_, realm| !matches(realm));
                let ids: Vec<_> = self
                    .frames
                    .frames
                    .iter()
                    .filter(|(_, f)| f.realm.as_ref().is_some_and(matches))
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in ids {
                    let epoch = self.frames.epoch()?;
                    if let Some(frame) = self.frames.frames.get_mut(&id) {
                        frame.realm = None;
                        frame.epoch = epoch;
                    }
                }
            }
            "Page.frameAttached" => {
                let id = required_string(params, "frameId")?;
                let parent = required_string(params, "parentFrameId")?;
                self.frames
                    .register(id, Some(parent), &target, &route, false, false)?;
            }
            "Page.frameNavigated" => {
                let frame = params
                    .get("frame")
                    .and_then(Value::as_object)
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let id = required_string(frame, "id")?;
                let parent = optional_string(frame, "parentId")?;
                let root = self
                    .frames
                    .roots
                    .get(&target)
                    .is_some_and(|root| root == &id)
                    || (parent.is_none() && matches!(route.kind, TargetKind::Page));
                self.frames
                    .register(id, parent, &target, &route, root, true)?;
            }
            "Page.frameDetached" => {
                let id = required_string(params, "frameId")?;
                let Some(frame) = self.frames.frames.get(&id).cloned() else {
                    return Ok(());
                };
                let from_parent = frame
                    .parent
                    .as_ref()
                    .and_then(|p| self.frames.frames.get(p))
                    .is_some_and(|p| p.session_id == session);
                let own = frame.session_id == session;
                if !own && !from_parent {
                    return Ok(());
                }
                match params.get("reason").and_then(Value::as_str) {
                    Some("swap") if own => {
                        self.frames.remove_descendants(&id);
                        let epoch = self.frames.epoch()?;
                        if let Some(frame) = self.frames.frames.get_mut(&id) {
                            frame.swapping = true;
                            frame.realm = None;
                            frame.epoch = epoch;
                        }
                    }
                    Some("swap") => {}
                    Some("remove") => {
                        self.frames.remove_descendants(&id);
                        self.frames.frames.remove(&id);
                        self.frames.roots.retain(|_, root| root != &id);
                        self.frames.realms.retain(|_, realm| realm.frame_id != id);
                    }
                    _ => return Err(OwnerActorError::OutcomeUncertain),
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn frame_guard(&self, top_target: &str, frame_id: &str) -> Result<FrameGuard, OwnerActorError> {
        let top = self
            .routes
            .get(top_target)
            .ok_or(OwnerActorError::Rejected)?;
        let page = top.page_id.as_ref().ok_or(OwnerActorError::Rejected)?;
        let context = self
            .contexts
            .get(&top.route.browser_context_id)
            .ok_or(OwnerActorError::Rejected)?;
        if context.lifecycle != ContextLifecycle::Active
            || context.closing_pages.contains(page)
            || context.pages.get(page).map(String::as_str) != Some(top_target)
            || context.ownership.tenant_id != top.route.tenant_id
            || context.ownership.session_id != top.route.owner_session_id
            || context.ownership.fence != top.route.ownership_fence
        {
            return Err(OwnerActorError::Rejected);
        }
        self.context_egress
            .check_active(&context.ownership, Instant::now())?;
        let chain = self.frames.chain(frame_id)?;
        let (root_id, root) = chain.first().ok_or(OwnerActorError::Rejected)?;
        if self.frames.roots.get(top_target) != Some(root_id) || root.page_id.as_ref() != Some(page)
        {
            return Err(OwnerActorError::Rejected);
        }
        let mut ancestors = Vec::new();
        for (id, frame) in &chain {
            if !self.frames.ready_targets.contains(&frame.target_id) {
                return Err(OwnerActorError::Rejected);
            }
            let realm = frame.realm.as_ref().ok_or(OwnerActorError::Rejected)?;
            if self
                .frames
                .realms
                .get(&(realm.session_id.clone(), realm.id))
                != Some(realm)
            {
                return Err(OwnerActorError::Rejected);
            }
            let route = self
                .routes
                .get(&frame.target_id)
                .ok_or(OwnerActorError::Rejected)?;
            if frame.context_id != top.route.browser_context_id
                || route.route.tenant_id != top.route.tenant_id
                || route.route.owner_session_id != top.route.owner_session_id
                || route.route.ownership_fence != top.route.ownership_fence
                || route.target_incarnation != frame.target_incarnation
                || route.route.session_id != frame.session_id
            {
                return Err(OwnerActorError::Rejected);
            }
            if id != frame_id {
                ancestors.push(FrameEpochFence {
                    frame_id: FrameId::new(id.clone()),
                    target_incarnation: TargetIncarnation::new(frame.target_incarnation),
                    frame_document_epoch: DocumentEpoch::new(frame.epoch),
                    cdp_session_id: FlattenedSessionId::new(frame.session_id.clone()),
                });
            }
        }
        let (_, leaf) = chain.last().ok_or(OwnerActorError::Rejected)?;
        Ok(FrameGuard {
            scope: NodeFrameScope {
                owner: NodeOwnerBinding {
                    tenant_id: top.route.tenant_id.clone(),
                    session_id: top.route.owner_session_id.clone(),
                    worker_id: top.route.ownership_fence.worker_id().clone(),
                    placement_fence: top.route.ownership_fence.as_placement_fence(),
                },
                page_id: page.clone(),
                frame_id: FrameId::new(frame_id.to_owned()),
                cdp_session_id: FlattenedSessionId::new(leaf.session_id.clone()),
                ancestors,
            },
            target_id: leaf.target_id.clone(),
            target_incarnation: leaf.target_incarnation,
            epoch: leaf.epoch,
            realm: leaf.realm.clone().ok_or(OwnerActorError::Rejected)?,
        })
    }

    pub(super) fn main_frame_guard(&self, target: &str) -> Result<FrameGuard, OwnerActorError> {
        let root = self
            .frames
            .roots
            .get(target)
            .ok_or(OwnerActorError::Rejected)?;
        self.frame_guard(target, root)
    }

    pub(super) fn validate_frame_guard(&self, guard: &FrameGuard) -> Result<(), OwnerActorError> {
        let top = self
            .contexts
            .values()
            .filter(|context| {
                context.lifecycle == ContextLifecycle::Active
                    && !context.closing_pages.contains(&guard.scope.page_id)
            })
            .find_map(|context| context.pages.get(&guard.scope.page_id))
            .ok_or(OwnerActorError::Rejected)?;
        let current = self.frame_guard(top, guard.scope.frame_id.as_str())?;
        if current.scope != guard.scope
            || current.epoch != guard.epoch
            || current.target_incarnation != guard.target_incarnation
            || current.realm != guard.realm
        {
            return Err(OwnerActorError::Rejected);
        }
        Ok(())
    }

    /// Classifies only an observed epoch change within the same exact owner.
    /// Missing ownership, route retirement and transport failures are not document changes.
    pub(super) fn observed_document_change(&self, guard: &FrameGuard) -> bool {
        let Ok((context_id, top, route)) =
            self.owned_page_route(&guard.scope.owner.session_id, &guard.scope.page_id)
        else {
            return false;
        };
        if route.tenant_id() != &guard.scope.owner.tenant_id
            || route.ownership_fence().worker_id() != &guard.scope.owner.worker_id
            || route.ownership_fence().as_placement_fence() != guard.scope.owner.placement_fence
        {
            return false;
        }
        let changed = |id: &str, session: &str, incarnation: u64, epoch: u64| {
            self.frames.frames.get(id).is_some_and(|frame| {
                frame.context_id == context_id
                    && frame.session_id == session
                    && frame.target_incarnation == incarnation
                    && self.routes.get(&frame.target_id).is_some_and(|current| {
                        current.target_incarnation == incarnation
                            && current.route.browser_context_id() == context_id
                            && current.route.tenant_id() == route.tenant_id()
                            && current.route.owner_session_id() == route.owner_session_id()
                            && current.route.ownership_fence() == route.ownership_fence()
                            && current.route.session_id() == session
                    })
                    && frame.epoch != epoch
            })
        };
        if guard.scope.ancestors.iter().any(|ancestor| {
            changed(
                ancestor.frame_id.as_str(),
                ancestor.cdp_session_id.as_str(),
                ancestor.target_incarnation.get(),
                ancestor.frame_document_epoch.get(),
            )
        }) || changed(
            guard.scope.frame_id.as_str(),
            guard.realm.session_id.as_str(),
            guard.target_incarnation,
            guard.epoch,
        ) {
            return true;
        }
        // Some document replacements receive a new root FrameId. It is still
        // the exact owned target/session, never a newly attributed page.
        guard.target_id == top
            && guard.scope.ancestors.is_empty()
            && self.frames.roots.get(&top).is_some_and(|root| {
                root != guard.scope.frame_id.as_str()
                    && changed(
                        root,
                        guard.realm.session_id.as_str(),
                        guard.target_incarnation,
                        guard.epoch,
                    )
            })
    }

    pub(super) fn node_frame_guard(
        &mut self,
        top: &str,
        node_ref: &str,
        main_only: bool,
    ) -> Result<(FrameGuard, u64), OwnerActorError> {
        let handle = NodeHandle::from_token(node_ref);
        let binding = self
            .node_store
            .lookup_binding(&handle, node_store_now())
            .map_err(|_| OwnerActorError::Rejected)?;
        let guard = if main_only {
            self.main_frame_guard(top)?
        } else {
            self.frame_guard(top, binding.frame_scope.frame_id.as_str())?
        };
        let route = self.routes.get(top).ok_or(OwnerActorError::Rejected)?;
        let context = NodeResolutionContext {
            frame_scope: guard.scope.clone(),
            session_incarnation: SessionIncarnation::new(
                route.route.ownership_fence.session_incarnation(),
            ),
            target_incarnation: TargetIncarnation::new(guard.target_incarnation),
            frame_document_epoch: DocumentEpoch::new(guard.epoch),
            required_snapshot_id: None,
            current_url_revision: UrlRevision::new(route.url_revision),
            attached: true,
            visible: true,
            obscured: false,
            disabled: false,
        };
        let node = self
            .node_store
            .resolve(&handle, &context, node_store_now())
            .map_err(|_| OwnerActorError::Rejected)?;
        Ok((guard, node.backend_node_id().get()))
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(super) fn seed_test_main_frame(&mut self, target: &str) -> NodeFrameScope {
        let route = self.routes.get(target).expect("fixture route").clone();
        let frame_id = format!("frame-{target}");
        self.frames
            .register(frame_id.clone(), None, target, &route, true, false)
            .expect("fixture root");
        self.frame_event("Runtime.executionContextCreated", Some(&route.route.session_id), &json!({"context":{"id":1,"uniqueId":"fixture-realm","auxData":{"isDefault":true,"frameId":frame_id}}})).expect("fixture realm");
        self.frames.mark_ready(target);
        self.main_frame_guard(target).expect("fixture guard").scope
    }
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    async fn frame_document_node(
        &mut self,
        frame: &FrameGuard,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<i64, OwnerActorError> {
        self.validate_frame_guard(frame)?;
        self.active_frame_guard = Some(frame.clone());
        let session = frame.realm.session_id.clone();
        let document = self
            .command_event_first(
                "DOM.getDocument",
                json!({"depth":0}),
                Some(session.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        if self
            .frames
            .roots
            .get(&frame.target_id)
            .is_some_and(|root| root == frame.scope.frame_id.as_str())
        {
            return document
                .pointer("/root/nodeId")
                .and_then(Value::as_i64)
                .ok_or(OwnerActorError::OutcomeUncertain);
        }
        let document = self.command_event_first("Runtime.evaluate", json!({"expression":"document", "uniqueContextId":frame.realm.unique_id, "returnByValue":false}), Some(session.clone()), None, guarded.clone(), deadline).await?;
        let object = document
            .pointer("/result/objectId")
            .and_then(Value::as_str)
            .ok_or(OwnerActorError::Rejected)?
            .to_owned();
        let node = self
            .command_event_first(
                "DOM.requestNode",
                json!({"objectId":object}),
                Some(session.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        self.command_event_first(
            "Runtime.releaseObject",
            json!({"objectId":object}),
            Some(session),
            None,
            guarded,
            deadline,
        )
        .await?;
        node.get("nodeId")
            .and_then(Value::as_i64)
            .filter(|id| *id > 0)
            .ok_or(OwnerActorError::Rejected)
    }

    pub(super) async fn execute_frame_query(
        &mut self,
        top: &str,
        guarded: Option<GuardedPageExecution>,
        selector: &str,
        path: &[String],
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        if path.len() > MAX_DEPTH
            || path.iter().any(|s| s.is_empty() || s.len() > 8192)
            || path.iter().map(String::len).sum::<usize>() > 32768
        {
            return Err(OwnerActorError::Rejected);
        }
        let mut frame = self.main_frame_guard(top)?;
        for hop in path {
            let document = self
                .frame_document_node(&frame, guarded.clone(), deadline)
                .await?;
            let selected = self
                .command_event_first(
                    "DOM.querySelectorAll",
                    json!({"nodeId":document,"selector":hop}),
                    Some(frame.realm.session_id.clone()),
                    None,
                    guarded.clone(),
                    deadline,
                )
                .await?;
            let nodes = selected
                .get("nodeIds")
                .and_then(Value::as_array)
                .filter(|nodes| nodes.len() == 1)
                .ok_or(OwnerActorError::Rejected)?;
            let node = self
                .command_event_first(
                    "DOM.describeNode",
                    json!({"nodeId":nodes[0],"depth":0}),
                    Some(frame.realm.session_id.clone()),
                    None,
                    guarded.clone(),
                    deadline,
                )
                .await?;
            let node = node
                .get("node")
                .and_then(Value::as_object)
                .ok_or(OwnerActorError::Rejected)?;
            if !matches!(
                node.get("nodeName").and_then(Value::as_str),
                Some("IFRAME" | "FRAME")
            ) {
                return Err(OwnerActorError::Rejected);
            }
            let child = required_string(node, "frameId")?;
            self.validate_frame_guard(&frame)?;
            let entry = self
                .frames
                .frames
                .get_mut(&child)
                .ok_or(OwnerActorError::Rejected)?;
            if entry.context_id
                != self
                    .routes
                    .get(top)
                    .ok_or(OwnerActorError::Rejected)?
                    .route
                    .browser_context_id
                || entry
                    .parent
                    .as_ref()
                    .is_some_and(|parent| parent != frame.scope.frame_id.as_str())
            {
                return Err(OwnerActorError::Rejected);
            }
            // DOM.describeNode proves the exact frame-owner edge even when the
            // OOPIF root's own Page.getFrameTree omits parentId.
            entry.parent = Some(frame.scope.frame_id.as_str().to_owned());
            frame = self.frame_guard(top, &child)?;
        }
        let document = self
            .frame_document_node(&frame, guarded.clone(), deadline)
            .await?;
        let selected = self
            .command_event_first(
                "DOM.querySelectorAll",
                json!({"nodeId":document,"selector":selector}),
                Some(frame.realm.session_id.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        let ids = selected
            .get("nodeIds")
            .and_then(Value::as_array)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let total = ids.len();
        let mut backends = Vec::new();
        for id in ids.iter().take(MAX_QUERY_ALL_MATCHES) {
            let node = self
                .command_event_first(
                    "DOM.describeNode",
                    json!({"nodeId":id}),
                    Some(frame.realm.session_id.clone()),
                    None,
                    guarded.clone(),
                    deadline,
                )
                .await?;
            backends.push(
                node.pointer("/node/backendNodeId")
                    .and_then(Value::as_u64)
                    .ok_or(OwnerActorError::OutcomeUncertain)?,
            );
        }
        self.validate_frame_guard(&frame)?;
        let route = self
            .routes
            .get(&frame.target_id)
            .ok_or(OwnerActorError::Rejected)?;
        let session_incarnation =
            SessionIncarnation::new(route.route.ownership_fence.session_incarnation());
        let url_revision = route.url_revision;
        let mut handles = Vec::new();
        for backend in backends {
            let handle = self.node_store.insert(
                NodeBinding {
                    frame_scope: frame.scope.clone(),
                    session_incarnation,
                    target_incarnation: TargetIncarnation::new(frame.target_incarnation),
                    frame_document_epoch: DocumentEpoch::new(frame.epoch),
                    backend_node_id: BackendNodeId::new(backend),
                    snapshot_id: SnapshotId::new(0),
                    url_revision: UrlRevision::new(url_revision),
                },
                node_store_now(),
            );
            handles.push(handle.as_token().to_owned());
        }
        Ok(
            json!({"node_refs":handles,"returned_count":handles.len(),"limit":MAX_QUERY_ALL_MATCHES,"truncated":total > MAX_QUERY_ALL_MATCHES,"document_epoch":frame.epoch,"url_revision":url_revision}),
        )
    }
}

/// A CSS-pixel affine map. The fourth corner checks that a perspective quad is
/// not being silently approximated by a scale/translation or a bounding box.
#[derive(Clone, Copy, Debug)]
struct Affine {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}
impl Affine {
    const IDENTITY: Self = Self {
        a: 1.,
        b: 0.,
        c: 0.,
        d: 1.,
        x: 0.,
        y: 0.,
        width: 0.,
        height: 0.,
    };
    fn quad(values: &Value, width: f64, height: f64) -> Result<Self, OwnerActorError> {
        let values = values
            .as_array()
            .filter(|v| v.len() == 8)
            .ok_or(OwnerActorError::Rejected)?;
        let q: Vec<_> = values
            .iter()
            .map(|v| {
                v.as_f64()
                    .filter(|v| v.is_finite())
                    .ok_or(OwnerActorError::Rejected)
            })
            .collect::<Result<_, _>>()?;
        if !(width.is_finite() && height.is_finite() && width > 0. && height > 0.)
            || (q[4] - q[2] - q[6] + q[0]).abs() > 0.25
            || (q[5] - q[3] - q[7] + q[1]).abs() > 0.25
        {
            return Err(OwnerActorError::Rejected);
        }
        let map = Self {
            a: (q[2] - q[0]) / width,
            b: (q[3] - q[1]) / width,
            c: (q[6] - q[0]) / height,
            d: (q[7] - q[1]) / height,
            x: q[0],
            y: q[1],
            width,
            height,
        };
        if map.determinant().abs() < 0.000001 {
            return Err(OwnerActorError::Rejected);
        }
        Ok(map)
    }
    fn determinant(self) -> f64 {
        self.a * self.d - self.b * self.c
    }
    fn point(self, p: (f64, f64)) -> (f64, f64) {
        (
            self.a * p.0 + self.c * p.1 + self.x,
            self.b * p.0 + self.d * p.1 + self.y,
        )
    }
    fn inverse(self, p: (f64, f64)) -> (f64, f64) {
        let p = (p.0 - self.x, p.1 - self.y);
        let det = self.determinant();
        (
            (self.d * p.0 - self.c * p.1) / det,
            (-self.b * p.0 + self.a * p.1) / det,
        )
    }
    fn then(self, parent: Self) -> Self {
        Self {
            a: parent.a * self.a + parent.c * self.b,
            b: parent.b * self.a + parent.d * self.b,
            c: parent.a * self.c + parent.c * self.d,
            d: parent.b * self.c + parent.d * self.d,
            x: parent.a * self.x + parent.c * self.y + parent.x,
            y: parent.b * self.x + parent.d * self.y + parent.y,
            width: self.width,
            height: self.height,
        }
    }
    fn stable(self, other: Self) -> bool {
        // Matrix coefficients have different units; compare the actual content
        // corners in top-page CSS pixels instead of allowing scale-dependent motion.
        [(0., 0.), (1., 0.), (1., 1.), (0., 1.)]
            .iter()
            .all(|&(u, v)| {
                let before = self.point((u * self.width, v * self.height));
                let after = other.point((u * other.width, v * other.height));
                (before.0 - after.0).abs() <= 0.25 && (before.1 - after.1).abs() <= 0.25
            })
    }
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    async fn frame_value(
        &mut self,
        frame: &FrameGuard,
        expression: &str,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        self.validate_frame_guard(frame)?;
        let result=self.command_event_first("Runtime.evaluate",json!({"expression":expression,"uniqueContextId":frame.realm.unique_id,"returnByValue":true,"awaitPromise":false}),Some(frame.realm.session_id.clone()),None,guarded,deadline).await?;
        if result.get("exceptionDetails").is_some() {
            return Err(OwnerActorError::Rejected);
        }
        self.validate_frame_guard(frame)?;
        result
            .pointer("/result/value")
            .cloned()
            .ok_or(OwnerActorError::Rejected)
    }

    async fn frame_owner_backend(
        &mut self,
        parent: &FrameGuard,
        child: &str,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<u64, OwnerActorError> {
        self.validate_frame_guard(parent)?;
        let response = self
            .command_event_first(
                "DOM.getFrameOwner",
                json!({"frameId":child}),
                Some(parent.realm.session_id.clone()),
                None,
                guarded,
                deadline,
            )
            .await?;
        response
            .get("backendNodeId")
            .and_then(Value::as_u64)
            .ok_or(OwnerActorError::Rejected)
    }

    async fn frame_owner_call(
        &mut self,
        parent: &FrameGuard,
        backend: u64,
        function: &str,
        args: Vec<Value>,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        self.validate_frame_guard(parent)?;
        let resolved = self
            .command_event_first(
                "DOM.resolveNode",
                json!({"backendNodeId":backend,"executionContextId":parent.realm.id}),
                Some(parent.realm.session_id.clone()),
                None,
                guarded.clone(),
                deadline,
            )
            .await?;
        let object = resolved
            .pointer("/object/objectId")
            .and_then(Value::as_str)
            .ok_or(OwnerActorError::Rejected)?
            .to_owned();
        let mut arguments = vec![json!({"objectId":object})];
        arguments.extend(args);
        let response=self.command_event_first("Runtime.callFunctionOn",json!({"uniqueContextId":parent.realm.unique_id,"functionDeclaration":function,"arguments":arguments,"returnByValue":true,"awaitPromise":true}),Some(parent.realm.session_id.clone()),None,guarded.clone(),deadline).await?;
        self.command_event_first(
            "Runtime.releaseObject",
            json!({"objectId":object}),
            Some(parent.realm.session_id.clone()),
            None,
            guarded,
            deadline,
        )
        .await?;
        self.validate_frame_guard(parent)?;
        if response.get("exceptionDetails").is_some() {
            return Err(OwnerActorError::Rejected);
        }
        response
            .pointer("/result/value")
            .cloned()
            .ok_or(OwnerActorError::Rejected)
    }

    pub(super) async fn scroll_frame_ancestors(
        &mut self,
        top: &str,
        node: &str,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        let (leaf, _) = self.node_frame_guard(top, node, false)?;
        self.active_frame_guard = Some(leaf.clone());
        let chain = self.frames.chain(leaf.scope.frame_id.as_str())?;
        for pair in chain.windows(2) {
            let parent = self.frame_guard(top, &pair[0].0)?;
            let backend = self
                .frame_owner_backend(&parent, &pair[1].0, guarded.clone(), deadline)
                .await?;
            let result=self.frame_owner_call(&parent,backend,"function (el) { if (!el.isConnected || el.ownerDocument !== document || !['IFRAME','FRAME'].includes(el.tagName)) return false; el.scrollIntoView({block:'center',inline:'center'}); return true; }",vec![],guarded.clone(),deadline).await?;
            if result != Value::Bool(true) {
                return Err(OwnerActorError::Rejected);
            }
        }
        Ok(())
    }

    async fn frame_geometry(
        &mut self,
        top: &str,
        leaf: &FrameGuard,
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<Vec<(FrameGuard, Affine, Option<u64>)>, OwnerActorError> {
        let chain = self.frames.chain(leaf.scope.frame_id.as_str())?;
        let mut maps: Vec<(FrameGuard, Affine, Option<u64>)> = Vec::new();
        for (id, _) in &chain {
            let frame = self.frame_guard(top, id)?;
            let viewport=self.frame_value(&frame,"({width:innerWidth,height:innerHeight,scale:visualViewport ? visualViewport.scale : 1,offsetX:visualViewport ? visualViewport.offsetLeft : 0,offsetY:visualViewport ? visualViewport.offsetTop : 0})",guarded.clone(),deadline).await?;
            let width = viewport
                .get("width")
                .and_then(Value::as_f64)
                .ok_or(OwnerActorError::Rejected)?;
            let height = viewport
                .get("height")
                .and_then(Value::as_f64)
                .ok_or(OwnerActorError::Rejected)?;
            // Mobile pinch zoom has a distinct visual viewport transform. It is
            // outside this affine CSS-frame contract and cannot be guessed.
            if viewport.get("scale").and_then(Value::as_f64) != Some(1.)
                || viewport.get("offsetX").and_then(Value::as_f64) != Some(0.)
                || viewport.get("offsetY").and_then(Value::as_f64) != Some(0.)
            {
                return Err(OwnerActorError::Rejected);
            }
            if let Some((parent, _, _)) = maps.last().cloned() {
                let backend = self
                    .frame_owner_backend(&parent, id, guarded.clone(), deadline)
                    .await?;
                let model = self
                    .command_event_first(
                        "DOM.getBoxModel",
                        json!({"backendNodeId":backend}),
                        Some(parent.realm.session_id.clone()),
                        None,
                        guarded.clone(),
                        deadline,
                    )
                    .await?;
                let local = Affine::quad(
                    model
                        .pointer("/model/content")
                        .ok_or(OwnerActorError::Rejected)?,
                    width,
                    height,
                )?;
                // CDP quads include every same-process ancestor. Compose only
                // with the containing renderer's local-root-to-page map.
                let local_root = self
                    .frames
                    .roots
                    .get(&parent.target_id)
                    .ok_or(OwnerActorError::Rejected)?;
                let root_map = maps
                    .iter()
                    .find(|(frame, _, _)| frame.scope.frame_id.as_str() == local_root)
                    .map(|(_, map, _)| *map)
                    .ok_or(OwnerActorError::Rejected)?;
                maps.push((frame, local.then(root_map), Some(backend)));
            } else {
                maps.push((
                    frame,
                    Affine {
                        width,
                        height,
                        ..Affine::IDENTITY
                    },
                    None,
                ));
            }
        }
        Ok(maps)
    }

    pub(super) async fn frame_pointer_to_root(
        &mut self,
        top: &str,
        node: &str,
        point: (f64, f64),
        guarded: Option<GuardedPageExecution>,
        deadline: Option<Instant>,
    ) -> Result<(f64, f64), OwnerActorError> {
        let (leaf, _) = self.node_frame_guard(top, node, false)?;
        if leaf.scope.ancestors.is_empty() {
            return Ok(point);
        }
        let first = self
            .frame_geometry(top, &leaf, guarded.clone(), deadline)
            .await?;
        // Bound three visual samples in the root realm, then remeasure all
        // content quads. Layout animation in an ancestor cannot bypass the leaf check.
        let root = first.first().ok_or(OwnerActorError::Rejected)?.0.clone();
        let tick=self.command_event_first("Runtime.evaluate",json!({"expression":"new Promise(resolve => { let n=0; const timer=setTimeout(()=>resolve(false),250); const step=()=>{ if (++n===3) { clearTimeout(timer); resolve(true); } else requestAnimationFrame(step); }; requestAnimationFrame(step); })","uniqueContextId":root.realm.unique_id,"returnByValue":true,"awaitPromise":true}),Some(root.realm.session_id.clone()),None,guarded.clone(),deadline).await?;
        if tick.pointer("/result/value") != Some(&Value::Bool(true)) {
            return Err(OwnerActorError::Rejected);
        }
        let maps = self
            .frame_geometry(top, &leaf, guarded.clone(), deadline)
            .await?;
        if first.len() != maps.len()
            || first
                .iter()
                .zip(&maps)
                .any(|((_, a, _), (_, b, _))| !a.stable(*b))
        {
            return Err(OwnerActorError::Rejected);
        }
        let point = maps.last().ok_or(OwnerActorError::Rejected)?.1.point(point);
        if !point.0.is_finite() || !point.1.is_finite() {
            return Err(OwnerActorError::Rejected);
        }
        for pair in maps.windows(2) {
            let (parent, map, _) = &pair[0];
            let backend = pair[1].2.ok_or(OwnerActorError::Rejected)?;
            let local = map.inverse(point);
            let hit=self.frame_owner_call(parent,backend,"function (el,x,y) { if (!el.isConnected || el.ownerDocument !== document || x<0 || y<0 || x>=innerWidth || y>=innerHeight) return false; const s=getComputedStyle(el); if (s.visibility!=='visible' || s.display==='none' || s.pointerEvents==='none' || Number(s.opacity)===0) return false; return document.elementFromPoint(x,y)===el; }",vec![json!({"value":local.0}),json!({"value":local.1})],guarded.clone(),deadline).await?;
            if hit != Value::Bool(true) {
                return Err(OwnerActorError::Rejected);
            }
        }
        self.validate_frame_guard(&leaf)?;
        let local = maps
            .last()
            .ok_or(OwnerActorError::Rejected)?
            .1
            .inverse(point);
        let leaf_hit=self.call_function_on_node(top,leaf.realm.session_id.clone(),guarded,node,
            NodeFunctionCall { declaration:"function(x,y) { const r=this.getBoundingClientRect(); const hit=document.elementFromPoint(x,y); return this.isConnected && this.ownerDocument===document && Math.abs(r.left+r.width/2-x)<=0.25 && Math.abs(r.top+r.height/2-y)<=0.25 && !!hit && (hit===this || this.contains(hit)); }",
                arguments:json!([{"value":local.0},{"value":local.1}]) },deadline).await?;
        if leaf_hit != Value::Bool(true) {
            return Err(OwnerActorError::Rejected);
        }
        Ok(point)
    }
}

#[cfg(test)]
mod live_tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    fn route(
        context: &str,
        flat: &str,
        page: Option<PageId>,
        incarnation: u64,
    ) -> TargetRouteEntry {
        TargetRouteEntry {
            route: ChromiumTargetRoute {
                session_id: flat.to_owned(),
                browser_context_id: context.to_owned(),
                tenant_id: TenantId::new(),
                owner_session_id: SessionId::new(),
                ownership_fence: OwnershipFence::new(
                    browserd_core::WorkerId::new("frame-worker").unwrap(),
                    1,
                    1,
                    1,
                ),
            },
            kind: if page.is_some() {
                TargetKind::Page
            } else {
                TargetKind::Iframe
            },
            page_id: page,
            target_incarnation: incarnation,
            frame_document_epoch: 1,
            url_revision: 1,
            document: Default::default(),
            network: NetworkActivity::quiet_at(Instant::now()),
        }
    }
    fn realm(registry: &mut FrameRegistry, id: &str, session: &str) {
        registry.frames.get_mut(id).unwrap().realm = Some(Realm {
            id: 1,
            unique_id: format!("realm-{id}"),
            frame_id: id.to_owned(),
            session_id: session.to_owned(),
        });
    }
    #[test]
    fn real_frame_id_is_independent_of_target_id_and_swap_keeps_parent() {
        let mut registry = FrameRegistry::default();
        let root = route("context", "flat-root", Some(PageId::new()), 1);
        registry
            .register("frame-root".into(), None, "target-root", &root, true, false)
            .unwrap();
        realm(&mut registry, "frame-root", "flat-root");
        registry
            .register(
                "frame-child".into(),
                Some("frame-root".into()),
                "target-root",
                &root,
                false,
                false,
            )
            .unwrap();
        let before = registry.frames["frame-child"].epoch;
        let child = route("context", "flat-oopif", None, 2);
        registry
            .register(
                "frame-child".into(),
                None,
                "target-oopif",
                &child,
                true,
                false,
            )
            .unwrap();
        realm(&mut registry, "frame-child", "flat-oopif");
        let chain = registry.chain("frame-child").unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].1.target_id, "target-oopif");
        assert!(chain[1].1.epoch > before);
        registry.retire_target("target-root-stale").unwrap();
        assert!(registry.chain("frame-child").is_ok());
    }
    #[test]
    fn parent_commit_removes_subtree_and_reused_frame_never_reuses_epoch() {
        let mut registry = FrameRegistry::default();
        let root = route("context", "flat", Some(PageId::new()), 1);
        registry
            .register("root".into(), None, "target", &root, true, false)
            .unwrap();
        registry
            .register(
                "child".into(),
                Some("root".into()),
                "target",
                &root,
                false,
                false,
            )
            .unwrap();
        let prior = registry.frames["child"].epoch;
        registry
            .register("root".into(), None, "target", &root, true, true)
            .unwrap();
        assert!(!registry.frames.contains_key("child"));
        registry
            .register(
                "child".into(),
                Some("root".into()),
                "target",
                &root,
                false,
                false,
            )
            .unwrap();
        assert!(registry.frames["child"].epoch > prior);
    }
    #[test]
    fn foreign_context_cannot_rebind_a_frame() {
        let mut registry = FrameRegistry::default();
        let root = route("one", "flat", Some(PageId::new()), 1);
        registry
            .register("root".into(), None, "target", &root, true, false)
            .unwrap();
        assert_eq!(
            registry.register(
                "root".into(),
                None,
                "other",
                &route("two", "other-flat", None, 2),
                true,
                false
            ),
            Err(OwnerActorError::UnknownOwnership)
        );
    }
    #[test]
    fn bounded_context_frames_and_incomplete_or_overdeep_chains_reject() {
        let mut registry = FrameRegistry::default();
        let root = route("context", "flat", Some(PageId::new()), 1);
        for i in 0..MAX_CONTEXT_FRAMES {
            registry
                .register(format!("f{i}"), None, "target", &root, false, false)
                .unwrap();
        }
        assert_eq!(
            registry.register("overflow".into(), None, "target", &root, false, false),
            Err(OwnerActorError::StateOverflow)
        );
        assert!(registry.chain("f0").is_err());
        for i in 0..10 {
            let id = format!("f{i}");
            realm(&mut registry, &id, "flat");
            if i > 0 {
                registry.frames.get_mut(&id).unwrap().parent = Some(format!("f{}", i - 1));
            }
        }
        assert!(registry.chain("f8").is_ok());
        assert!(registry.chain("f9").is_err());
    }
    #[test]
    fn affine_rotation_scale_inverse_and_renderer_composition_preserve_point() {
        let outer = Affine::quad(
            &json!([100., 50., 100., 250., -100., 250., -100., 50.]),
            100.,
            100.,
        )
        .unwrap();
        let inner = Affine::quad(
            &json!([10., 20., 110., 20., 110., 70., 10., 70.]),
            200.,
            100.,
        )
        .unwrap();
        let map = inner.then(outer);
        let p = (27., 36.);
        let r = map.inverse(map.point(p));
        assert!((r.0 - p.0).abs() < 1e-8 && (r.1 - p.1).abs() < 1e-8);
    }
    #[test]
    fn non_affine_or_degenerate_content_quads_reject() {
        assert!(Affine::quad(&json!([0, 0, 100, 0, 80, 100, 0, 100]), 100., 100.).is_err());
        assert!(Affine::quad(&json!([0, 0, 0, 0, 0, 100, 0, 100]), 100., 100.).is_err());
        assert!(Affine::quad(&json!([0, 0, 100, 0, 100, 100, 0, 100]), 0., 100.).is_err());
    }

    #[test]
    fn geometry_stability_measures_css_pixel_motion_not_matrix_coefficients() {
        let before = Affine::quad(&json!([0, 0, 500, 0, 500, 500, 0, 500]), 500., 500.).unwrap();
        let scaled = Affine::quad(&json!([0, 0, 520, 0, 520, 520, 0, 520]), 500., 500.).unwrap();
        assert!(!before.stable(scaled));
        let jitter = Affine::quad(
            &json!([0.1, 0.1, 500.1, 0.1, 500.1, 500.1, 0.1, 500.1]),
            500.,
            500.,
        )
        .unwrap();
        assert!(before.stable(jitter));
    }
}
