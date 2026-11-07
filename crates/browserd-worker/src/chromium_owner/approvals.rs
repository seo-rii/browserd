//! Actor-minted, bounded approval observations. No browser value is approval authority.
use super::*;
use crate::{BrowserFileAttachment, TypedApprovalObservation, WorkerActionCommand};
use browserd_policy::{ApprovalContextScope, ApprovalNodeBinding, NodeReference, Origin};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct ApprovalQuery {
    pub tenant: TenantId,
    pub session: SessionId,
    pub page: Option<PageId>,
    pub fence: OwnershipFence,
    pub action: WorkerActionCommand,
    pub chromium_build: String,
    pub isolation: IsolationProfile,
}

pub(crate) struct LegacyApprovalQuery {
    pub tenant: TenantId,
    pub session: SessionId,
    pub incarnation: u64,
    pub page: PageId,
    pub node: String,
    pub chromium_build: String,
    pub isolation: IsolationProfile,
}

pub(crate) struct PreparedApproval {
    pub deadline: Instant,
    pub observation: TypedApprovalObservation,
    query: ApprovalQuery,
    context_id: String,
    frames: Vec<frames::FrameGuard>,
    route_revisions: Vec<(String, u64)>,
    page_fence: Option<PageExecutionFence>,
    files: Option<uploads::PreparedFiles>,
}

pub(crate) enum ApprovedEffect {
    Browser(PageCommand),
    Secret(crate::ResolvedSecret),
    Files,
    Checkpoint,
    Capture {
        command: browserd_features::CaptureCommand,
        request: crate::GeneratedArtifactRequest,
        store: Arc<dyn crate::SandboxClient>,
    },
}
pub(crate) enum ApprovedResult {
    Browser(Value),
    Checkpoint(Box<crate::CheckpointSnapshot>),
    Capture(Box<crate::GeneratedCaptureResult>),
}

pub(super) struct ActiveApproval {
    context_id: String,
    ownership: ContextOwnership,
    frames: Vec<frames::FrameGuard>,
    route_revisions: Vec<(String, u64)>,
    pub(super) document_change_started: bool,
}

impl ChromiumTargetManagerBackend {
    pub(crate) fn prepare_legacy_node_approval(
        &self,
        query: LegacyApprovalQuery,
        deadline: Option<Instant>,
    ) -> Result<Box<PreparedApproval>, OwnerActorError> {
        let deadline = deadline.unwrap_or_else(|| Instant::now() + self.mailbox.request_timeout);
        self.mailbox.request_until(
            |response| OwnerRequest::PrepareLegacyApproval {
                query,
                deadline,
                response,
            },
            deadline,
        )
    }

    pub(crate) fn prepare_approval(
        &self,
        query: ApprovalQuery,
        files: Option<Vec<BrowserFileAttachment>>,
        deadline: Instant,
    ) -> Result<Box<PreparedApproval>, OwnerActorError> {
        self.mailbox.request_until(
            |response| OwnerRequest::PrepareApproval {
                query,
                files,
                deadline,
                response,
            },
            deadline,
        )
    }
    pub(crate) fn execute_prepared_approval(
        &self,
        prepared: Box<PreparedApproval>,
        effect: ApprovedEffect,
        deadline: Instant,
    ) -> Result<ApprovedResult, OwnerActorError> {
        self.mailbox.request_until(
            |response| OwnerRequest::ExecutePreparedApproval {
                prepared,
                effect,
                deadline,
                response,
            },
            deadline,
        )
    }
}

fn hash(value: &Value, domain: &[u8]) -> Result<[u8; 32], OwnerActorError> {
    let encoded = serde_json::to_vec(value).map_err(|_| OwnerActorError::Rejected)?;
    if encoded.len() > 128 * 1024 {
        return Err(OwnerActorError::Rejected);
    }
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn node_hints(node: &Value) -> (Option<String>, Option<String>) {
    let Some(attributes) = node.get("attributes").and_then(Value::as_array) else {
        return (None, None);
    };
    if attributes.len() > 4096 || !attributes.len().is_multiple_of(2) {
        return (None, None);
    }
    let attribute = |name: &str| {
        let values: Vec<_> = attributes
            .chunks_exact(2)
            .filter(|pair| pair[0].as_str() == Some(name))
            .collect();
        if values.len() != 1 {
            return None;
        }
        values[0][1]
            .as_str()
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .map(str::to_owned)
    };
    (
        attribute("role"),
        attribute("aria-label").or_else(|| attribute("title")),
    )
}

fn command_node(action: &WorkerActionCommand) -> Option<&str> {
    match action {
        WorkerActionCommand::Click { node_ref }
        | WorkerActionCommand::DoubleClick { node_ref }
        | WorkerActionCommand::Hover { node_ref }
        | WorkerActionCommand::Focus { node_ref }
        | WorkerActionCommand::Blur { node_ref }
        | WorkerActionCommand::Check { node_ref }
        | WorkerActionCommand::Uncheck { node_ref }
        | WorkerActionCommand::Fill { node_ref, .. }
        | WorkerActionCommand::FillSecret { node_ref, .. }
        | WorkerActionCommand::SetFiles { node_ref, .. }
        | WorkerActionCommand::SelectOption { node_ref, .. }
        | WorkerActionCommand::GetText { node_ref }
        | WorkerActionCommand::GetAttribute { node_ref, .. }
        | WorkerActionCommand::GetProperties { node_ref }
        | WorkerActionCommand::GetComputedStyle { node_ref }
        | WorkerActionCommand::ExtractTable { node_ref } => Some(node_ref),
        WorkerActionCommand::GetHtml { node_ref } => node_ref.as_deref(),
        _ => None,
    }
}

fn find_frame<'a>(tree: &'a Value, id: &str) -> Result<&'a Value, OwnerActorError> {
    let mut stack = vec![tree];
    let mut seen = 0usize;
    let mut found = None;
    while let Some(tree) = stack.pop() {
        seen += 1;
        if seen > 4096 {
            return Err(OwnerActorError::StateOverflow);
        }
        let frame = tree.get("frame").ok_or(OwnerActorError::Rejected)?;
        if frame.get("id").and_then(Value::as_str) == Some(id) {
            if found.is_some() {
                return Err(OwnerActorError::Rejected);
            }
            found = Some(frame);
        }
        if let Some(children) = tree.get("childFrames") {
            let children = children.as_array().ok_or(OwnerActorError::Rejected)?;
            if stack.len() + children.len() > 4096 {
                return Err(OwnerActorError::StateOverflow);
            }
            stack.extend(children);
        }
    }
    found.ok_or(OwnerActorError::Rejected)
}

fn trusted_origin(frame: &Value) -> Result<(Origin, ApprovalContextScope), OwnerActorError> {
    let raw = frame
        .get("securityOrigin")
        .and_then(Value::as_str)
        .filter(|raw| raw.len() <= 2048)
        .ok_or(OwnerActorError::Rejected)?;
    if let Ok(origin) = Origin::parse(raw) {
        if origin.as_str() != raw {
            return Err(OwnerActorError::Rejected);
        }
        return Ok((
            origin,
            ApprovalContextScope::HttpOrigin {
                origin: raw.to_owned(),
            },
        ));
    }
    if matches!(raw, "null" | "://" | "") {
        return Ok((
            Origin::opaque_document_scope(),
            ApprovalContextScope::OpaqueDocument,
        ));
    }
    Err(OwnerActorError::Rejected)
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) async fn prepare_legacy_node_approval(
        &mut self,
        query: LegacyApprovalQuery,
        deadline: Instant,
    ) -> Result<Box<PreparedApproval>, OwnerActorError> {
        let (_, context) = self.active_context_for_session(&query.session)?;
        if context.ownership.tenant_id != query.tenant
            || context.ownership.fence.session_incarnation() != query.incarnation
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let fence = context.ownership.fence.clone();
        self.prepare_typed_approval(
            ApprovalQuery {
                tenant: query.tenant,
                session: query.session,
                page: Some(query.page),
                fence,
                // The legacy envelope already binds its payload; this query observes only its node.
                action: WorkerActionCommand::GetText {
                    node_ref: query.node,
                },
                chromium_build: query.chromium_build,
                isolation: query.isolation,
            },
            None,
            deadline,
        )
        .await
    }

    pub(super) fn validate_active_approval(&self) -> Result<(), OwnerActorError> {
        let Some(active) = &self.active_approval else {
            return Ok(());
        };
        let context = self
            .contexts
            .get(&active.context_id)
            .ok_or(OwnerActorError::Rejected)?;
        if context.lifecycle != ContextLifecycle::Active || context.ownership != active.ownership {
            return Err(OwnerActorError::Rejected);
        }
        self.context_egress
            .check_active(&context.ownership, Instant::now())?;
        if !active.document_change_started {
            for frame in &active.frames {
                self.validate_frame_guard(frame)?;
            }
            for (target, revision) in &active.route_revisions {
                if self
                    .routes
                    .get(target)
                    .is_none_or(|route| route.url_revision != *revision)
                {
                    return Err(OwnerActorError::Rejected);
                }
            }
        }
        Ok(())
    }

    async fn approval_frame_evidence(
        &mut self,
        frame: &frames::FrameGuard,
        deadline: Instant,
    ) -> Result<(Value, Origin, ApprovalContextScope), OwnerActorError> {
        self.validate_frame_guard(frame)?;
        let response = self
            .command_event_first(
                "Page.getFrameTree",
                json!({}),
                Some(frame.scope.cdp_session_id.as_str().to_owned()),
                None,
                None,
                Some(deadline),
            )
            .await?;
        self.validate_frame_guard(frame)?;
        let frame_info = find_frame(
            response.get("frameTree").ok_or(OwnerActorError::Rejected)?,
            frame.scope.frame_id.as_str(),
        )?;
        let url = frame_info
            .get("url")
            .and_then(Value::as_str)
            .filter(|url| url.len() <= 8192 && !url.chars().any(char::is_control))
            .ok_or(OwnerActorError::Rejected)?;
        let (origin, scope) = trusted_origin(frame_info)?;
        let material = json!({"frame":self.approval_frame_material(frame)?, "url":url, "origin":origin.as_str()});
        Ok((material, origin, scope))
    }

    pub(super) async fn prepare_typed_approval(
        &mut self,
        query: ApprovalQuery,
        files: Option<Vec<BrowserFileAttachment>>,
        deadline: Instant,
    ) -> Result<Box<PreparedApproval>, OwnerActorError> {
        self.active_frame_guard = None;
        self.frame_action_active = true;
        let result = self
            .prepare_typed_approval_inner(query, files, deadline)
            .await;
        self.active_frame_guard = None;
        self.frame_action_active = false;
        result
    }

    async fn prepare_typed_approval_inner(
        &mut self,
        query: ApprovalQuery,
        files: Option<Vec<BrowserFileAttachment>>,
        deadline: Instant,
    ) -> Result<Box<PreparedApproval>, OwnerActorError> {
        if Instant::now() >= deadline {
            return Err(OwnerActorError::DeadlineBeforeDispatch);
        }
        let (context_id, context) = self.active_context_for_session(&query.session)?;
        if context.ownership.tenant_id != query.tenant || context.ownership.fence != query.fence {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if matches!(query.action, WorkerActionCommand::Evaluate { .. })
            && context
                .options
                .as_ref()
                .is_none_or(|options| options.feature_profile != "privileged")
        {
            return Err(OwnerActorError::Rejected);
        }
        let context_id = context_id.to_owned();
        let build_material =
            serde_json::to_value(&self.artifact_identity).map_err(|_| OwnerActorError::Rejected)?;
        let build_digest = hash(&build_material, b"browserd.approval.chromium-build.v2\0")?;
        let mut frames = Vec::new();
        let mut materials = Vec::new();
        let mut route_revisions = Vec::new();
        let mut node_binding = None;
        let mut page_fence = None;
        let mut prepared_files = None;
        let (origin, scope, target_incarnation, epoch, revision) =
            if let WorkerActionCommand::Checkpoint { origins } = &query.action {
                checkpoints::validate_origins(origins)?;
                if files.is_some() {
                    return Err(OwnerActorError::Rejected);
                }
                let pages: Vec<_> = self
                    .contexts
                    .get(&context_id)
                    .ok_or(OwnerActorError::Rejected)?
                    .pages
                    .keys()
                    .cloned()
                    .collect();
                let mut outstanding: BTreeSet<_> = origins.iter().cloned().collect();
                for page in pages {
                    if outstanding.is_empty() {
                        break;
                    }
                    let (_, top, _) = self.owned_page_route(&query.session, &page)?;
                    let frame = self.main_frame_guard(&top)?;
                    let (material, origin, scope) =
                        self.approval_frame_evidence(&frame, deadline).await?;
                    if matches!(scope, ApprovalContextScope::HttpOrigin { .. })
                        && outstanding.remove(origin.as_str())
                    {
                        route_revisions.extend(self.approval_route_revisions(&frame)?);
                        frames.push(frame);
                        materials.push(material);
                    }
                }
                if !outstanding.is_empty() {
                    return Err(OwnerActorError::Rejected);
                }
                // No page/origin is invented for a cookie-only context capture.
                (
                    Origin::browser_context_scope(),
                    ApprovalContextScope::BrowserContext,
                    query.fence.session_incarnation(),
                    query.fence.session_incarnation(),
                    query.fence.session_incarnation(),
                )
            } else {
                let page = query.page.as_ref().ok_or(OwnerActorError::Rejected)?;
                let (_, top, route) = self.owned_page_route(&query.session, page)?;
                if route.tenant_id() != &query.tenant || route.ownership_fence() != &query.fence {
                    return Err(OwnerActorError::UnknownOwnership);
                }
                let top_entry = self.routes.get(&top).ok_or(OwnerActorError::Rejected)?;
                page_fence = Some(PageExecutionFence {
                    target_incarnation: top_entry.target_incarnation,
                    frame_document_epoch: top_entry.frame_document_epoch,
                    url_revision: top_entry.url_revision,
                });
                let (frame, backend) = match command_node(&query.action) {
                    Some(node) => {
                        let (frame, backend) = self.node_frame_guard(&top, node, false)?;
                        (frame, Some(backend))
                    }
                    None => (self.main_frame_guard(&top)?, None),
                };
                self.active_frame_guard = Some(frame.clone());
                let (mut material, origin, scope) =
                    self.approval_frame_evidence(&frame, deadline).await?;
                route_revisions.extend(self.approval_route_revisions(&frame)?);
                if matches!(
                    query.action,
                    WorkerActionCommand::FillSecret { .. } | WorkerActionCommand::SetFiles { .. }
                ) && !matches!(scope, ApprovalContextScope::HttpOrigin { .. })
                {
                    return Err(OwnerActorError::Rejected);
                }
                if let Some(node) = command_node(&query.action) {
                    let binding = self
                        .node_store
                        .lookup_binding(&NodeHandle::from_token(node), node_store_now())
                        .map_err(|_| OwnerActorError::Rejected)?;
                    let described = self
                        .command_event_first(
                            "DOM.describeNode",
                            json!({"backendNodeId":backend,"depth":0,"pierce":false}),
                            Some(frame.scope.cdp_session_id.as_str().to_owned()),
                            None,
                            None,
                            Some(deadline),
                        )
                        .await?;
                    let description = described.get("node").ok_or(OwnerActorError::Rejected)?;
                    if description.get("backendNodeId").and_then(Value::as_u64) != backend {
                        return Err(OwnerActorError::Rejected);
                    }
                    self.validate_frame_guard(&frame)?;
                    let (role, name) = node_hints(description);
                    material["node"] = json!({"token":node,"backend":backend,"snapshot":binding.snapshot_id.get(),"role":role,"name":name});
                    let valid = self.call_function_on_node(&top, frame.scope.cdp_session_id.as_str().to_owned(), None, node,
                    NodeFunctionCall { declaration:"function () { return this.isConnected && this.ownerDocument===document; }", arguments:json!([]) }, Some(deadline)).await?;
                    if valid != Value::Bool(true) {
                        return Err(OwnerActorError::Rejected);
                    }
                    node_binding = Some(ApprovalNodeBinding {
                        node_ref: node.to_owned(),
                        role,
                        name,
                        binding_sha256: hash(&material, b"browserd.approval.node.v2\0")?,
                    });
                }
                match &query.action {
                    WorkerActionCommand::FillSecret { node_ref, .. } => {
                        self.inspect_typed_secret_input(&top, node_ref, deadline)
                            .await?;
                    }
                    WorkerActionCommand::SetFiles {
                        node_ref,
                        artifact_ids,
                    } => {
                        self.inspect_typed_file_input(&top, node_ref, artifact_ids.len(), deadline)
                            .await?;
                        if let Some(files) = files {
                            if files
                                .iter()
                                .map(|file| file.key().artifact_id())
                                .ne(artifact_ids.iter())
                            {
                                return Err(OwnerActorError::Rejected);
                            }
                            prepared_files = Some(
                                self.prepare_set_files(&top, node_ref, files, Some(deadline), true)
                                    .await?,
                            );
                        }
                    }
                    _ if files.is_some() => return Err(OwnerActorError::Rejected),
                    _ => {}
                }
                self.validate_frame_guard(&frame)?;
                let incarnation = frame.target_incarnation();
                let epoch = frame.epoch;
                let revision = self
                    .routes
                    .get(&top)
                    .ok_or(OwnerActorError::Rejected)?
                    .url_revision;
                frames.push(frame);
                materials.push(material);
                (origin, scope, incarnation, epoch, revision)
            };
        for frame in &frames {
            self.validate_frame_guard(frame)?;
        }
        for (target, revision) in &route_revisions {
            if self
                .routes
                .get(target)
                .is_none_or(|route| route.url_revision != *revision)
            {
                return Err(OwnerActorError::Rejected);
            }
        }
        let (current_id, current) = self.active_context_for_session(&query.session)?;
        if current_id != context_id
            || current.ownership.tenant_id != query.tenant
            || current.ownership.fence != query.fence
        {
            return Err(OwnerActorError::Rejected);
        }
        let target_hash = hash(
            &json!({"context":context_id,"tenant":query.tenant,"session":query.session,"page":query.page,
            "worker":query.fence.worker_id(),"worker_epoch":query.fence.worker_epoch(),"placement":query.fence.placement_version(),"incarnation":query.fence.session_incarnation(),
            "build":build_digest,"frames":materials}),
            b"browserd.approval.target.v2\0",
        )?;
        let credential_refs = match &query.action {
            WorkerActionCommand::FillSecret { secret_ref, .. } => vec![secret_ref.clone()],
            _ => vec![],
        };
        let resolved_ips = match origin
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
        {
            Ok(ip) => vec![ip],
            Err(_) => vec![],
        };
        let observation = TypedApprovalObservation {
            tenant_id: query.tenant.clone(),
            session_id: query.session.clone(),
            page_id: query.page.clone(),
            fence: query.fence.clone(),
            context_scope: scope,
            target_binding_sha256: target_hash,
            node_binding: node_binding.clone(),
            build_identity_sha256: build_digest,
            live: crate::LiveApprovalContext {
                target_incarnation,
                frame_document_epoch: epoch,
                current_origin: origin,
                url_revision: revision,
                node_ref: node_binding
                    .as_ref()
                    .map(|node| NodeReference::new(node.node_ref.clone()))
                    .transpose()
                    .map_err(|_| OwnerActorError::Rejected)?,
                node_valid: true,
                resolved_ips,
                credential_refs,
                chromium_build: query.chromium_build.clone(),
                effective_isolation: query.isolation,
            },
        };
        Ok(Box::new(PreparedApproval {
            deadline,
            observation,
            query,
            context_id,
            frames,
            route_revisions,
            page_fence,
            files: prepared_files,
        }))
    }

    pub(super) async fn execute_typed_approval(
        &mut self,
        mut prepared: Box<PreparedApproval>,
        effect: ApprovedEffect,
        deadline: Instant,
    ) -> Result<ApprovedResult, OwnerActorError> {
        self.active_frame_guard = None;
        self.frame_action_active = true;
        let result = async {
            // Re-observe after callback; no native/sensitive effect can precede this comparison.
            let current = self
                .prepare_typed_approval_inner(prepared.query.clone(), None, deadline)
                .await?;
            if current.observation != prepared.observation {
                return Err(OwnerActorError::Rejected);
            }
            self.active_approval = Some(ActiveApproval {
                context_id: prepared.context_id.clone(),
                ownership: ContextOwnership {
                    tenant_id: prepared.query.tenant.clone(),
                    session_id: prepared.query.session.clone(),
                    fence: prepared.query.fence.clone(),
                },
                frames: prepared.frames.clone(),
                route_revisions: prepared.route_revisions.clone(),
                document_change_started: false,
            });
            self.validate_active_approval()?;
            match effect {
                ApprovedEffect::Browser(mut command) => {
                    if matches!(
                        prepared.query.action,
                        WorkerActionCommand::FillSecret { .. }
                            | WorkerActionCommand::SetFiles { .. }
                            | WorkerActionCommand::Checkpoint { .. }
                    ) {
                        return Err(OwnerActorError::Rejected);
                    }
                    if let PageCommand::Evaluate { guard, .. } = &mut command {
                        *guard = Some(Box::new(EvaluateExecutionGuard {
                            frame: prepared
                                .frames
                                .first()
                                .ok_or(OwnerActorError::Rejected)?
                                .clone(),
                            page: prepared.page_fence.ok_or(OwnerActorError::Rejected)?,
                        }));
                    }
                    let page = prepared
                        .query
                        .page
                        .as_ref()
                        .ok_or(OwnerActorError::Rejected)?;
                    self.execute_page_command_inner(
                        &prepared.query.session,
                        page,
                        command,
                        None,
                        Some(deadline),
                    )
                    .await
                    .map(ApprovedResult::Browser)
                }
                ApprovedEffect::Files => self
                    .commit_set_files(
                        prepared.files.take().ok_or(OwnerActorError::Rejected)?,
                        Some(deadline),
                    )
                    .await
                    .map(ApprovedResult::Browser),
                ApprovedEffect::Secret(secret) => {
                    let WorkerActionCommand::FillSecret {
                        node_ref,
                        secret_ref,
                    } = &prepared.query.action
                    else {
                        return Err(OwnerActorError::Rejected);
                    };
                    if secret.grant().tenant_id() != &prepared.query.tenant
                        || secret.grant().secret_ref() != secret_ref
                        || secret.grant().origin() != &prepared.observation.live.current_origin
                    {
                        return Err(OwnerActorError::Rejected);
                    }
                    self.fill_typed_secret(
                        &prepared.query.session,
                        prepared
                            .query
                            .page
                            .as_ref()
                            .ok_or(OwnerActorError::Rejected)?,
                        node_ref,
                        &prepared.observation.live.current_origin,
                        secret,
                        deadline,
                    )
                    .await
                    .map(ApprovedResult::Browser)
                }
                ApprovedEffect::Checkpoint => {
                    let WorkerActionCommand::Checkpoint { origins } = &prepared.query.action else {
                        return Err(OwnerActorError::Rejected);
                    };
                    self.capture_checkpoint(
                        &checkpoints::CheckpointQuery {
                            tenant: prepared.query.tenant.clone(),
                            session: prepared.query.session.clone(),
                            fence: prepared.query.fence.clone(),
                        },
                        origins,
                        deadline,
                    )
                    .await
                    .map(|snapshot| ApprovedResult::Checkpoint(Box::new(snapshot)))
                }
                ApprovedEffect::Capture {
                    command,
                    request,
                    store,
                } => {
                    if prepared.query.action.capture_command().as_ref() != Some(&command) {
                        return Err(OwnerActorError::Rejected);
                    }
                    self.capture_page(
                        &prepared.query.session,
                        prepared
                            .query
                            .page
                            .as_ref()
                            .ok_or(OwnerActorError::Rejected)?,
                        command,
                        request,
                        store,
                        deadline,
                    )
                    .await
                    .map(|capture| ApprovedResult::Capture(Box::new(capture)))
                }
            }
        }
        .await;
        self.active_approval = None;
        self.active_frame_guard = None;
        self.frame_action_active = false;
        result
    }
}

#[cfg(test)]
mod live_tests;
