use std::sync::{Arc, Mutex};
use std::time::Instant;

use browserd_core::{ActionId, IsolationProfile, PageId, SessionId, TenantId};
use browserd_policy::{ActionType, CanonicalActionProposal, Origin};
use browserd_session::OwnershipFence;
use serde_json::json;

use crate::chromium_owner::{
    ApprovalQuery, ApprovedEffect, ApprovedResult, ChromiumTargetManagerBackend,
    EvaluateExecutionGuard, OwnerActorError, PageCommand, PageExecutionFence,
};
use crate::{
    ActionExecutionResult, ApprovedActionError, ChromiumDriver, DependencyError,
    LiveApprovalContext, TypedApprovalObservation, WorkerActionCommand, WorkerNavigateWaitUntil,
    WorkerSessionOptionsV1, WorkerWaitCondition,
};

const MAX_ACTION_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_ACTION_RESULT_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct CdpChromiumDriver {
    backend: ChromiumTargetManagerBackend,
    effect_gate: Arc<Mutex<()>>,
    chromium_build: Arc<str>,
    isolation: IsolationProfile,
    privileged_evaluate: bool,
    worker_tenant_assignment: Option<crate::WorkerTenantAssignment>,
    capture_admission: browserd_features::FeatureAdmission,
}

impl CdpChromiumDriver {
    pub(crate) fn new(
        backend: ChromiumTargetManagerBackend,
        effect_gate: Arc<Mutex<()>>,
        chromium_build: String,
        isolation: IsolationProfile,
    ) -> Self {
        Self {
            backend,
            effect_gate,
            chromium_build: Arc::from(chromium_build),
            isolation,
            privileged_evaluate: false,
            worker_tenant_assignment: None,
            capture_admission: browserd_features::FeatureAdmission::new(
                browserd_features::FeatureConcurrencyLimits {
                    pdf: 1,
                    full_page_screenshot: 1,
                    large_snapshot: 2,
                    scrape: 1,
                },
            ),
        }
    }

    pub fn with_privileged_evaluate(mut self, enabled: bool) -> Self {
        self.privileged_evaluate = enabled;
        self
    }

    pub fn with_worker_tenant_assignment(
        mut self,
        assignment: crate::WorkerTenantAssignment,
    ) -> Result<Self, DependencyError> {
        if self.isolation != IsolationProfile::DedicatedWorker {
            return Err(DependencyError::Rejected);
        }
        self.worker_tenant_assignment = Some(assignment);
        Ok(self)
    }

    pub fn list_pages_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<Vec<PageId>, DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .list_pages_owned(tenant_id.clone(), session_id.clone(), fence.clone())
            .map_err(map_owner_error)
    }

    fn dispatch_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        command: PageCommand,
        result_shape: ActionResultShape,
        execution_fence: Option<PageExecutionFence>,
        deadline: Option<Instant>,
    ) -> ActionExecutionResult {
        let execution = match deadline {
            Some(deadline) => self.backend.execute_page_command_until(
                session_id.clone(),
                page_id.clone(),
                command,
                execution_fence,
                deadline,
            ),
            None => self.backend.execute_page_command(
                session_id.clone(),
                page_id.clone(),
                command,
                execution_fence,
            ),
        };
        Self::format_action_execution(execution, result_shape)
    }

    fn format_action_execution(
        execution: Result<serde_json::Value, OwnerActorError>,
        result_shape: ActionResultShape,
    ) -> ActionExecutionResult {
        match execution {
            Ok(result) => {
                let safe_result = match result_shape {
                    ActionResultShape::Unit => json!({"ok": true}),
                    ActionResultShape::Url | ActionResultShape::Title => {
                        let Some(value) = result
                            .get("result")
                            .and_then(|result| result.get("value"))
                            .and_then(serde_json::Value::as_str)
                            .filter(|value| {
                                value.len() <= MAX_ACTION_RESULT_BYTES
                                    && !value.chars().any(char::is_control)
                            })
                        else {
                            return ActionExecutionResult::OutcomeUnknown;
                        };
                        if matches!(result_shape, ActionResultShape::Url) {
                            json!({"url": value})
                        } else {
                            json!({"title": value})
                        }
                    }
                    // The command already produced its caller-facing result; the size cap below
                    // is the only gate.
                    ActionResultShape::Json | ActionResultShape::Snapshot => result,
                };
                let max_result_bytes = if matches!(result_shape, ActionResultShape::Snapshot) {
                    browserd_actions::MAX_SNAPSHOT_RESULT_CONTENT_BYTES
                } else {
                    MAX_ACTION_RESULT_BYTES
                };
                match serde_json::to_vec(&safe_result) {
                    Ok(encoded) if encoded.len() <= max_result_bytes => {
                        ActionExecutionResult::Succeeded(encoded)
                    }
                    Ok(_) if matches!(result_shape, ActionResultShape::Snapshot) => {
                        ActionExecutionResult::FailedKnown("snapshot_too_large".to_owned())
                    }
                    _ => ActionExecutionResult::OutcomeUnknown,
                }
            }
            Err(OwnerActorError::Rejected | OwnerActorError::UnknownOwnership) => {
                ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned())
            }
            Err(OwnerActorError::DeadlineBeforeDispatch) => {
                ActionExecutionResult::FailedKnown("action_timeout".to_owned())
            }
            Err(OwnerActorError::NavigationInterrupted) => {
                ActionExecutionResult::FailedKnown("navigation_interrupted".to_owned())
            }
            Err(OwnerActorError::NavigationTimeout) => {
                ActionExecutionResult::FailedKnown("navigation_timeout".to_owned())
            }
            Err(OwnerActorError::DocumentChanged) => {
                ActionExecutionResult::FailedKnown("document_changed".to_owned())
            }
            Err(
                OwnerActorError::StateOverflow
                | OwnerActorError::Unavailable
                | OwnerActorError::OutcomeUncertain
                | OwnerActorError::ScriptException,
            ) => ActionExecutionResult::OutcomeUnknown,
        }
    }

    fn typed_query(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: Option<&PageId>,
        fence: &OwnershipFence,
        action: WorkerActionCommand,
    ) -> ApprovalQuery {
        ApprovalQuery {
            tenant: tenant.clone(),
            session: session.clone(),
            page: page.cloned(),
            fence: fence.clone(),
            action,
            chromium_build: self.chromium_build.to_string(),
            isolation: self.isolation,
        }
    }

    fn prepare_expected_approval(
        &self,
        expected: &TypedApprovalObservation,
        action: WorkerActionCommand,
        files: Option<Vec<crate::BrowserFileAttachment>>,
        deadline: Instant,
    ) -> Result<Box<crate::chromium_owner::approvals::PreparedApproval>, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let prepared = self
            .backend
            .prepare_approval(
                self.typed_query(
                    &expected.tenant_id,
                    &expected.session_id,
                    expected.page_id.as_ref(),
                    &expected.fence,
                    action,
                ),
                files,
                deadline,
            )
            .map_err(map_approval_error)?;
        if prepared.observation != *expected {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        Ok(prepared)
    }

    fn observe(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
        deadline: Option<Instant>,
    ) -> Result<DriverObservation, ObservationError> {
        if proposal.action_type() == &ActionType::Evaluate && proposal.node_ref().is_some() {
            return Err(ObservationError::Dependency(DependencyError::Rejected));
        }
        let node_ref = proposal
            .node_ref()
            .map(|node_ref| node_ref.as_str().to_owned());
        if let Some(node) = node_ref.as_ref() {
            let prepared = self
                .backend
                .prepare_legacy_node_approval(
                    crate::chromium_owner::approvals::LegacyApprovalQuery {
                        tenant: proposal.tenant_id().clone(),
                        session: session_id.clone(),
                        incarnation: proposal.session_incarnation(),
                        page: page_id.clone(),
                        node: node.clone(),
                        chromium_build: self.chromium_build.to_string(),
                        isolation: self.isolation,
                    },
                    deadline,
                )
                .map_err(|error| match error {
                    OwnerActorError::DeadlineBeforeDispatch => {
                        ObservationError::DeadlineBeforeDispatch
                    }
                    error => ObservationError::Dependency(map_owner_error(error)),
                })?;
            if proposal.session_id() != session_id || proposal.page_id() != page_id {
                return Err(ObservationError::Dependency(DependencyError::Rejected));
            }
            return Ok(DriverObservation {
                live: prepared.observation.live.clone(),
                evaluate_guard: None,
                prepared: Some(prepared),
            });
        }
        let (observed, evaluate_guard) = if proposal.action_type() == &ActionType::Evaluate {
            self.backend
                .observe_evaluate_page(
                    proposal.tenant_id().clone(),
                    session_id.clone(),
                    proposal.session_incarnation(),
                    page_id.clone(),
                    None,
                    deadline,
                )
                .map(|observed| (observed.page, Some(observed.guard)))
        } else {
            match deadline {
                Some(deadline) => self.backend.observe_page_until(
                    proposal.tenant_id().clone(),
                    session_id.clone(),
                    proposal.session_incarnation(),
                    page_id.clone(),
                    node_ref,
                    deadline,
                ),
                None => self.backend.observe_page(
                    proposal.tenant_id().clone(),
                    session_id.clone(),
                    proposal.session_incarnation(),
                    page_id.clone(),
                    node_ref,
                ),
            }
            .map(|observed| (observed, None))
        }
        .map_err(|error| match error {
            OwnerActorError::DeadlineBeforeDispatch => ObservationError::DeadlineBeforeDispatch,
            error => ObservationError::Dependency(map_owner_error(error)),
        })?;
        if observed.tenant_id != *proposal.tenant_id()
            || observed.session_id != *proposal.session_id()
            || observed.session_incarnation != proposal.session_incarnation()
            || page_id != proposal.page_id()
        {
            return Err(ObservationError::Dependency(DependencyError::Rejected));
        }
        let origin = Origin::parse(&observed.origin)
            .map_err(|_| ObservationError::Dependency(DependencyError::Rejected))?;
        let resolved_ips = if evaluate_guard.is_some() {
            literal_origin_ips(&origin)
        } else {
            Vec::new()
        };
        let live = LiveApprovalContext {
            target_incarnation: observed.target_incarnation,
            frame_document_epoch: observed.frame_document_epoch,
            current_origin: origin,
            url_revision: observed.url_revision,
            node_ref: proposal.node_ref().cloned(),
            node_valid: observed.node_valid,
            resolved_ips,
            credential_refs: Vec::new(),
            chromium_build: self.chromium_build.to_string(),
            effective_isolation: self.isolation,
        };
        Ok(DriverObservation {
            live,
            evaluate_guard,
            prepared: None,
        })
    }

    fn execute_action_with_deadline(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
        deadline: Option<Instant>,
    ) -> ActionExecutionResult {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return ActionExecutionResult::FailedKnown("action_timeout".to_owned());
        }
        let Ok(_effect) = self.effect_gate.lock() else {
            return ActionExecutionResult::OutcomeUnknown;
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return ActionExecutionResult::FailedKnown("action_timeout".to_owned());
        }
        let Some(page_id) = page_id else {
            return ActionExecutionResult::FailedKnown("page_required".to_owned());
        };
        let (command, result_shape) = match parse_action_payload(payload) {
            Ok(parsed) => parsed,
            Err(reason) => return ActionExecutionResult::FailedKnown(reason.to_owned()),
        };
        self.dispatch_action(session_id, page_id, command, result_shape, None, deadline)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_approved_action_with_deadline(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        deadline: Option<Instant>,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let (mut command, result_shape) =
            parse_action_payload(payload).map_err(|_| ApprovedActionError::DispatchRevoked)?;
        let observation = self
            .observe(session_id, page_id, proposal, deadline)
            .map_err(|error| match error {
                ObservationError::DeadlineBeforeDispatch => {
                    ApprovedActionError::DeadlineBeforeDispatch
                }
                ObservationError::Dependency(DependencyError::Rejected) => {
                    ApprovedActionError::DispatchRevoked
                }
                ObservationError::Dependency(DependencyError::Unavailable) => {
                    ApprovedActionError::Unavailable
                }
                ObservationError::Dependency(DependencyError::OutcomeUncertain) => {
                    ApprovedActionError::OutcomeUncertain
                }
            })?;
        let observed = observation.live;
        if let Some(reason) = inspected.stale_reason(&observed) {
            return Err(ApprovedActionError::ApprovalStale(reason));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        if let Some(prepared) = observation.prepared {
            let execution_deadline = prepared.deadline;
            authorize_and_commit(&observed)?;
            return Ok(
                match self.backend.execute_prepared_approval(
                    prepared,
                    ApprovedEffect::Browser(command),
                    execution_deadline,
                ) {
                    Ok(ApprovedResult::Browser(value)) => {
                        Self::format_action_execution(Ok(value), result_shape)
                    }
                    _ => ActionExecutionResult::OutcomeUnknown,
                },
            );
        }
        let execution_fence = if let PageCommand::Evaluate { guard, .. } = &mut command {
            let bound = observation
                .evaluate_guard
                .ok_or(ApprovedActionError::DispatchRevoked)?;
            let page_fence = bound.page_fence();
            *guard = Some(Box::new(bound));
            page_fence
        } else {
            if observation.evaluate_guard.is_some() {
                return Err(ApprovedActionError::DispatchRevoked);
            }
            PageExecutionFence {
                target_incarnation: observed.target_incarnation,
                frame_document_epoch: observed.frame_document_epoch,
                url_revision: observed.url_revision,
            }
        };
        authorize_and_commit(&observed)?;
        Ok(
            match self.dispatch_action(
                session_id,
                page_id,
                command,
                result_shape,
                Some(execution_fence),
                deadline,
            ) {
                ActionExecutionResult::FailedKnown(_) => ActionExecutionResult::OutcomeUnknown,
                result => result,
            },
        )
    }
}

impl ChromiumDriver for CdpChromiumDriver {
    fn effective_isolation(&self) -> crate::WorkerIsolationProfile {
        match self.isolation {
            IsolationProfile::SharedContext => crate::WorkerIsolationProfile::SharedContext,
            IsolationProfile::TenantDedicatedShard => {
                crate::WorkerIsolationProfile::TenantDedicatedShard
            }
            IsolationProfile::DedicatedProcess => crate::WorkerIsolationProfile::DedicatedProcess,
            IsolationProfile::DedicatedWorker => crate::WorkerIsolationProfile::DedicatedWorker,
        }
    }
    fn inspect_typed_approval_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: Option<&PageId>,
        fence: &OwnershipFence,
        action: &WorkerActionCommand,
        deadline: Instant,
    ) -> Result<TypedApprovalObservation, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        if !action.is_valid() {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        if matches!(action, WorkerActionCommand::Evaluate { .. }) && !self.privileged_evaluate {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        self.backend
            .prepare_approval(
                self.typed_query(tenant, session, page, fence, action.clone()),
                None,
                deadline,
            )
            .map(|prepared| prepared.observation)
            .map_err(map_approval_error)
    }

    fn execute_typed_browser_until(
        &self,
        expected: &TypedApprovalObservation,
        payload: &[u8],
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        if payload.len() > MAX_ACTION_PAYLOAD_BYTES {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let action: WorkerActionCommand =
            serde_json::from_slice(payload).map_err(|_| ApprovedActionError::DispatchRevoked)?;
        if matches!(action, WorkerActionCommand::Evaluate { .. }) && !self.privileged_evaluate {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let (command, shape) =
            parse_action_payload(payload).map_err(|_| ApprovedActionError::DispatchRevoked)?;
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let prepared = self.prepare_expected_approval(expected, action, None, deadline)?;
        authorize_and_commit(&prepared.observation)?;
        let result = match self.backend.execute_prepared_approval(
            prepared,
            ApprovedEffect::Browser(command),
            deadline,
        ) {
            Ok(ApprovedResult::Browser(value)) => Self::format_action_execution(Ok(value), shape),
            _ => ActionExecutionResult::OutcomeUnknown,
        };
        Ok(result)
    }

    fn execute_typed_secret_until(
        &self,
        expected: &TypedApprovalObservation,
        secret: crate::ResolvedSecret,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let node = expected
            .node_binding
            .as_ref()
            .ok_or(ApprovedActionError::DispatchRevoked)?;
        if secret.grant().tenant_id() != &expected.tenant_id
            || secret.grant().origin() != &expected.live.current_origin
        {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let action = WorkerActionCommand::FillSecret {
            node_ref: node.node_ref.clone(),
            secret_ref: secret.grant().secret_ref().to_owned(),
        };
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let prepared = self.prepare_expected_approval(expected, action, None, deadline)?;
        authorize_and_commit(&prepared.observation)?;
        Ok(
            match self.backend.execute_prepared_approval(
                prepared,
                ApprovedEffect::Secret(secret),
                deadline,
            ) {
                Ok(ApprovedResult::Browser(value)) if value == json!({"ok":true}) => {
                    ActionExecutionResult::Succeeded(br#"{"ok":true}"#.to_vec())
                }
                _ => ActionExecutionResult::OutcomeUnknown,
            },
        )
    }

    fn execute_typed_files_until(
        &self,
        expected: &TypedApprovalObservation,
        files: Vec<crate::BrowserFileAttachment>,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let node = expected
            .node_binding
            .as_ref()
            .ok_or(ApprovedActionError::DispatchRevoked)?;
        let action = WorkerActionCommand::SetFiles {
            node_ref: node.node_ref.clone(),
            artifact_ids: files
                .iter()
                .map(|file| file.key().artifact_id().clone())
                .collect(),
        };
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let prepared = self.prepare_expected_approval(expected, action, Some(files), deadline)?;
        authorize_and_commit(&prepared.observation)?;
        Ok(
            match self
                .backend
                .execute_prepared_approval(prepared, ApprovedEffect::Files, deadline)
            {
                Ok(ApprovedResult::Browser(value)) if value == json!({"ok":true}) => {
                    ActionExecutionResult::Succeeded(br#"{"ok":true}"#.to_vec())
                }
                _ => ActionExecutionResult::OutcomeUnknown,
            },
        )
    }

    fn capture_typed_checkpoint_until(
        &self,
        expected: &TypedApprovalObservation,
        origins: &[String],
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<crate::CheckpointSnapshot, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let prepared = self.prepare_expected_approval(
            expected,
            WorkerActionCommand::Checkpoint {
                origins: origins.to_vec(),
            },
            None,
            deadline,
        )?;
        authorize_and_commit(&prepared.observation)?;
        match self
            .backend
            .execute_prepared_approval(prepared, ApprovedEffect::Checkpoint, deadline)
        {
            Ok(ApprovedResult::Checkpoint(snapshot)) => Ok(*snapshot),
            _ => Err(ApprovedActionError::OutcomeUncertain),
        }
    }

    fn execute_typed_capture_until(
        &self,
        expected: &TypedApprovalObservation,
        command: browserd_features::CaptureCommand,
        request: crate::GeneratedArtifactRequest,
        store: Arc<dyn crate::SandboxClient>,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<crate::GeneratedCaptureResult, ApprovedActionError> {
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        if !command.validate() {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let action = match &command {
            browserd_features::CaptureCommand::Screenshot { options } => {
                WorkerActionCommand::Screenshot {
                    options: options.clone(),
                }
            }
            browserd_features::CaptureCommand::Pdf { options } => WorkerActionCommand::Pdf {
                options: options.clone(),
            },
            browserd_features::CaptureCommand::Scrape { options } => WorkerActionCommand::Scrape {
                options: options.clone(),
            },
        };
        let _permit = self
            .capture_admission
            .acquire(command.admission_class())
            .map_err(|_| ApprovedActionError::DispatchRevoked)?;
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let prepared = self.prepare_expected_approval(expected, action, None, deadline)?;
        authorize_and_commit(&prepared.observation)?;
        match self.backend.execute_prepared_approval(
            prepared,
            ApprovedEffect::Capture {
                command,
                request,
                store,
            },
            deadline,
        ) {
            Ok(ApprovedResult::Capture(result)) => Ok(*result),
            _ => Err(ApprovedActionError::OutcomeUncertain),
        }
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
        if !self.privileged_evaluate {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let (mut command, shape) =
            parse_action_payload(payload).map_err(|_| ApprovedActionError::DispatchRevoked)?;
        if !matches!(command, PageCommand::Evaluate { .. }) {
            return Err(ApprovedActionError::DispatchRevoked);
        }
        let observation = self
            .backend
            .observe_evaluate_page(
                tenant_id.clone(),
                session_id.clone(),
                fence.session_incarnation(),
                page_id.clone(),
                Some(fence.clone()),
                Some(deadline),
            )
            .map_err(|error| match error {
                OwnerActorError::DeadlineBeforeDispatch => {
                    ApprovedActionError::DeadlineBeforeDispatch
                }
                OwnerActorError::Rejected | OwnerActorError::UnknownOwnership => {
                    ApprovedActionError::DispatchRevoked
                }
                OwnerActorError::Unavailable => ApprovedActionError::Unavailable,
                _ => ApprovedActionError::OutcomeUncertain,
            })?;
        let observed = observation.page;
        let current_origin =
            Origin::parse(&observed.origin).map_err(|_| ApprovedActionError::DispatchRevoked)?;
        let resolved_ips = literal_origin_ips(&current_origin);
        let live = LiveApprovalContext {
            target_incarnation: observed.target_incarnation,
            frame_document_epoch: observed.frame_document_epoch,
            current_origin,
            url_revision: observed.url_revision,
            node_ref: None,
            node_valid: true,
            resolved_ips,
            credential_refs: Vec::new(),
            chromium_build: self.chromium_build.to_string(),
            effective_isolation: self.isolation,
        };
        if Instant::now() >= deadline {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let execution_fence = observation.guard.page_fence();
        let PageCommand::Evaluate { guard, .. } = &mut command else {
            return Err(ApprovedActionError::DispatchRevoked);
        };
        *guard = Some(Box::new(observation.guard));
        authorize_and_commit(&live)?;
        Ok(
            match self.dispatch_action(
                session_id,
                page_id,
                command,
                shape,
                Some(execution_fence),
                Some(deadline),
            ) {
                ActionExecutionResult::FailedKnown(_) => ActionExecutionResult::OutcomeUnknown,
                result => result,
            },
        )
    }

    fn capture_checkpoint_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        origins: &[String],
        deadline: Instant,
    ) -> Result<crate::CheckpointSnapshot, crate::CheckpointError> {
        if Instant::now() >= deadline {
            return Err(crate::CheckpointError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| crate::CheckpointError::Unavailable)?;
        self.backend
            .capture_checkpoint_until(
                tenant.clone(),
                session.clone(),
                fence.clone(),
                origins.to_vec(),
                deadline,
            )
            .map_err(map_checkpoint_error)
    }

    fn restore_checkpoint_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        primary_page: &PageId,
        fence: &OwnershipFence,
        snapshot: crate::CheckpointSnapshot,
        deadline: Instant,
    ) -> Result<(), crate::CheckpointError> {
        if Instant::now() >= deadline {
            return Err(crate::CheckpointError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| crate::CheckpointError::Unavailable)?;
        self.backend
            .restore_checkpoint_until(
                tenant.clone(),
                session.clone(),
                primary_page.clone(),
                fence.clone(),
                snapshot,
                deadline,
            )
            .map_err(map_checkpoint_error)
    }

    fn inspect_secret_fill_target_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        deadline: Instant,
    ) -> Result<crate::SecretFillTarget, crate::SecretFillError> {
        if Instant::now() >= deadline {
            return Err(crate::SecretFillError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| crate::SecretFillError::Unavailable)?;
        self.backend
            .inspect_secret_target_until(
                tenant.clone(),
                session.clone(),
                page.clone(),
                fence.clone(),
                node_ref.to_owned(),
                deadline,
            )
            .map_err(map_secret_inspection_error)
    }

    fn execute_secret_fill_until(
        &self,
        target: &crate::SecretFillTarget,
        secret: crate::ResolvedSecret,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &crate::SecretFillTarget,
        ) -> Result<(), crate::SecretFillError>,
    ) -> Result<ActionExecutionResult, crate::SecretFillError> {
        if Instant::now() >= deadline {
            return Err(crate::SecretFillError::DeadlineBeforeDispatch);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| crate::SecretFillError::Unavailable)?;
        if secret.grant().tenant_id() != &target.tenant_id
            || secret.grant().origin() != &target.origin
        {
            return Err(crate::SecretFillError::DispatchRevoked);
        }
        let current = self
            .backend
            .inspect_secret_target_until(
                target.tenant_id.clone(),
                target.session_id.clone(),
                target.page_id.clone(),
                target.fence.clone(),
                target.node_ref.clone(),
                deadline,
            )
            .map_err(map_secret_inspection_error)?;
        if &current != target {
            return Err(crate::SecretFillError::DispatchRevoked);
        }
        if Instant::now() >= deadline {
            return Err(crate::SecretFillError::DeadlineBeforeDispatch);
        }
        authorize_and_commit(&current)?;
        // Authorization is durable now. No owner/mailbox/transport error permits replay.
        Ok(
            match self.backend.fill_secret_until(current, secret, deadline) {
                Ok(result) if result == json!({"ok":true}) => {
                    ActionExecutionResult::Succeeded(br#"{"ok":true}"#.to_vec())
                }
                _ => ActionExecutionResult::OutcomeUnknown,
            },
        )
    }

    fn pending_browser_downloads(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        limit: usize,
    ) -> Result<Vec<crate::BrowserDownloadCompletion>, DependencyError> {
        self.backend
            .pending_downloads(session_id.clone(), fence.clone(), limit)
            .map_err(map_owner_error)
    }

    fn open_browser_download(
        &self,
        completion: &crate::BrowserDownloadCompletion,
    ) -> Result<crate::BrowserDownloadFile, DependencyError> {
        self.backend
            .open_download(completion.clone())
            .map_err(map_owner_error)
    }

    fn ack_browser_download(
        &self,
        completion: &crate::BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        self.backend
            .ack_download(completion.clone())
            .map_err(map_owner_error)
    }

    fn reject_browser_download(
        &self,
        completion: &crate::BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        self.backend
            .reject_download(completion.clone())
            .map_err(map_owner_error)
    }

    fn viewer_rebind(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<u64, DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .viewer_rebind(session_id.clone(), page_id.clone(), fence.clone())
            .map_err(map_owner_error)
    }
    fn viewer_start(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let frame = self
            .backend
            .viewer(
                session_id.clone(),
                page_id.clone(),
                fence.clone(),
                crate::chromium_owner::viewer::ViewerOperation::Start,
            )
            .map_err(map_owner_error)?;
        let _ = frame;
        Ok(())
    }
    fn viewer_stop(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let frame = self
            .backend
            .viewer(
                session_id.clone(),
                page_id.clone(),
                fence.clone(),
                crate::chromium_owner::viewer::ViewerOperation::Stop,
            )
            .map_err(map_owner_error)?;
        let _ = frame;
        Ok(())
    }
    fn viewer_frame(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<Option<crate::WorkerViewerFrame>, DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let frame = self
            .backend
            .viewer(
                session_id.clone(),
                page_id.clone(),
                fence.clone(),
                crate::chromium_owner::viewer::ViewerOperation::Frame,
            )
            .map_err(map_owner_error)?;
        Ok(frame)
    }
    fn viewer_input(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        transform_epoch: u64,
        message: &crate::ViewerClientMessage,
    ) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let frame = self
            .backend
            .viewer(
                session_id.clone(),
                page_id.clone(),
                fence.clone(),
                crate::chromium_owner::viewer::ViewerOperation::Input {
                    transform_epoch,
                    message: message.clone(),
                },
            )
            .map_err(map_owner_error)?;
        let _ = frame;
        Ok(())
    }
    fn viewer_cleanup(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        cleanup: &browserd_viewer::InputCleanup,
    ) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let frame = self
            .backend
            .viewer(
                session_id.clone(),
                page_id.clone(),
                fence.clone(),
                crate::chromium_owner::viewer::ViewerOperation::Cleanup(cleanup.clone()),
            )
            .map_err(map_owner_error)?;
        let _ = frame;
        Ok(())
    }
    fn execute_capture_until(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        command: browserd_features::CaptureCommand,
        request: crate::GeneratedArtifactRequest,
        store: Arc<dyn crate::SandboxClient>,
        deadline: Instant,
    ) -> Result<crate::GeneratedCaptureResult, DependencyError> {
        if !command.validate() || Instant::now() >= deadline {
            return Err(DependencyError::Rejected);
        }
        let _permit = self
            .capture_admission
            .acquire(command.admission_class())
            .map_err(|_| DependencyError::Rejected)?;
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .execute_capture_until(
                session_id.clone(),
                page_id.clone(),
                command,
                request,
                store,
                deadline,
            )
            .map_err(map_owner_error)
    }

    fn execute_file_attachment_until(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        files: Vec<crate::BrowserFileAttachment>,
        deadline: Instant,
    ) -> ActionExecutionResult {
        if Instant::now() >= deadline {
            return ActionExecutionResult::FailedKnown("action_timeout".to_owned());
        }
        if files.is_empty()
            || files.len() > 128
            || node_ref.is_empty()
            || node_ref.len() > 1024
            || files
                .iter()
                .any(|file| file.fence() != fence || file.key().session_id() != session_id)
        {
            return ActionExecutionResult::FailedKnown("browser_operation_rejected".to_owned());
        }
        let Ok(_effect) = self.effect_gate.lock() else {
            return ActionExecutionResult::OutcomeUnknown;
        };
        if Instant::now() >= deadline {
            return ActionExecutionResult::FailedKnown("action_timeout".to_owned());
        }
        self.dispatch_action(
            session_id,
            page_id,
            PageCommand::SetFiles {
                node_ref: node_ref.to_owned(),
                files,
            },
            ActionResultShape::Unit,
            None,
            Some(deadline),
        )
    }
    fn qualify(&self) -> Result<(), DependencyError> {
        self.backend.qualify().map_err(map_owner_error)
    }

    fn shard_managed_contexts(&self) -> bool {
        true
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        if self
            .worker_tenant_assignment
            .as_ref()
            .is_some_and(|assignment| {
                assignment.tenant_id() != tenant_id || assignment.worker_id() != fence.worker_id()
            })
            || (self.isolation == IsolationProfile::DedicatedWorker
                && self.worker_tenant_assignment.is_none())
        {
            return Err(DependencyError::Rejected);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .create_context_owned(tenant_id.clone(), session_id.clone(), fence.clone())
            .map_err(map_owner_error)
    }

    fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        if !options.is_valid()
            || self
                .worker_tenant_assignment
                .as_ref()
                .is_some_and(|assignment| {
                    assignment.tenant_id() != tenant_id
                        || assignment.worker_id() != fence.worker_id()
                })
            || (self.isolation == IsolationProfile::DedicatedWorker
                && self.worker_tenant_assignment.is_none())
            || (!matches!(
                self.isolation,
                IsolationProfile::DedicatedProcess | IsolationProfile::DedicatedWorker
            ) && self.backend.effective_context_isolation() != Some(self.isolation))
            || options.network_class != "public"
            || options.checkpoint_ref.is_some()
            || options.dialog_policy != "auto_dismiss"
            || !(options.feature_profile == "standard"
                || (self.privileged_evaluate && options.feature_profile == "privileged"))
        {
            return Err(DependencyError::Rejected);
        }
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .create_context_owned_with_options(
                tenant_id.clone(),
                session_id.clone(),
                fence.clone(),
                options.clone(),
            )
            .map_err(map_owner_error)
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn close_context_fenced(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if self.backend.effective_context_isolation().is_some() {
            return self
                .backend
                .dispose_context_verified_until(
                    session_id.clone(),
                    fence.clone(),
                    Instant::now() + std::time::Duration::from_secs(30),
                )
                .map_err(map_owner_error);
        }
        self.backend
            .dispose_context(session_id.clone(), fence.clone())
            .map_err(map_owner_error)
    }

    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .create_page(session_id.clone())
            .map_err(map_owner_error)
    }

    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .close_page(session_id.clone(), page_id.clone())
            .map_err(map_owner_error)
    }

    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .activate_page(session_id.clone(), page_id.clone())
            .map_err(map_owner_error)
    }

    fn execute_action(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.execute_action_with_deadline(session_id, page_id, payload, None)
    }

    fn execute_action_until(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
        deadline: Instant,
    ) -> ActionExecutionResult {
        self.execute_action_with_deadline(session_id, page_id, payload, Some(deadline))
    }

    fn inspect_approval_context(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.observe(session_id, page_id, proposal, None)
            .map(|observation| observation.live)
            .map_err(|error| match error {
                ObservationError::DeadlineBeforeDispatch => DependencyError::OutcomeUncertain,
                ObservationError::Dependency(error) => error,
            })
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
        self.execute_approved_action_with_deadline(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            None,
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
        self.execute_approved_action_with_deadline(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            Some(deadline),
            authorize_and_commit,
        )
    }

    fn cancel_action(
        &self,
        session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        let _effect = self
            .effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.backend
            .validate_session(session_id.clone())
            .map_err(map_owner_error)?;
        Ok(false)
    }
}

#[derive(Clone, Copy)]
enum ActionResultShape {
    Unit,
    Url,
    Title,
    /// The command already produced its final, caller-facing JSON result.
    Json,
    /// A validated read-only snapshot has the SPEC 4 MiB result allowance.
    Snapshot,
}

enum ObservationError {
    DeadlineBeforeDispatch,
    Dependency(DependencyError),
}

struct DriverObservation {
    live: LiveApprovalContext,
    evaluate_guard: Option<EvaluateExecutionGuard>,
    prepared: Option<Box<crate::chromium_owner::approvals::PreparedApproval>>,
}

fn literal_origin_ips(origin: &Origin) -> Vec<std::net::IpAddr> {
    let host = origin.host();
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>().ok().into_iter().collect()
}

fn map_checkpoint_error(error: OwnerActorError) -> crate::CheckpointError {
    match error {
        OwnerActorError::DeadlineBeforeDispatch => crate::CheckpointError::DeadlineBeforeDispatch,
        OwnerActorError::Rejected | OwnerActorError::UnknownOwnership => {
            crate::CheckpointError::Rejected
        }
        OwnerActorError::Unavailable => crate::CheckpointError::Unavailable,
        _ => crate::CheckpointError::OutcomeUncertain,
    }
}

fn map_secret_inspection_error(error: OwnerActorError) -> crate::SecretFillError {
    match error {
        OwnerActorError::DeadlineBeforeDispatch => crate::SecretFillError::DeadlineBeforeDispatch,
        OwnerActorError::Rejected | OwnerActorError::UnknownOwnership => {
            crate::SecretFillError::Rejected
        }
        OwnerActorError::Unavailable => crate::SecretFillError::Unavailable,
        _ => crate::SecretFillError::OutcomeUncertain,
    }
}

fn parse_action_payload(payload: &[u8]) -> Result<(PageCommand, ActionResultShape), &'static str> {
    if payload.is_empty() || payload.len() > MAX_ACTION_PAYLOAD_BYTES {
        return Err("invalid_action_payload");
    }
    let action =
        serde_json::from_slice::<WorkerActionCommand>(payload).map_err(|_| "unsupported_action")?;
    if !action.is_valid() {
        return Err("invalid_action_arguments");
    }
    match action {
        WorkerActionCommand::SetFiles { .. } => Err("artifact_preparation_required"),
        WorkerActionCommand::FillSecret { .. } => Err("secret_preparation_required"),
        WorkerActionCommand::Checkpoint { .. } => Err("checkpoint_preparation_required"),
        WorkerActionCommand::Navigate { url, wait_until } => Ok((
            PageCommand::Navigate { url, wait_until },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::Reload => Ok((PageCommand::Reload, ActionResultShape::Unit)),
        WorkerActionCommand::GoBack => Ok((PageCommand::GoBack, ActionResultShape::Unit)),
        WorkerActionCommand::GoForward => Ok((PageCommand::GoForward, ActionResultShape::Unit)),
        WorkerActionCommand::Click { node_ref } => {
            Ok((PageCommand::Click { node_ref }, ActionResultShape::Unit))
        }
        WorkerActionCommand::DoubleClick { node_ref } => Ok((
            PageCommand::DoubleClick { node_ref },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::Hover { node_ref } => {
            Ok((PageCommand::Hover { node_ref }, ActionResultShape::Unit))
        }
        WorkerActionCommand::Focus { node_ref } => {
            Ok((PageCommand::Focus { node_ref }, ActionResultShape::Unit))
        }
        WorkerActionCommand::Blur { node_ref } => {
            Ok((PageCommand::Blur { node_ref }, ActionResultShape::Unit))
        }
        WorkerActionCommand::Check { node_ref } => {
            Ok((PageCommand::Check { node_ref }, ActionResultShape::Unit))
        }
        WorkerActionCommand::Uncheck { node_ref } => {
            Ok((PageCommand::Uncheck { node_ref }, ActionResultShape::Unit))
        }
        WorkerActionCommand::Fill { node_ref, value } => Ok((
            PageCommand::Fill { node_ref, value },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::SelectOption { node_ref, values } => Ok((
            PageCommand::SelectOption { node_ref, values },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::Evaluate { expression } => Ok((
            PageCommand::Evaluate {
                expression,
                guard: None,
            },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::WaitFor { condition } => Ok((
            // `network_quiet` is decided from the owner's in-flight request ledger, not a JS
            // predicate, so it routes to its own command; every other condition polls JS (BRD-011).
            match condition {
                WorkerWaitCondition::NetworkQuiet { quiet_ms } => {
                    PageCommand::WaitForNetworkQuiet { quiet_ms }
                }
                condition => PageCommand::WaitFor {
                    predicate: wait_predicate(&condition),
                },
            },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::HandleDialog {
            accept,
            prompt_text,
        } => Ok((
            PageCommand::HandleDialog {
                accept,
                prompt_text,
            },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::Snapshot => Ok((PageCommand::Snapshot, ActionResultShape::Snapshot)),
        WorkerActionCommand::TypeText { text } => {
            Ok((PageCommand::InsertText { text }, ActionResultShape::Unit))
        }
        WorkerActionCommand::PressKey { key } => {
            Ok((PageCommand::PressKey { key }, ActionResultShape::Unit))
        }
        WorkerActionCommand::Scroll { delta_x, delta_y } => Ok((
            PageCommand::Scroll { delta_x, delta_y },
            ActionResultShape::Unit,
        )),
        WorkerActionCommand::QueryAll {
            selector,
            frame_path,
        } => Ok((
            PageCommand::QueryAll {
                selector,
                frame_path,
            },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::GetText { node_ref } => {
            Ok((PageCommand::GetText { node_ref }, ActionResultShape::Json))
        }
        WorkerActionCommand::GetHtml { node_ref } => {
            Ok((PageCommand::GetHtml { node_ref }, ActionResultShape::Json))
        }
        WorkerActionCommand::GetAttribute { node_ref, name } => Ok((
            PageCommand::GetAttribute { node_ref, name },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::GetProperties { node_ref } => Ok((
            PageCommand::GetProperties { node_ref },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::GetComputedStyle { node_ref } => Ok((
            PageCommand::GetComputedStyle { node_ref },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::ExtractTable { node_ref } => Ok((
            PageCommand::ExtractTable { node_ref },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::GetUrl => Ok((PageCommand::ReadUrl, ActionResultShape::Url)),
        WorkerActionCommand::GetTitle => Ok((PageCommand::ReadTitle, ActionResultShape::Title)),
        WorkerActionCommand::Screenshot { .. }
        | WorkerActionCommand::Pdf { .. }
        | WorkerActionCommand::Scrape { .. } => Err("capture_requires_artifact_context"),
    }
}

/// Serializes a string as a JS string literal (JSON escaping is a safe subset of JS).
fn js_string_literal(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Builds the boolean JS predicate a `wait_for` condition polls.
fn wait_predicate(condition: &WorkerWaitCondition) -> String {
    match condition {
        WorkerWaitCondition::SelectorAttached { selector } => {
            format!("!!document.querySelector({})", js_string_literal(selector))
        }
        WorkerWaitCondition::SelectorVisible { selector } => format!(
            "(() => {{ const el = document.querySelector({}); if (!el) return false; const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'; }})()",
            js_string_literal(selector)
        ),
        WorkerWaitCondition::SelectorHidden { selector } => format!(
            "(() => {{ const el = document.querySelector({}); if (!el) return true; const r = el.getBoundingClientRect(); return !(r.width > 0 && r.height > 0) || getComputedStyle(el).visibility === 'hidden'; }})()",
            js_string_literal(selector)
        ),
        WorkerWaitCondition::UrlMatches { pattern } => {
            format!("location.href.includes({})", js_string_literal(pattern))
        }
        WorkerWaitCondition::LoadState { state } => match state {
            WorkerNavigateWaitUntil::Load => "document.readyState === 'complete'".to_owned(),
            WorkerNavigateWaitUntil::Domcontentloaded => {
                "(document.readyState === 'interactive' || document.readyState === 'complete')"
                    .to_owned()
            }
        },
        // Superseded by the owner's in-flight request ledger (BRD-011): `map_command` routes
        // `NetworkQuiet` to `PageCommand::WaitForNetworkQuiet` before reaching here, so this arm is
        // unreachable. It is retained only for match exhaustiveness and polls false (fail-closed, a
        // timeout rather than a spurious success) should any future caller route through it.
        WorkerWaitCondition::NetworkQuiet { .. } => "false".to_owned(),
    }
}

fn map_owner_error(error: OwnerActorError) -> DependencyError {
    match error {
        OwnerActorError::Rejected
        | OwnerActorError::UnknownOwnership
        | OwnerActorError::NavigationInterrupted
        | OwnerActorError::NavigationTimeout
        | OwnerActorError::DocumentChanged => DependencyError::Rejected,
        OwnerActorError::StateOverflow | OwnerActorError::Unavailable => {
            DependencyError::Unavailable
        }
        OwnerActorError::DeadlineBeforeDispatch
        | OwnerActorError::OutcomeUncertain
        | OwnerActorError::ScriptException => DependencyError::OutcomeUncertain,
    }
}

fn map_approval_error(error: OwnerActorError) -> ApprovedActionError {
    match error {
        OwnerActorError::DeadlineBeforeDispatch => ApprovedActionError::DeadlineBeforeDispatch,
        OwnerActorError::Rejected | OwnerActorError::UnknownOwnership => {
            ApprovedActionError::DispatchRevoked
        }
        OwnerActorError::Unavailable => ApprovedActionError::Unavailable,
        _ => ApprovedActionError::OutcomeUncertain,
    }
}
