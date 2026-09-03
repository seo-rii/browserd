use std::sync::{Arc, Mutex};
use std::time::Instant;

use browserd_core::{ActionId, IsolationProfile, PageId, SessionId, TenantId};
use browserd_policy::{CanonicalActionProposal, Origin};
use browserd_session::OwnershipFence;
use serde_json::json;

use crate::chromium_owner::{
    ChromiumTargetManagerBackend, OwnerActorError, PageCommand, PageExecutionFence,
};
use crate::{
    ActionExecutionResult, ApprovedActionError, ChromiumDriver, DependencyError,
    LiveApprovalContext, WorkerActionCommand, WorkerNavigateWaitUntil, WorkerSessionOptionsV1,
    WorkerWaitCondition,
};

const MAX_ACTION_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_ACTION_RESULT_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct CdpChromiumDriver {
    backend: ChromiumTargetManagerBackend,
    effect_gate: Arc<Mutex<()>>,
    chromium_build: Arc<str>,
    isolation: IsolationProfile,
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
        }
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
                    ActionResultShape::Json => result,
                };
                match serde_json::to_vec(&safe_result) {
                    Ok(encoded) if encoded.len() <= MAX_ACTION_RESULT_BYTES => {
                        ActionExecutionResult::Succeeded(encoded)
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
            Err(
                OwnerActorError::StateOverflow
                | OwnerActorError::Unavailable
                | OwnerActorError::OutcomeUncertain,
            ) => ActionExecutionResult::OutcomeUnknown,
        }
    }

    fn observe(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
        deadline: Option<Instant>,
    ) -> Result<LiveApprovalContext, ObservationError> {
        let node_ref = proposal
            .node_ref()
            .map(|node_ref| node_ref.as_str().to_owned());
        let observed = match deadline {
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
        Ok(LiveApprovalContext {
            target_incarnation: observed.target_incarnation,
            frame_document_epoch: observed.frame_document_epoch,
            current_origin: origin,
            url_revision: observed.url_revision,
            node_ref: proposal.node_ref().cloned(),
            node_valid: observed.node_valid,
            resolved_ips: Vec::new(),
            credential_refs: Vec::new(),
            chromium_build: self.chromium_build.to_string(),
            effective_isolation: self.isolation,
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
        let (command, result_shape) =
            parse_action_payload(payload).map_err(|_| ApprovedActionError::DispatchRevoked)?;
        let observed = self
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
        if let Some(reason) = inspected.stale_reason(&observed) {
            return Err(ApprovedActionError::ApprovalStale(reason));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ApprovedActionError::DeadlineBeforeDispatch);
        }
        let execution_fence = PageExecutionFence {
            target_incarnation: observed.target_incarnation,
            frame_document_epoch: observed.frame_document_epoch,
            url_revision: observed.url_revision,
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
            || self.isolation != IsolationProfile::DedicatedProcess
            || options.network_class != "public"
            || options.checkpoint_ref.is_some()
            || options.dialog_policy != "auto_dismiss"
            || options.feature_profile != "standard"
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
}

enum ObservationError {
    DeadlineBeforeDispatch,
    Dependency(DependencyError),
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
            PageCommand::Evaluate { expression },
            ActionResultShape::Json,
        )),
        WorkerActionCommand::WaitFor { condition } => Ok((
            PageCommand::WaitFor {
                predicate: wait_predicate(&condition),
            },
            ActionResultShape::Unit,
        )),
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
        WorkerActionCommand::QueryAll { selector } => {
            Ok((PageCommand::QueryAll { selector }, ActionResultShape::Json))
        }
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
        WorkerWaitCondition::NetworkQuiet { quiet_ms } => format!(
            "(() => {{ const e = performance.getEntriesByType('resource'); if (!e.length) return true; const last = e[e.length - 1]; const end = last.responseEnd || last.startTime; return (performance.now() - end) >= {quiet_ms}; }})()"
        ),
    }
}

fn map_owner_error(error: OwnerActorError) -> DependencyError {
    match error {
        OwnerActorError::Rejected
        | OwnerActorError::UnknownOwnership
        | OwnerActorError::NavigationInterrupted
        | OwnerActorError::NavigationTimeout => DependencyError::Rejected,
        OwnerActorError::StateOverflow | OwnerActorError::Unavailable => {
            DependencyError::Unavailable
        }
        OwnerActorError::DeadlineBeforeDispatch | OwnerActorError::OutcomeUncertain => {
            DependencyError::OutcomeUncertain
        }
    }
}
