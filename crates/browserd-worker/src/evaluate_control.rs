//! Mandatory admission and durable intent for arbitrary JavaScript execution.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use browserd_actions::{ActionKind, KnownFailureReason};
use browserd_core::{ActionId, PageId, PrincipalId, SessionExecution, SessionId};
use browserd_features::{BuiltinFeature, FeatureProfile};
use browserd_observability::{AppendOutcome, AuditEvent, AuditEventId};
use browserd_policy::{ActionType, ExecutionContext};
use browserd_session::{OwnershipFence, SessionLifecycle};

use crate::{
    APPROVED_DISPATCH_AUTHORIZATION_REJECTED, APPROVED_DISPATCH_AUTHORIZING,
    APPROVED_DISPATCH_DRIVER_PENDING, APPROVED_DISPATCH_INSPECTING,
    APPROVED_DISPATCH_RETURNED_UNCERTAIN, APPROVED_DISPATCH_STARTED, APPROVED_DISPATCH_STOPPED,
    ActionExecutionResult, ActionStatus, ApprovedActionError, ChromiumDriver, SandboxClient,
    SessionExecutor, WorkerActionCommand, WorkerControlPlane, validate_fence,
};

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub(crate) fn admit_privileged_evaluate(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        action_id: &ActionId,
        executor: &Arc<SessionExecutor>,
    ) -> Result<(), KnownFailureReason> {
        let (tenant_id, principal_id, request_hash) = {
            let session = executor
                .state
                .lock()
                .map_err(|_| KnownFailureReason::NotDispatched)?;
            validate_fence(&session, fence).map_err(|_| KnownFailureReason::PolicyDenied)?;
            let action = session
                .actions
                .get(action_id)
                .ok_or(KnownFailureReason::NotDispatched)?;
            if session.feature_profile != FeatureProfile::Privileged
                || !self
                    .privileged_evaluate_policy
                    .allows(&session.tenant_id, &action.requester_principal_id)
                || action.snapshot.feature != Some(BuiltinFeature::PrivilegedEvaluate)
                || action.snapshot.kind != ActionKind::Mutating
                || !matches!(
                    serde_json::from_slice::<WorkerActionCommand>(&action.payload),
                    Ok(WorkerActionCommand::Evaluate { .. })
                )
            {
                return Err(KnownFailureReason::PolicyDenied);
            }
            if let Some(approval_id) = &action.approval_id {
                let approval = session
                    .approvals
                    .get(approval_id)
                    .ok_or(KnownFailureReason::PolicyDenied)?;
                let request = approval
                    .request
                    .as_ref()
                    .ok_or(KnownFailureReason::PolicyDenied)?;
                if request.proposal().action_type() != &ActionType::Evaluate
                    || approval.feature != "browser:evaluate"
                    || request.proposal().node_ref().is_some()
                {
                    return Err(KnownFailureReason::PolicyDenied);
                }
            }
            self.admit_runtime_operation(&session.tenant_id, session_id, "browser:evaluate")
                .map_err(|_| KnownFailureReason::PolicyDenied)?;
            (
                session.tenant_id.clone(),
                action.requester_principal_id.clone(),
                action.snapshot.canonical_request_hash,
            )
        };
        // An opt-in policy never permits unaudited evaluate, including non-production hosts.
        let wal = self
            .audit_wal
            .as_ref()
            .ok_or(KnownFailureReason::NotDispatched)?;
        let event_id = AuditEventId::new(format!("evaluate-dispatch:{action_id}"))
            .map_err(|_| KnownFailureReason::NotDispatched)?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "tenant_id": tenant_id,
            "session_id": session_id,
            "action_id": action_id,
            "principal_id": principal_id,
            "worker_id": fence.worker_id(),
            "worker_epoch": fence.worker_epoch(),
            "placement_version": fence.placement_version(),
            "session_incarnation": fence.session_incarnation(),
            "request_hash": request_hash,
            "policy_digest_sha256": self.privileged_evaluate_policy.digest(),
        }))
        .map_err(|_| KnownFailureReason::NotDispatched)?;
        match wal.append(AuditEvent::new(
            event_id,
            "browser.evaluate.dispatch",
            payload,
            true,
        )) {
            Ok(AppendOutcome::Durable(_) | AppendOutcome::Existing(_)) => Ok(()),
            _ => Err(KnownFailureReason::NotDispatched),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_privileged_evaluate(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        action_id: &ActionId,
        principal_id: &PrincipalId,
        payload: &[u8],
        deadline: Instant,
        executor: &Arc<SessionExecutor>,
    ) -> ActionExecutionResult {
        let mut effect_started = false;
        let execution = (|| {
            if Instant::now() >= deadline {
                return Err(ApprovedActionError::DeadlineBeforeDispatch);
            }
            let (tenant_id, permit) = {
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| ApprovedActionError::Unavailable)?;
                validate_fence(&session, fence)
                    .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                let permit = session
                    .actions
                    .get(action_id)
                    .and_then(|action| action.dispatch_permit.clone())
                    .ok_or(ApprovedActionError::DispatchRevoked)?;
                (session.tenant_id.clone(), permit)
            };
            if executor
                .approved_dispatch_phase
                .compare_exchange(
                    APPROVED_DISPATCH_INSPECTING,
                    APPROVED_DISPATCH_DRIVER_PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                return Err(ApprovedActionError::DispatchRevoked);
            }
            self.driver.execute_privileged_evaluate_until(
                &tenant_id,
                session_id,
                page_id,
                fence,
                payload,
                deadline,
                &mut |observed| {
                    if executor
                        .approved_dispatch_phase
                        .compare_exchange(
                            APPROVED_DISPATCH_DRIVER_PENDING,
                            APPROVED_DISPATCH_AUTHORIZING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        return Err(ApprovedActionError::DispatchRevoked);
                    }
                    let admission = (|| {
                        if Instant::now() >= deadline {
                            return Err(ApprovedActionError::DeadlineBeforeDispatch);
                        }
                        let session = executor
                            .state
                            .lock()
                            .map_err(|_| ApprovedActionError::Unavailable)?;
                        validate_fence(&session, fence)
                            .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                        let snapshot = session.machine.snapshot();
                        let action = session
                            .actions
                            .get(action_id)
                            .ok_or(ApprovedActionError::DispatchRevoked)?;
                        if snapshot.lifecycle != SessionLifecycle::Ready
                            || snapshot.execution != SessionExecution::Running(action_id.clone())
                            || !session.occupies_capacity
                            || session.tenant_id != tenant_id
                            || session.feature_profile != FeatureProfile::Privileged
                            || !session.pages.contains(page_id)
                            || session.closing_pages.contains(page_id)
                            || action.snapshot.status != ActionStatus::Running
                            || action.requester_principal_id != *principal_id
                            || action.page_id.as_ref() != Some(page_id)
                            || action.payload != payload
                            || action.dispatch_permit.as_ref() != Some(&permit)
                            || !self
                                .privileged_evaluate_policy
                                .allows(&tenant_id, principal_id)
                            || observed.target_incarnation == 0
                            || observed.frame_document_epoch == 0
                            || observed.url_revision == 0
                            || observed.node_ref.is_some()
                            || !observed.node_valid
                        {
                            return Err(ApprovedActionError::DispatchRevoked);
                        }
                        let context = ExecutionContext {
                            tenant_id: tenant_id.clone(),
                            requester_principal_id: principal_id.clone(),
                            session_id: session_id.clone(),
                            session_incarnation: fence.session_incarnation(),
                            page_id: page_id.clone(),
                            target_incarnation: observed.target_incarnation,
                            frame_document_epoch: observed.frame_document_epoch,
                            current_origin: observed.current_origin.clone(),
                            url_revision: observed.url_revision,
                            node_ref: None,
                            node_valid: observed.node_valid,
                            placement_owned: true,
                            resolved_ips: observed.resolved_ips.clone(),
                            credential_refs: observed.credential_refs.clone(),
                            feature: "browser:evaluate".to_owned(),
                            chromium_build: observed.chromium_build.clone(),
                            effective_isolation: observed.effective_isolation,
                        };
                        self.emergency_policy
                            .authorize_feature_dispatch(&context, || {
                                // Sample both clocks only after acquiring policy admission. A
                                // lock wait must never extend the action or ownership deadline.
                                if Instant::now() >= deadline {
                                    return Err(ApprovedActionError::DeadlineBeforeDispatch);
                                }
                                let now = self
                                    .clock
                                    .now()
                                    .map_err(|_| ApprovedActionError::Unavailable)?
                                    .max(session.machine.last_observed_at());
                                if [
                                    snapshot.lease_expires_at,
                                    snapshot.session_expires_at,
                                    snapshot.idle_expires_at,
                                ]
                                .into_iter()
                                .flatten()
                                .any(|at| now >= at)
                                {
                                    return Err(ApprovedActionError::DispatchRevoked);
                                }
                                effect_started = true;
                                executor
                                    .approved_dispatch_phase
                                    .store(APPROVED_DISPATCH_STARTED, Ordering::Release);
                                Ok(())
                            })
                            .map_err(|_| ApprovedActionError::DispatchRevoked)??;
                        Ok(())
                    })();
                    if admission.is_err() {
                        executor
                            .approved_dispatch_phase
                            .store(APPROVED_DISPATCH_AUTHORIZATION_REJECTED, Ordering::Release);
                    }
                    admission
                },
            )
        })();
        let completion = executor.approved_dispatch_wait.lock().ok();
        executor.approved_dispatch_phase.store(
            if effect_started {
                APPROVED_DISPATCH_RETURNED_UNCERTAIN
            } else {
                APPROVED_DISPATCH_STOPPED
            },
            Ordering::Release,
        );
        executor.approved_dispatch_changed.notify_all();
        drop(completion);
        match execution {
            Ok(ActionExecutionResult::Succeeded(result)) if effect_started => {
                ActionExecutionResult::Succeeded(result)
            }
            _ if effect_started => ActionExecutionResult::OutcomeUnknown,
            Ok(ActionExecutionResult::OutcomeUnknown)
            | Err(ApprovedActionError::OutcomeUncertain) => ActionExecutionResult::OutcomeUnknown,
            Err(ApprovedActionError::DeadlineBeforeDispatch) => {
                ActionExecutionResult::FailedKnown("action_timeout".to_owned())
            }
            Ok(ActionExecutionResult::Succeeded(_)) => ActionExecutionResult::OutcomeUnknown,
            _ => ActionExecutionResult::FailedKnown("evaluate_dispatch_rejected".to_owned()),
        }
    }
}
