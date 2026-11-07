//! Authoritative policy decisions are made from the queue head's owned browser observation.

use super::*;
use browserd_policy::{
    ActionApprovalDecision as PolicyDecision, ActionApprovalOutcome, ApprovalActionKind,
    ApprovalArtifactBinding, ApprovalWorkerFence, CredentialRefsHash, TypedActionPayload,
    TypedActionProposalBinding,
};

#[derive(Clone, Debug)]
pub(crate) struct TypedActionAdmission {
    pub(crate) proposal: CanonicalActionProposal,
    pub(crate) observation: TypedApprovalObservation,
    pub(crate) decision: PolicyDecision,
    pub(crate) secret_grant: Option<SecretGrant>,
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub(crate) fn expire_action_approvals(
        &self,
        session: &mut SessionState,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<usize, WorkerError> {
        for approval in session.approvals.values().filter(|approval| {
            approval.state == ApprovalState::Pending
                && now >= approval.expires_at
                && approval.proposal.typed_binding().is_some()
        }) {
            if let Err(error) =
                self.audit_approval_event("expire", &approval.proposal, None, serde_json::json!({}))
            {
                session.durability_degraded = true;
                return Err(error);
            }
        }
        expire_pending_approvals(session, fence, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_typed_effect(
        &self,
        admission: &TypedActionAdmission,
        request: Option<&ApprovalRequest>,
        observed: &TypedApprovalObservation,
        action_id: &ActionId,
        deadline: Instant,
        executor: &SessionExecutor,
    ) -> Result<(), ApprovedActionError> {
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
        let result = (|| {
            if Instant::now() >= deadline {
                return Err(ApprovedActionError::DeadlineBeforeDispatch);
            }
            if observed != &admission.observation {
                return Err(ApprovedActionError::ApprovalStale(
                    StaleApprovalReason::ActionBinding,
                ));
            }
            let policy = self
                .action_approval_policy
                .as_ref()
                .ok_or(ApprovedActionError::DispatchRevoked)?;
            let binding = admission
                .proposal
                .typed_binding()
                .ok_or(ApprovedActionError::DispatchRevoked)?;
            if binding.action_id != *action_id
                || binding.policy_digest != policy.digest()
                || policy
                    .evaluate_proposal(&admission.proposal)
                    .map_err(|_| ApprovedActionError::DispatchRevoked)?
                    != admission.decision
            {
                return Err(ApprovedActionError::DispatchRevoked);
            }
            let session = executor
                .state
                .lock()
                .map_err(|_| ApprovedActionError::Unavailable)?;
            validate_fence(&session, &observed.fence)
                .map_err(|_| ApprovedActionError::DispatchRevoked)?;
            let snapshot = session.machine.snapshot();
            let action = session
                .actions
                .get(action_id)
                .ok_or(ApprovedActionError::DispatchRevoked)?;
            if snapshot.lifecycle != SessionLifecycle::Ready
                || snapshot.execution != SessionExecution::Running(action_id.clone())
                || !session.occupies_capacity
                || session.durability_degraded
                || session.tenant_id != observed.tenant_id
                || session.machine.session_id() != &observed.session_id
                || action.snapshot.status != ActionStatus::Running
                || action.dispatch_permit.is_none()
                || action.snapshot.action_sequence.get() != binding.sequence
                || action.requester_principal_id != *admission.proposal.requester_principal_id()
                || action.page_id != observed.page_id
                || ActionArgumentsHash::digest(&action.payload)
                    != admission.proposal.canonical_arguments_hash()
                || action
                    .policy_admission
                    .as_ref()
                    .is_none_or(|original| original.proposal.hash() != admission.proposal.hash())
                || observed.page_id.as_ref().is_some_and(|page| {
                    !session.pages.contains(page) || session.closing_pages.contains(page)
                })
            {
                return Err(ApprovedActionError::DispatchRevoked);
            }
            if let TypedActionPayload::SetFiles { files, .. } = &binding.payload {
                let ids = files
                    .iter()
                    .map(|file| file.artifact_id.clone())
                    .collect::<Vec<_>>();
                if &self
                    .approval_artifact_bindings(&session, &observed.fence, &ids)
                    .map_err(|_| ApprovedActionError::DispatchRevoked)?
                    != files
                {
                    return Err(ApprovedActionError::ApprovalStale(
                        StaleApprovalReason::ActionBinding,
                    ));
                }
            }
            let context = ExecutionContext {
                tenant_id: observed.tenant_id.clone(),
                requester_principal_id: action.requester_principal_id.clone(),
                session_id: observed.session_id.clone(),
                session_incarnation: observed.fence.session_incarnation(),
                page_id: admission.proposal.page_id().clone(),
                target_incarnation: observed.live.target_incarnation,
                frame_document_epoch: observed.live.frame_document_epoch,
                current_origin: observed.live.current_origin.clone(),
                url_revision: observed.live.url_revision,
                node_ref: observed.live.node_ref.clone(),
                node_valid: observed.live.node_valid,
                placement_owned: true,
                resolved_ips: observed.live.resolved_ips.clone(),
                credential_refs: observed.live.credential_refs.clone(),
                feature: format!("browser:{}", binding.payload.action_kind().as_str()),
                chromium_build: observed.live.chromium_build.clone(),
                effective_isolation: observed.live.effective_isolation,
            };
            let trusted_now = || -> Result<u64, ApprovedActionError> {
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
                .any(|expiry| now >= expiry)
                    || now.get() >= admission.proposal.expires_at_unix_ms()
                    || Instant::now() >= deadline
                {
                    return Err(ApprovedActionError::DeadlineBeforeDispatch);
                }
                Ok(now.get())
            };
            let commit = || {
                executor
                    .approved_dispatch_phase
                    .store(APPROVED_DISPATCH_STARTED, Ordering::Release)
            };
            match admission.decision.outcome {
                ActionApprovalOutcome::Manual => {
                    let request = request.ok_or(ApprovedActionError::DispatchRevoked)?;
                    let approval = action
                        .approval_id
                        .as_ref()
                        .and_then(|id| session.approvals.get(id))
                        .ok_or(ApprovedActionError::DispatchRevoked)?;
                    if !approval
                        .request
                        .as_ref()
                        .is_some_and(|original| std::ptr::eq(original.as_ref(), request))
                    {
                        return Err(ApprovedActionError::DispatchRevoked);
                    }
                    request
                        .authorize_typed_and_dispatch_with_clock(
                            &self.emergency_policy,
                            &context,
                            binding,
                            policy,
                            trusted_now,
                            commit,
                        )
                        .map_err(|error| match error {
                            ApprovalAuthorizationError::Approval(ApprovalError::ApprovalStale(
                                reason,
                            )) => ApprovedActionError::ApprovalStale(reason),
                            ApprovalAuthorizationError::Approval(_) => {
                                ApprovedActionError::DispatchRevoked
                            }
                            ApprovalAuthorizationError::Clock(error) => error,
                        })
                }
                ActionApprovalOutcome::Allow => {
                    if request.is_some() {
                        return Err(ApprovedActionError::DispatchRevoked);
                    }
                    self.emergency_policy
                        .authorize_feature_dispatch(&context, || {
                            trusted_now()?;
                            commit();
                            Ok(())
                        })
                        .map_err(|_| ApprovedActionError::DispatchRevoked)?
                }
                ActionApprovalOutcome::Deny => Err(ApprovedActionError::DispatchRevoked),
            }
        })();
        if result.is_err() {
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_AUTHORIZATION_REJECTED, Ordering::Release);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_typed_policy_action(
        &self,
        admission: &TypedActionAdmission,
        request: Option<&ApprovalRequest>,
        action_id: &ActionId,
        requester: &PrincipalId,
        payload: &[u8],
        deadline: Instant,
        executor: &Arc<SessionExecutor>,
    ) -> (
        ActionExecutionResult,
        Option<checkpoint_control::CheckpointPublicationGuard>,
    ) {
        let mut checkpoint = None;
        let observed = &admission.observation;
        let execution = (|| -> Result<ActionExecutionResult, ApprovedActionError> {
            self.audit_approval_event("dispatch", &admission.proposal, None, serde_json::json!({}))
                .map_err(|_| ApprovedActionError::DispatchRevoked)?;
            let command: WorkerActionCommand = serde_json::from_slice(payload)
                .map_err(|_| ApprovedActionError::DispatchRevoked)?;
            if ActionArgumentsHash::digest(payload) != admission.proposal.canonical_arguments_hash()
            {
                return Err(ApprovedActionError::DispatchRevoked);
            }
            let mut callback = |current: &TypedApprovalObservation| {
                self.admit_typed_effect(admission, request, current, action_id, deadline, executor)
            };
            match command {
                WorkerActionCommand::Checkpoint { origins } => {
                    let (outcome, publication) = self.execute_checkpoint(
                        &observed.session_id,
                        &observed.fence,
                        &origins,
                        action_id,
                        requester,
                        deadline,
                        executor,
                        Some((admission, request)),
                    );
                    checkpoint = publication;
                    Ok(outcome)
                }
                WorkerActionCommand::FillSecret { secret_ref, .. } => {
                    let resolver = self
                        .secret_resolver
                        .as_ref()
                        .ok_or(ApprovedActionError::DispatchRevoked)?;
                    let expected_grant = admission
                        .secret_grant
                        .as_ref()
                        .ok_or(ApprovedActionError::DispatchRevoked)?;
                    let grant = resolver
                        .authorize(
                            &observed.tenant_id,
                            requester,
                            &secret_ref,
                            &observed.live.current_origin,
                            deadline,
                        )
                        .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                    if &grant != expected_grant {
                        return Err(ApprovedActionError::DispatchRevoked);
                    }
                    // Revocation already visible before value preparation must prevent a value
                    // read. The callback repeats admission at the actual effect boundary.
                    self.emergency_policy
                        .authorize_secret_dispatch(
                            &observed.tenant_id,
                            &observed.session_id,
                            &secret_ref,
                            &observed.live.current_origin,
                            || (),
                        )
                        .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                    self.audit_secret_injection_intent(
                        &observed.tenant_id,
                        &observed.session_id,
                        action_id,
                        requester,
                        &grant,
                    )
                    .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                    let value_deadline = Instant::now()
                        .checked_add(Duration::from_secs(5))
                        .ok_or(ApprovedActionError::Unavailable)?
                        .min(deadline);
                    let secret = resolver
                        .resolve(&grant, value_deadline)
                        .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                    if secret.grant() != &grant {
                        return Err(ApprovedActionError::DispatchRevoked);
                    }
                    begin_typed_driver(executor)?;
                    self.driver
                        .execute_typed_secret_until(
                            observed,
                            secret,
                            value_deadline,
                            &mut |current| {
                                self.admit_typed_effect(
                                    admission,
                                    request,
                                    current,
                                    action_id,
                                    value_deadline,
                                    executor,
                                )
                            },
                        )
                        .map(|outcome| match outcome {
                            ActionExecutionResult::Succeeded(_) => {
                                ActionExecutionResult::Succeeded(b"{\"ok\":true}".to_vec())
                            }
                            ActionExecutionResult::OutcomeUnknown => {
                                ActionExecutionResult::OutcomeUnknown
                            }
                            ActionExecutionResult::FailedKnown(_) => {
                                ActionExecutionResult::FailedKnown("secret_rejected".to_owned())
                            }
                        })
                }
                WorkerActionCommand::SetFiles {
                    node_ref,
                    artifact_ids,
                } => {
                    let _cleanup = executor
                        .cleanup_owner
                        .lock()
                        .map_err(|_| ApprovedActionError::Unavailable)?;
                    let page = observed
                        .page_id
                        .as_ref()
                        .ok_or(ApprovedActionError::DispatchRevoked)?;
                    let files = self
                        .prepare_file_attachments(
                            &observed.session_id,
                            page,
                            &observed.fence,
                            &node_ref,
                            &artifact_ids,
                            deadline,
                            executor,
                        )
                        .map_err(|_| ApprovedActionError::DispatchRevoked)?;
                    begin_typed_driver(executor)?;
                    self.driver
                        .execute_typed_files_until(observed, files, deadline, &mut callback)
                }
                command => {
                    if let Some(capture) = command.capture_command() {
                        let page = observed
                            .page_id
                            .as_ref()
                            .ok_or(ApprovedActionError::DispatchRevoked)?;
                        self.execute_capture(
                            &observed.session_id,
                            page,
                            &observed.fence,
                            capture,
                            action_id,
                            deadline,
                            executor,
                            Some((admission, request)),
                        )
                        .map(ActionExecutionResult::Succeeded)
                        .map_err(|_| ApprovedActionError::DispatchRevoked)
                    } else {
                        begin_typed_driver(executor)?;
                        self.driver.execute_typed_browser_until(
                            observed,
                            payload,
                            deadline,
                            &mut callback,
                        )
                    }
                }
            }
        })();
        let started =
            executor.approved_dispatch_phase.load(Ordering::Acquire) == APPROVED_DISPATCH_STARTED;
        let outcome = match execution {
            Ok(ActionExecutionResult::Succeeded(result)) if started => {
                ActionExecutionResult::Succeeded(result)
            }
            Ok(_) if started => ActionExecutionResult::OutcomeUnknown,
            Err(_) if started => ActionExecutionResult::OutcomeUnknown,
            Ok(ActionExecutionResult::Succeeded(_) | ActionExecutionResult::OutcomeUnknown) => {
                ActionExecutionResult::OutcomeUnknown
            }
            Ok(outcome) => outcome,
            Err(ApprovedActionError::DeadlineBeforeDispatch) => {
                ActionExecutionResult::FailedKnown("action_timeout".to_owned())
            }
            Err(ApprovedActionError::OutcomeUncertain) => ActionExecutionResult::OutcomeUnknown,
            Err(ApprovedActionError::ApprovalStale(_)) => {
                let _ = self.audit_approval_event(
                    "stale",
                    &admission.proposal,
                    None,
                    serde_json::json!({}),
                );
                ActionExecutionResult::FailedKnown("approval_stale".to_owned())
            }
            Err(_) => ActionExecutionResult::FailedKnown("action_approval_rejected".to_owned()),
        };
        let waiter = executor.approved_dispatch_wait.lock().ok();
        executor.approved_dispatch_phase.store(
            if started {
                APPROVED_DISPATCH_RETURNED_UNCERTAIN
            } else {
                APPROVED_DISPATCH_STOPPED
            },
            Ordering::Release,
        );
        executor.approved_dispatch_changed.notify_all();
        drop(waiter);
        (outcome, checkpoint)
    }

    /// No browser or provider I/O runs under the session mutex. ActionOwner serializes queue heads;
    /// cancellation and close are checked again when the resulting decision is installed.
    pub(crate) fn prepare_action_policy(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        executor: &SessionExecutor,
    ) -> Result<(), WorkerError> {
        let Some(policy) = &self.action_approval_policy else {
            return Ok(());
        };
        let (
            id,
            sequence,
            tenant,
            requester,
            page,
            primary_page,
            payload,
            timeout,
            effective_isolation,
        ) = {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            let Some(id) = session.action_queue.front() else {
                return Ok(());
            };
            let action = session.actions.get(id).ok_or(WorkerError::ActionNotFound)?;
            if action.policy_admission.is_some()
                || action.policy_failure.is_some()
                || action.snapshot.status != ActionStatus::Queued
            {
                return Ok(());
            }
            (
                id.clone(),
                action.snapshot.action_sequence,
                session.tenant_id.clone(),
                action.requester_principal_id.clone(),
                action.page_id.clone(),
                session.primary_page_id.clone(),
                action.payload.clone(),
                action.execution_timeout,
                session.effective_isolation,
            )
        };
        let prepared = (|| -> Result<TypedActionAdmission, WorkerError> {
            let command: WorkerActionCommand = serde_json::from_slice(&payload)
                .map_err(|_| WorkerError::ApprovalEvidenceMismatch)?;
            if !command.is_valid() {
                return Err(WorkerError::ApprovalEvidenceMismatch);
            }
            let deadline = Instant::now()
                .checked_add(timeout.min(Duration::from_secs(5)))
                .ok_or(WorkerError::InvalidConfiguration)?;
            let observation = self
                .driver
                .inspect_typed_approval_until(
                    &tenant,
                    session_id,
                    page.as_ref(),
                    fence,
                    &command,
                    deadline,
                )
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            if observation.tenant_id != tenant
                || observation.session_id != *session_id
                || observation.fence != *fence
                || observation.page_id != page
                || !observation.live.node_valid
                || observation.live.effective_isolation
                    != match effective_isolation {
                        WorkerIsolationProfile::SharedContext => IsolationProfile::SharedContext,
                        WorkerIsolationProfile::TenantDedicatedShard => {
                            IsolationProfile::TenantDedicatedShard
                        }
                        WorkerIsolationProfile::DedicatedProcess => {
                            IsolationProfile::DedicatedProcess
                        }
                        WorkerIsolationProfile::DedicatedWorker => {
                            IsolationProfile::DedicatedWorker
                        }
                    }
            {
                return Err(WorkerError::ApprovalEvidenceMismatch);
            }
            let (typed_payload, secret_grant) = match &command {
                WorkerActionCommand::FillSecret {
                    node_ref,
                    secret_ref,
                } => {
                    let resolver = self
                        .secret_resolver
                        .as_ref()
                        .ok_or(WorkerError::DependencyUnavailable)?;
                    let node = observation
                        .node_binding
                        .clone()
                        .filter(|node| node.node_ref == *node_ref)
                        .ok_or(WorkerError::ApprovalEvidenceMismatch)?;
                    let grant = resolver
                        .authorize(
                            &tenant,
                            &requester,
                            secret_ref,
                            &observation.live.current_origin,
                            deadline,
                        )
                        .map_err(|_| WorkerError::DependencyUnavailable)?;
                    if grant.tenant_id() != &tenant
                        || grant.principal_id() != &requester
                        || grant.secret_ref() != secret_ref
                        || grant.origin() != &observation.live.current_origin
                    {
                        return Err(WorkerError::ApprovalEvidenceMismatch);
                    }
                    (
                        TypedActionPayload::FillSecret {
                            node,
                            secret_ref: secret_ref.clone(),
                            grant_metadata_sha256: grant.metadata_digest(),
                        },
                        Some(grant),
                    )
                }
                WorkerActionCommand::SetFiles {
                    node_ref,
                    artifact_ids,
                } => {
                    let node = observation
                        .node_binding
                        .clone()
                        .filter(|node| node.node_ref == *node_ref)
                        .ok_or(WorkerError::ApprovalEvidenceMismatch)?;
                    let session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    validate_fence(&session, fence)?;
                    (
                        TypedActionPayload::SetFiles {
                            node,
                            files: self.approval_artifact_bindings(
                                &session,
                                fence,
                                artifact_ids,
                            )?,
                        },
                        None,
                    )
                }
                WorkerActionCommand::Checkpoint { origins } => {
                    if self.checkpoint_store.is_none() {
                        return Err(WorkerError::DependencyUnavailable);
                    }
                    (
                        TypedActionPayload::Checkpoint {
                            origins: origins.clone(),
                            build_identity_sha256: observation.build_identity_sha256,
                        },
                        None,
                    )
                }
                _ => (
                    TypedActionPayload::Browser {
                        action: action_kind(&command),
                        arguments_sha256: Sha256::digest(&payload).into(),
                        node: observation.node_binding.clone(),
                        navigation_destination: match &command {
                            WorkerActionCommand::Navigate { url, .. } => Some(
                                url::Url::parse(url)
                                    .map_err(|_| WorkerError::ApprovalEvidenceMismatch)?
                                    .as_str()
                                    .to_owned(),
                            ),
                            _ => None,
                        },
                    },
                    None,
                ),
            };
            let trusted_now = self.clock.now()?;
            let expires = trusted_now
                .get()
                .checked_add(self.config.approval_timeout_millis)
                .ok_or(WorkerError::InvalidConfiguration)?;
            let legacy_type = typed_payload.legacy_action_type();
            let node_ref = typed_payload
                .node()
                .map(|node| NodeReference::new(&node.node_ref))
                .transpose()
                .map_err(|_| WorkerError::ApprovalEvidenceMismatch)?;
            let binding = TypedActionProposalBinding {
                schema_version: 2,
                action_id: id.clone(),
                sequence: sequence.get(),
                fence: ApprovalWorkerFence {
                    worker_id: fence.worker_id().clone(),
                    worker_epoch: fence.worker_epoch(),
                    placement_version: fence.placement_version(),
                    session_incarnation: fence.session_incarnation(),
                },
                policy_digest: policy.digest(),
                target_binding_sha256: observation.target_binding_sha256,
                context_scope: observation.context_scope.clone(),
                payload: typed_payload,
            };
            let proposal = CanonicalActionProposal::new(
                tenant.clone(),
                requester.clone(),
                session_id.clone(),
                fence.session_incarnation(),
                page.clone().unwrap_or(primary_page),
                observation.live.target_incarnation,
                observation.live.frame_document_epoch,
                observation.live.current_origin.clone(),
                observation.live.url_revision,
                legacy_type,
                ActionArgumentsHash::digest(&payload),
                node_ref,
                CredentialRefsHash::digest(
                    observation.live.credential_refs.iter().map(String::as_str),
                ),
                expires,
            )
            .with_typed_binding(binding)
            .map_err(|_| WorkerError::ApprovalEvidenceMismatch)?;
            let decision = policy
                .evaluate_proposal(&proposal)
                .map_err(|_| WorkerError::ApprovalEvidenceMismatch)?;
            self.audit_approval_event(
                "proposal",
                &proposal,
                None,
                serde_json::json!({"decision":decision.outcome}),
            )?;
            Ok(TypedActionAdmission {
                proposal,
                observation,
                decision,
                secret_grant,
            })
        })();
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        if session.machine.lifecycle() != SessionLifecycle::Ready
            || session.action_queue.front() != Some(&id)
            || !session
                .actions
                .get(&id)
                .is_some_and(|a| a.snapshot.status == ActionStatus::Queued)
        {
            return Ok(());
        }
        match prepared {
            Ok(admission) if admission.decision.outcome == ActionApprovalOutcome::Manual => {
                let approval_id = ApprovalId::new();
                session
                    .action_ledger
                    .require_approval_with_identity(
                        fence.as_placement_fence(),
                        &id,
                        approval_id.clone(),
                    )
                    .map_err(map_action_ledger_error)?;
                let binding = admission
                    .proposal
                    .typed_binding()
                    .ok_or(WorkerError::StateUnavailable)?;
                session.approvals.insert(
                    approval_id.clone(),
                    ApprovalRecord {
                        action_id: id.clone(),
                        state: ApprovalState::Pending,
                        expires_at: SessionTime::new(admission.proposal.expires_at_unix_ms()),
                        proposal: admission.proposal.clone(),
                        feature: format!("browser:{}", binding.payload.action_kind().as_str()),
                        require_four_eyes: admission.decision.require_four_eyes,
                        request: None,
                    },
                );
                let action = session
                    .actions
                    .get_mut(&id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::PendingApproval;
                action.approval_id = Some(approval_id);
                action.policy_admission = Some(admission);
            }
            other => {
                session
                    .action_ledger
                    .mark_ready(fence.as_placement_fence(), &id)
                    .map_err(map_action_ledger_error)?;
                let action = session
                    .actions
                    .get_mut(&id)
                    .ok_or(WorkerError::ActionNotFound)?;
                match other {
                    Ok(admission) if admission.decision.outcome == ActionApprovalOutcome::Allow => {
                        action.policy_admission = Some(admission)
                    }
                    Ok(_) => action.policy_failure = Some("action_policy_denied"),
                    Err(_) => action.policy_failure = Some("action_policy_preparation_rejected"),
                }
            }
        }
        Ok(())
    }

    fn approval_artifact_bindings(
        &self,
        session: &SessionState,
        fence: &OwnershipFence,
        ids: &[ArtifactId],
    ) -> Result<Vec<ApprovalArtifactBinding>, WorkerError> {
        let mut bindings = Vec::with_capacity(ids.len());
        for id in ids {
            let record = session
                .artifacts
                .get(id)
                .ok_or(WorkerError::ArtifactNotFound)?;
            self.validate_artifact_record_publication(record, fence)?;
            let publication = record
                .publication
                .as_ref()
                .ok_or(WorkerError::ArtifactNotFound)?;
            let canonical =
                serde_json::to_vec(&ArtifactPublicationWire::from_publication(publication))
                    .map_err(|_| WorkerError::StateUnavailable)?;
            let metadata = publication.metadata();
            bindings.push(ApprovalArtifactBinding {
                artifact_id: id.clone(),
                object_generation: *publication.object_generation().as_bytes(),
                size_bytes: metadata.size_bytes(),
                checksum_sha256: *metadata.checksum().as_bytes(),
                effective_filename: record
                    .display_filename
                    .clone()
                    .unwrap_or_else(|| format!("{id}.bin")),
                publication_sha256: Sha256::digest(canonical).into(),
                scan_evidence_sha256: publication
                    .scan_attestation()
                    .map(|evidence| *evidence.digest()),
            });
        }
        Ok(bindings)
    }

    pub(crate) fn audit_approval_event(
        &self,
        kind: &str,
        proposal: &CanonicalActionProposal,
        principal: Option<&PrincipalId>,
        detail: serde_json::Value,
    ) -> Result<(), WorkerError> {
        let wal = self
            .audit_wal
            .as_ref()
            .ok_or(WorkerError::DependencyUnavailable)?;
        let binding = proposal
            .typed_binding()
            .ok_or(WorkerError::ApprovalEvidenceMismatch)?;
        let event = AuditEvent::new(
            AuditEventId::new(format!("action-approval:{kind}:{}", binding.action_id))
                .map_err(|_| WorkerError::StateUnavailable)?,
            format!("action.approval.{kind}"),
            serde_json::to_vec(&serde_json::json!({"tenant_id":proposal.tenant_id(),
                "session_id":proposal.session_id(), "action_id":binding.action_id,
                "sequence":binding.sequence, "requester":proposal.requester_principal_id(),
                "principal":principal, "proposal_hash":proposal.hash().as_bytes(),
                "policy_digest":binding.policy_digest, "fence":binding.fence,"detail":detail}))
            .map_err(|_| WorkerError::StateUnavailable)?,
            true,
        );
        match wal
            .append(event)
            .map_err(|_| WorkerError::DependencyUnavailable)?
        {
            AppendOutcome::Durable(_) | AppendOutcome::Existing(_) => Ok(()),
            AppendOutcome::DroppedNonCritical => Err(WorkerError::DependencyUnavailable),
        }
    }
}

fn action_kind(command: &WorkerActionCommand) -> ApprovalActionKind {
    use ApprovalActionKind as K;
    use WorkerActionCommand as C;
    match command {
        C::Navigate { .. } => K::Navigate,
        C::Reload => K::Reload,
        C::GoBack => K::GoBack,
        C::GoForward => K::GoForward,
        C::Click { .. } => K::Click,
        C::DoubleClick { .. } => K::DoubleClick,
        C::Hover { .. } => K::Hover,
        C::Focus { .. } => K::Focus,
        C::Blur { .. } => K::Blur,
        C::Check { .. } => K::Check,
        C::Uncheck { .. } => K::Uncheck,
        C::Fill { .. } => K::Fill,
        C::FillSecret { .. } => K::FillSecret,
        C::SelectOption { .. } => K::SelectOption,
        C::SetFiles { .. } => K::SetFiles,
        C::Evaluate { .. } => K::Evaluate,
        C::WaitFor { .. } => K::WaitFor,
        C::HandleDialog { .. } => K::HandleDialog,
        C::Snapshot => K::Snapshot,
        C::TypeText { .. } => K::TypeText,
        C::PressKey { .. } => K::PressKey,
        C::Scroll { .. } => K::Scroll,
        C::QueryAll { .. } => K::QueryAll,
        C::GetText { .. } => K::GetText,
        C::GetHtml { .. } => K::GetHtml,
        C::GetAttribute { .. } => K::GetAttribute,
        C::GetProperties { .. } => K::GetProperties,
        C::GetComputedStyle { .. } => K::GetComputedStyle,
        C::ExtractTable { .. } => K::ExtractTable,
        C::GetUrl => K::GetUrl,
        C::GetTitle => K::GetTitle,
        C::Screenshot { .. } => K::Screenshot,
        C::Pdf { .. } => K::Pdf,
        C::Scrape { .. } => K::Scrape,
        C::Checkpoint { .. } => K::Checkpoint,
    }
}

pub(crate) fn begin_typed_driver(executor: &SessionExecutor) -> Result<(), ApprovedActionError> {
    executor
        .approved_dispatch_phase
        .compare_exchange(
            APPROVED_DISPATCH_INSPECTING,
            APPROVED_DISPATCH_DRIVER_PENDING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|_| ApprovedActionError::DispatchRevoked)
}
