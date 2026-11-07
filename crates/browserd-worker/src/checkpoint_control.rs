//! Credential-equivalent state is kept out of action results and generic artifacts.

use super::*;

pub(super) struct CheckpointPublicationGuard {
    store: Arc<dyn CheckpointStore>,
    tenant: TenantId,
    session: SessionId,
    fence: OwnershipFence,
    action: ActionId,
    reference: String,
    degraded: Arc<AtomicBool>,
    committed: bool,
}

impl CheckpointPublicationGuard {
    pub(super) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for CheckpointPublicationGuard {
    fn drop(&mut self) {
        if !self.committed
            && self
                .store
                .discard(
                    &self.tenant,
                    &self.session,
                    &self.fence,
                    &self.action,
                    &self.reference,
                )
                .is_err()
        {
            self.degraded.store(true, Ordering::Release);
        }
    }
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub(super) fn cleanup_expired_checkpoints(&self, now: SessionTime) -> Result<(), WorkerError> {
        let Some(store) = &self.checkpoint_store else {
            return Ok(());
        };
        let mut last = self
            .checkpoint_cleanup_at
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let instant = Instant::now();
        if last.is_some_and(|previous| instant.duration_since(previous) < Duration::from_secs(60)) {
            return Ok(());
        }
        store
            .cleanup_expired(now.max(self.clock.now()?).get())
            .map_err(|_| WorkerError::DurabilityUnavailable)?;
        *last = Some(instant);
        Ok(())
    }

    fn audit_checkpoint_intent(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        event_suffix: &str,
        operation: &str,
        extra: Value,
    ) -> Result<(), WorkerError> {
        let wal = self
            .audit_wal
            .as_ref()
            .ok_or(WorkerError::DurabilityUnavailable)?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "tenant_id":tenant_id,
            "session_id":session_id,
            "context":extra,
        }))
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        let event = AuditEvent::new(
            AuditEventId::new(format!("checkpoint-{operation}:{event_suffix}"))
                .map_err(|_| WorkerError::InvalidConfiguration)?,
            format!("checkpoint.{operation}.intent"),
            payload,
            true,
        );
        match wal
            .append(event)
            .map_err(|_| WorkerError::DurabilityUnavailable)?
        {
            AppendOutcome::Durable(_) | AppendOutcome::Existing(_) => Ok(()),
            AppendOutcome::DroppedNonCritical => Err(WorkerError::DurabilityUnavailable),
        }
    }

    pub(super) fn audit_checkpoint_restore_intent(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        reference: &str,
    ) -> Result<(), WorkerError> {
        self.audit_checkpoint_intent(
            tenant_id, session_id, &session_id.to_string(), "restore",
            serde_json::json!({"checkpoint_ref_sha256":format!("{:x}", Sha256::digest(reference.as_bytes()))}),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_checkpoint(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        origins: &[String],
        action_id: &ActionId,
        requester: &PrincipalId,
        deadline: Instant,
        executor: &Arc<SessionExecutor>,
        typed: Option<(
            &crate::action_approval::TypedActionAdmission,
            Option<&crate::ApprovalRequest>,
        )>,
    ) -> (ActionExecutionResult, Option<CheckpointPublicationGuard>) {
        let mut publication = None;
        let capture = (|| -> Result<Vec<u8>, CheckpointError> {
            if self.checkpoint_cleanup_degraded.load(Ordering::Acquire) {
                return Err(CheckpointError::Unavailable);
            }
            let store = self
                .checkpoint_store
                .as_ref()
                .ok_or(CheckpointError::Rejected)?;
            let _admission = self
                .capture_admission
                .acquire(browserd_features::AdmissionClass::LargeSnapshot)
                .map_err(|_| CheckpointError::Rejected)?;
            let _cleanup = executor
                .cleanup_owner
                .lock()
                .map_err(|_| CheckpointError::Unavailable)?;
            let inspect = || -> Result<TenantId, CheckpointError> {
                if Instant::now() >= deadline {
                    return Err(CheckpointError::DeadlineBeforeDispatch);
                }
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| CheckpointError::Unavailable)?;
                validate_fence(&session, fence).map_err(|_| CheckpointError::Rejected)?;
                let now = self
                    .clock
                    .now()
                    .map_err(|_| CheckpointError::Unavailable)?
                    .max(session.machine.last_observed_at());
                let snapshot = session.machine.snapshot();
                if session.machine.session_id() != session_id
                    || session.machine.lifecycle() != SessionLifecycle::Ready
                    || snapshot.execution != SessionExecution::Running(action_id.clone())
                    || !session.occupies_capacity
                    || session.durability_degraded
                    || snapshot.lease_expires_at.is_none_or(|expiry| now >= expiry)
                    || snapshot.session_expires_at.is_some_and(|expiry| now >= expiry)
                    || snapshot.idle_expires_at.is_some_and(|expiry| now >= expiry)
                    || !session.actions.get(action_id).is_some_and(|action| {
                        action.snapshot.status == ActionStatus::Running
                            && &action.requester_principal_id == requester
                            && action.dispatch_permit.is_some()
                            && matches!(serde_json::from_slice::<WorkerActionCommand>(&action.payload),
                                Ok(WorkerActionCommand::Checkpoint { origins: requested }) if requested == origins)
                    })
                {
                    return Err(CheckpointError::Rejected);
                }
                Ok(session.tenant_id.clone())
            };
            let tenant_id = inspect()?;
            self.admit_runtime_operation(&tenant_id, session_id, "browser:checkpoint")
                .map_err(|_| CheckpointError::Rejected)?;
            self.audit_checkpoint_intent(
                &tenant_id, session_id, &action_id.to_string(), "create",
                serde_json::json!({
                    "action_id":action_id,
                    "principal_id":requester,
                    "origin_sha256":origins.iter().map(|origin| format!("{:x}", Sha256::digest(origin.as_bytes()))).collect::<Vec<_>>(),
                }),
            ).map_err(|_| CheckpointError::Rejected)?;
            let snapshot = if let Some((admission, approval)) = typed {
                crate::action_approval::begin_typed_driver(executor)
                    .and_then(|()| {
                        self.driver.capture_typed_checkpoint_until(
                            &admission.observation,
                            origins,
                            deadline,
                            &mut |observed| {
                                self.admit_typed_effect(
                                    admission, approval, observed, action_id, deadline, executor,
                                )
                            },
                        )
                    })
                    .map_err(|error| match error {
                        crate::ApprovedActionError::OutcomeUncertain => {
                            CheckpointError::OutcomeUncertain
                        }
                        crate::ApprovedActionError::DeadlineBeforeDispatch => {
                            CheckpointError::DeadlineBeforeDispatch
                        }
                        _ => CheckpointError::Rejected,
                    })?
            } else {
                self.admit_runtime_operation(&tenant_id, session_id, "browser:checkpoint")
                    .map_err(|_| CheckpointError::Rejected)?;
                self.driver
                    .capture_checkpoint_until(&tenant_id, session_id, fence, origins, deadline)?
            };
            snapshot.validate()?;
            if snapshot.origins.len() != origins.len()
                || !origins
                    .iter()
                    .all(|origin| snapshot.origins.iter().any(|state| &state.origin == origin))
                || inspect()? != tenant_id
            {
                return Err(CheckpointError::Rejected);
            }
            let receipt = store.save(
                &tenant_id,
                session_id,
                fence,
                action_id,
                snapshot,
                self.clock
                    .now()
                    .map_err(|_| CheckpointError::Unavailable)?
                    .get(),
                deadline,
            )?;
            publication = Some(CheckpointPublicationGuard {
                store: Arc::clone(store),
                tenant: tenant_id.clone(),
                session: session_id.clone(),
                fence: fence.clone(),
                action: action_id.clone(),
                reference: receipt.checkpoint_ref.clone(),
                degraded: Arc::clone(&self.checkpoint_cleanup_degraded),
                committed: false,
            });
            if receipt.source_session_id != *session_id {
                return Err(CheckpointError::OutcomeUncertain);
            }
            // A reference is published only while the action still owns admission. Close or
            // cancellation can win during storage IO; remove that exact unpublished object.
            if inspect().is_err() {
                return Err(CheckpointError::Rejected);
            }
            serde_json::to_vec(&serde_json::json!({"checkpoint_ref":receipt.checkpoint_ref}))
                .map_err(|_| CheckpointError::Unavailable)
        })();
        let outcome = match capture {
            Ok(result) => ActionExecutionResult::Succeeded(result),
            Err(CheckpointError::OutcomeUncertain) => ActionExecutionResult::OutcomeUnknown,
            Err(CheckpointError::DeadlineBeforeDispatch) => {
                ActionExecutionResult::FailedKnown("action_timeout".to_owned())
            }
            Err(_) => ActionExecutionResult::FailedKnown("checkpoint_rejected".to_owned()),
        };
        (outcome, publication)
    }
}
