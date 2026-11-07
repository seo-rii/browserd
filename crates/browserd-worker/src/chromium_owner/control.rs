//! Bounded owner control work progresses while a page command awaits Chromium.
use std::future::Future;
use std::pin::Pin;

use super::*;

pub(super) const MAX_PENDING_CONTROL: usize = 16;
pub(super) type ControlFuture = Pin<Box<dyn Future<Output = ControlCompletion> + Send>>;

pub(super) enum ControlCompletion {
    Health {
        response: std_mpsc::SyncSender<Result<(), OwnerActorError>>,
        result: Result<(), OwnerActorError>,
    },
    Dialog {
        target: OwnerAdmissionTarget,
        ownership: ContextOwnership,
        result: Result<(), OwnerActorError>,
    },
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) fn start_control(&mut self, request: OwnerRequest) -> Result<(), OwnerActorError> {
        let OwnerRequest::Health { response } = request else {
            return Err(OwnerActorError::Rejected);
        };
        if self.control_tasks.len() >= MAX_PENDING_CONTROL {
            return Err(OwnerActorError::StateOverflow);
        }
        let expected = self.driver.version().clone();
        let client = self.client.clone();
        let timeout = self.command_timeout;
        self.control_tasks.push(Box::pin(async move {
            let result = client
                .command("Browser.getVersion", json!({}), None, Some(timeout))
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)
                .and_then(|value| {
                    for (field, expected) in [
                        ("protocolVersion", expected.protocol_version.as_str()),
                        ("product", expected.product.as_str()),
                        ("revision", expected.revision.as_str()),
                        ("userAgent", expected.user_agent.as_str()),
                        ("jsVersion", expected.js_version.as_str()),
                    ] {
                        if value.get(field).and_then(Value::as_str) != Some(expected) {
                            return Err(OwnerActorError::OutcomeUncertain);
                        }
                    }
                    Ok(())
                });
            ControlCompletion::Health { response, result }
        }));
        Ok(())
    }

    pub(super) fn finish_control(
        &mut self,
        completed: ControlCompletion,
    ) -> Result<(), OwnerActorError> {
        if self.shutdown.is_cancelled() || self.event_failed_closed {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        match completed {
            ControlCompletion::Health { response, result } => {
                let failed = result.is_err();
                response
                    .send(result)
                    .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                if failed {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
            }
            ControlCompletion::Dialog {
                target,
                ownership,
                result,
            } => {
                // Exact flattened target scopes never authorize a replacement target. A close
                // racing the ACK retires this scope, so its rejection cannot taint a new page.
                if let Some(route) = self.routes.get(&target.target_id)
                    && route.admission_target(&target.target_id) == target
                    && route.ownership() == ownership
                {
                    result?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn dialog_opened(
        &mut self,
        session: Option<&str>,
        params: &Value,
    ) -> Result<(), OwnerActorError> {
        let session = session
            .filter(|id| valid_identifier(id))
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let (target_id, route) = self
            .routes
            .iter()
            .find(|(_, route)| route.route.session_id == session)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let context = self
            .contexts
            .get(&route.route.browser_context_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if context.lifecycle != ContextLifecycle::Active || context.ownership != route.ownership() {
            return Err(OwnerActorError::UnknownOwnership);
        }
        self.context_egress
            .check_active(&context.ownership, Instant::now())?;
        // The admitted default is auto_dismiss; an explicitly installed unsupported policy
        // cannot reach this effect. Alert acknowledgement is accept; all other dialogs dismiss.
        if context
            .options
            .as_ref()
            .is_some_and(|options| options.dialog_policy != "auto_dismiss")
        {
            return Err(OwnerActorError::Rejected);
        }
        let accept = match params.get("type").and_then(Value::as_str) {
            Some("alert") => true,
            Some("confirm" | "prompt" | "beforeunload") => false,
            _ => return Err(OwnerActorError::Rejected),
        };
        if self.control_tasks.len() >= MAX_PENDING_CONTROL {
            return Err(OwnerActorError::StateOverflow);
        }
        let target = route.admission_target(target_id);
        let ownership = context.ownership.clone();
        let session = session.to_owned();
        let client = self.client.clone();
        let timeout = self.command_timeout;
        let expires = self
            .context_egress
            .next_expiry()
            .map_or(Instant::now() + timeout, |lease| {
                lease.min(Instant::now() + timeout)
            });
        self.control_tasks.push(Box::pin(async move {
            let remaining = expires.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return ControlCompletion::Dialog {
                    target,
                    ownership,
                    result: Err(OwnerActorError::OutcomeUncertain),
                };
            }
            let result = client
                .command(
                    "Page.handleJavaScriptDialog",
                    json!({"accept": accept}),
                    Some(session),
                    Some(remaining),
                )
                .await
                .map_err(|_| OwnerActorError::OutcomeUncertain)
                .and_then(|value| {
                    value
                        .is_object()
                        .then_some(())
                        .ok_or(OwnerActorError::OutcomeUncertain)
                });
            ControlCompletion::Dialog {
                target,
                ownership,
                result,
            }
        }));
        Ok(())
    }

    pub(super) async fn control_interval(&mut self, wake: Instant) -> Result<(), OwnerActorError> {
        loop {
            self.ensure_context_wait_lease()?;
            if Instant::now() >= wake {
                return Ok(());
            }
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return Err(OwnerActorError::OutcomeUncertain),
                () = tokio::time::sleep_until(wake.into()) => return Ok(()),
                request = self.control_requests.recv() => {
                    self.start_control(request.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                complete = self.control_tasks.next(), if !self.control_tasks.is_empty() => {
                    self.finish_control(complete.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                incoming = self.events.recv() => {
                    self.handle_incoming(incoming.ok_or(OwnerActorError::OutcomeUncertain)?, None)?;
                }
            }
        }
    }

    /// ACKs must never recurse into download servicing, which may itself await an ACK.
    /// Checkpoint Fetch events are retained in a finite owner queue for its guarded handler;
    /// ordinary events, health, dialogs and shutdown remain live during the bounded ACK wait.
    pub(super) async fn control_ack<F>(
        &mut self,
        command: F,
        expires: Instant,
    ) -> Result<Value, OwnerActorError>
    where
        F: Future<Output = Result<Value, CdpCommandError>>,
    {
        tokio::pin!(command);
        loop {
            self.ensure_context_wait_lease()?;
            if Instant::now() >= expires {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return Err(OwnerActorError::OutcomeUncertain),
                () = tokio::time::sleep_until(expires.into()) => return Err(OwnerActorError::OutcomeUncertain),
                request = self.control_requests.recv() => {
                    self.start_control(request.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                complete = self.control_tasks.next(), if !self.control_tasks.is_empty() => {
                    self.finish_control(complete.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                incoming = self.events.recv() => {
                    let incoming = incoming.ok_or(OwnerActorError::OutcomeUncertain)?;
                    if matches!(&incoming, CdpIncoming::Event { method, .. } if method == "Fetch.requestPaused")
                        && self.checkpoint_interception.is_some()
                    {
                        if self.deferred_checkpoint_events.len() >= MAX_PENDING_CONTROL {
                            return Err(OwnerActorError::StateOverflow);
                        }
                        self.deferred_checkpoint_events.push_back(incoming);
                    } else {
                        self.handle_incoming(incoming, None)?;
                    }
                }
                response = &mut command => return response.map_err(map_command_error),
            }
        }
    }
}

pub(super) async fn checkpoint_event(
    events: &mut mpsc::Receiver<CdpIncoming>,
    deferred: &mut VecDeque<CdpIncoming>,
) -> Option<CdpIncoming> {
    if let Some(event) = deferred.pop_front() {
        Some(event)
    } else {
        events.recv().await
    }
}
