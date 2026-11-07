//! Recover missing terminal WAL proofs without querying or recreating a browser session.
use super::*;
use browserd_actions::{ActionTerminalSource, JournalSessionScope, TerminalCustodyReceipt};

const MAX_CATCHUP_RECORDS_PER_PASS: usize = 16;

struct CatchupRunningGuard<'a>(&'a AtomicBool);
impl Drop for CatchupRunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// Examine at most sixteen retained records and make at most one historical read RPC per
    /// candidate. Unsupported origins are excluded durably; failures never imply unsupported.
    /// The catalog cursor includes irrelevant records, preventing starvation behind pinned rows.
    /// A missing coordinator response preserves the cursor; exact attachment is idempotent.
    pub fn reconcile_terminal_custody_catchup(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=256).contains(&limit) {
            return Err(ApiError::invalid_request(
                "terminal custody catch-up limit must be 1..=256",
            ));
        }
        if self
            .custody_catchup_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(0);
        }
        let _running = CatchupRunningGuard(&self.custody_catchup_running);
        let mut cursor = self.custody_catchup_scan.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "terminal custody catch-up unavailable",
            )
        })?;
        let limit = limit.min(if self.fleet.is_some() {
            MAX_CATCHUP_RECORDS_PER_PASS / 2
        } else {
            MAX_CATCHUP_RECORDS_PER_PASS
        });
        let page = self
            .actions
            .scan_terminal_custody_catchup(cursor.clone(), limit)
            .map_err(action_coordination_api_error)?;
        if page.examined() > limit || page.actions().len() > page.examined() {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "terminal custody catch-up exceeded its bound",
            ));
        }
        let mut attached = 0;
        for action in page.actions() {
            if self.catch_up_terminal_custody(action)? {
                attached += 1;
            }
        }
        *cursor = if page.is_complete() {
            GatewayActionRecoveryCursor::default()
        } else {
            page.next_cursor().clone()
        };
        Ok(attached)
    }

    fn catch_up_terminal_custody(&self, durable: &GatewayActionSnapshot) -> Result<bool, ApiError> {
        let original = durable.placement().directory_fence();
        if !durable.requires_terminal_custody_catchup()
            || !durable
                .terminal()
                .is_some_and(|terminal| terminal.source() == ActionTerminalSource::Worker)
        {
            return Ok(false);
        }
        let Ok(serving) = self.historical_worker(original.worker_id()) else {
            return Ok(false);
        };
        if original.worker_epoch() > serving.epoch {
            return Ok(false);
        }
        let scope = JournalSessionScope::new(
            durable.tenant_id().clone(),
            durable.session_id().clone(),
            original.worker_id().clone(),
            browserd_core::PlacementFence::new(
                original.worker_epoch(),
                original.placement_version(),
                original.session_incarnation(),
            ),
        )
        .map_err(|_| ApiError::new(ErrorCode::Internal, "invalid terminal custody scope"))?;
        let response = serving
            .client
            .request(WorkerRpcRequest::GetTerminalCustody {
                expected_serving_worker_id: serving.worker_id.clone(),
                expected_serving_worker_epoch: serving.epoch,
                scope: scope.clone(),
                action_id: durable.action_id().clone(),
                action_sequence: durable.action_sequence(),
                kind: durable.kind(),
            });
        let Ok(WorkerRpcResponse::TerminalCustody(proof)) = response else {
            return Ok(false);
        };
        if proof
            .validate_for(
                &serving.worker_id,
                serving.epoch,
                &scope,
                durable.action_id(),
                durable.action_sequence(),
                durable.kind(),
            )
            .is_err()
            || !receipt_matches_terminal(durable, &proof.receipt)
        {
            return Ok(false);
        }
        let receipt = *proof.receipt;
        let mut expected = durable.clone();
        // Matching proofs attach metadata only. A concurrent gateway-only resolution preserves the
        // original unresolved worker proof through the coordinator's saved terminal anchor.
        for _ in 0..2 {
            let new_resolution = receipt
                .resolution()
                .filter(|_| expected.resolution().is_none());
            // A real worker annotation may have committed before its original response was
            // lost. Transfer that positive fact through the existing atomic resolution path;
            // never invoke Worker ResolveAction or manufacture an annotation.
            let result = if let Some(annotation) = new_resolution {
                self.actions.resolve_unknown_with_custody(
                    expected.tenant_id(),
                    expected.session_id(),
                    expected.action_id(),
                    expected.revision(),
                    expected.placement(),
                    annotation.clone(),
                    Some(receipt.clone()),
                    Some(browserd_actions::TerminalCustodyRequirement::Required),
                    Utc::now(),
                )
            } else {
                self.actions.attach_terminal_custody(
                    expected.tenant_id(),
                    expected.session_id(),
                    expected.action_id(),
                    expected.revision(),
                    expected.placement(),
                    receipt.clone(),
                )
            };
            match result {
                Ok(current) => {
                    if !same_terminal_action(&expected, &current)
                        || Some(current.revision())
                            != expected
                                .revision()
                                .checked_add(u64::from(new_resolution.is_some()))
                        || current.resolution() != new_resolution.or(expected.resolution())
                        || current.requires_terminal_custody_catchup()
                    {
                        return Err(ApiError::new(
                            ErrorCode::Internal,
                            "terminal custody attachment contradicted its action",
                        ));
                    }
                    return Ok(true);
                }
                Err(GatewayActionCoordinationError::StaleWrite(current))
                    if same_terminal_action(durable, &current)
                        && receipt_matches_terminal(&current, &receipt) =>
                {
                    if !(current.requires_terminal_custody_catchup()
                        || receipt.resolution().is_some() && current.resolution().is_none())
                    {
                        return Ok(false);
                    }
                    expected = *current;
                }
                Err(
                    GatewayActionCoordinationError::NotFound
                    | GatewayActionCoordinationError::InvalidCustodyReceipt
                    | GatewayActionCoordinationError::CustodyAckConflict
                    | GatewayActionCoordinationError::ResolutionConflict
                    | GatewayActionCoordinationError::ResolutionNotAllowed
                    | GatewayActionCoordinationError::PendingCustodyCapacity
                    | GatewayActionCoordinationError::StaleWrite(_),
                ) => return Ok(false),
                Err(error) => return Err(action_coordination_api_error(error)),
            }
        }
        Ok(false)
    }
}

fn receipt_matches_terminal(
    action: &GatewayActionSnapshot,
    receipt: &TerminalCustodyReceipt,
) -> bool {
    receipt.action_id() == action.action_id()
        && receipt.action_sequence() == action.action_sequence()
        && receipt.kind() == action.kind()
        && action.terminal().is_some_and(|terminal| {
            terminal.source() == ActionTerminalSource::Worker
                && terminal.detail() == receipt.terminal()
        })
        && (receipt.resolution().is_none()
            || action.resolution().is_none()
            || receipt.resolution() == action.resolution())
}

fn same_terminal_action(first: &GatewayActionSnapshot, current: &GatewayActionSnapshot) -> bool {
    first.tenant_id() == current.tenant_id()
        && first.session_id() == current.session_id()
        && first.action_id() == current.action_id()
        && first.action_sequence() == current.action_sequence()
        && first.kind() == current.kind()
        && first.idempotency_key() == current.idempotency_key()
        && first.request_hash() == current.request_hash()
        && first.placement() == current.placement()
        && first.delivery() == current.delivery()
        && first.terminal() == current.terminal()
        && first.result_content() == current.result_content()
}
