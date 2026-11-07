//! Durable worker-retention acknowledgments, independent of browser dispatch and event delivery.
use super::*;
use browserd_actions::TerminalCustodyReceipt;
use browserd_coordination::{GatewayCustodyCursor, GatewayPendingCustody};

const MAX_CUSTODY_ACKS_PER_PASS: usize = 16;

struct CustodyRunningGuard<'a>(&'a AtomicBool);
impl Drop for CustodyRunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// Check optional WAL authority only after the public action receipt has authenticated.
    /// The worker's internal request/dispatch identities deliberately differ from the Gateway's.
    pub(super) fn validated_terminal_custody(
        &self,
        durable: &GatewayActionSnapshot,
        receipt: &WorkerActionReceipt,
    ) -> Result<Option<TerminalCustodyReceipt>, ApiError> {
        let Some(custody) = receipt.custody.as_deref() else {
            return Ok(None);
        };
        let placement = durable.placement().directory_fence();
        let fence = custody.fence();
        if receipt.to_action_snapshot().is_err()
            || receipt.fence.tenant_id != *durable.tenant_id()
            || receipt.fence.session_id != *durable.session_id()
            || receipt.fence.worker_epoch != placement.worker_epoch()
            || receipt.fence.placement_version != placement.placement_version()
            || receipt.fence.session_incarnation != placement.session_incarnation()
            || receipt.action_id != *durable.action_id()
            || receipt.action_sequence != durable.action_sequence()
            || receipt.idempotency_key != durable.idempotency_key()
            || receipt.canonical_request_hash != *durable.request_hash().as_bytes()
            || receipt.kind != durable.kind()
            || custody.validate().is_err()
            || custody.original_worker_id() != placement.worker_id()
            || custody.tenant_id() != durable.tenant_id()
            || custody.session_id() != durable.session_id()
            || custody.action_id() != durable.action_id()
            || custody.action_sequence() != durable.action_sequence()
            || custody.kind() != durable.kind()
            || fence.worker_epoch != receipt.fence.worker_epoch
            || fence.placement_version != receipt.fence.placement_version
            || fence.session_incarnation != receipt.fence.session_incarnation
            || Some(custody.terminal()) != receipt.terminal_detail
            || custody.resolution() != receipt.resolution.as_ref()
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned mismatched terminal custody",
            ));
        }
        Ok(Some(custody.clone()))
    }

    /// Scan a hard-bounded page and transfer custody only after coordination committed the
    /// terminal result, source event, and obligation. Ready state and live sessions are irrelevant.
    /// Copy ACK becomes a durable Release obligation. Only that second phase authorizes worker
    /// cleanup; a positive release response then removes the exact coordinator obligation.
    /// Each RPC uses the configured client timeout; at most sixteen RPCs run in one pass.
    pub fn reconcile_terminal_custody(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=256).contains(&limit) {
            return Err(ApiError::invalid_request(
                "terminal custody limit must be 1..=256",
            ));
        }
        if self
            .custody_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(0);
        }
        let _running = CustodyRunningGuard(&self.custody_running);
        let mut cursor = self.custody_scan.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "terminal custody scan unavailable",
            )
        })?;
        let limit = limit.min(if self.fleet.is_some() {
            MAX_CUSTODY_ACKS_PER_PASS / 2
        } else {
            MAX_CUSTODY_ACKS_PER_PASS
        });
        let page = self
            .actions
            .scan_pending_custody(cursor.clone(), limit)
            .map_err(action_coordination_api_error)?;
        if page.entries().len() > limit {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "terminal custody scan exceeded its bound",
            ));
        }
        let mut acknowledged = 0;
        for entry in page.entries() {
            if self.ack_worker_custody(entry)? {
                acknowledged += 1;
            }
        }
        *cursor = if page.is_complete() {
            GatewayCustodyCursor::default()
        } else {
            page.next_cursor().clone()
        };
        Ok(acknowledged)
    }

    fn ack_worker_custody(&self, entry: &GatewayPendingCustody) -> Result<bool, ApiError> {
        let receipt = entry.receipt();
        if receipt.validate().is_err() {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "invalid durable terminal custody",
            ));
        }
        let Ok(serving) = self.historical_worker(receipt.original_worker_id()) else {
            return Ok(false);
        };
        // The serving process may be a newer epoch; the immutable original fence is never changed.
        let request = if entry.is_release() {
            WorkerRpcRequest::ReleaseTerminalCustody {
                expected_serving_worker_id: serving.worker_id.clone(),
                expected_serving_worker_epoch: serving.epoch,
                receipt: Box::new(receipt.clone()),
            }
        } else {
            WorkerRpcRequest::AckTerminalCustody {
                expected_serving_worker_id: serving.worker_id.clone(),
                expected_serving_worker_epoch: serving.epoch,
                receipt: Box::new(receipt.clone()),
            }
        };
        let ack = match (entry.is_release(), serving.client.request(request)) {
            (false, Ok(WorkerRpcResponse::TerminalCustodyAck(ack)))
            | (true, Ok(WorkerRpcResponse::TerminalCustodyRelease(ack))) => ack,
            _ => return Ok(false),
        };
        if ack.worker_id != serving.worker_id
            || ack.worker_epoch != serving.epoch
            || ack.receipt_sha256 != receipt.digest()
        {
            return Ok(false);
        }
        let persisted = if entry.is_release() {
            self.actions.complete_custody_release(entry, Utc::now())
        } else {
            self.actions.ack_pending_custody(entry, Utc::now())
        };
        match persisted {
            Ok(()) => Ok(true),
            // A later operator resolution replaced this exact obligation while the RPC ran.
            Err(GatewayActionCoordinationError::CustodyAckConflict) => Ok(false),
            Err(error) => Err(action_coordination_api_error(error)),
        }
    }
}
