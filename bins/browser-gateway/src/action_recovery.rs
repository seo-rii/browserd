//! Recover accepted actions without recreating sessions or replaying worker submissions.

use std::sync::atomic::{AtomicBool, Ordering};

use browserd_actions::{ActionDeliveryEvidence, ActionSnapshot, BrowserResult, TerminalDetail};
use browserd_api::ApiError;
use browserd_coordination::{GatewayActionCoordinationError, GatewayActionSnapshot};
use browserd_core::ErrorCode;
use browserd_worker::{
    WorkerActionReceipt, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
    WorkerSessionLifecycle,
};
use chrono::Utc;

use super::{
    GatewayWorkerClient, GatewayWorkerRuntime, action_coordination_api_error,
    coordinated_action_snapshot,
};

// InspectSession plus at most one GetAction for seven candidates is at most fourteen RPCs.
// Processing the complete page before advancing its opaque cursor preserves every candidate.
const MAX_ACTIONS_PER_PASS: usize = 7;

struct RecoveryRunningGuard<'a>(&'a AtomicBool);

impl Drop for RecoveryRunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Minimal, private routing authority. It does not admit mutations or manufacture a Ready session.
struct RecoveredActionRoute {
    fence: WorkerSessionFence,
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// Recover at most seven accepted actions per pass, with at most fourteen read-only worker
    /// RPCs. `limit` must be 1..=256 and is clamped to seven so the entire scanned page is visited
    /// before advancing its opaque cursor. Existing coordination/RPC timeouts bound each call.
    /// Concurrent passes on this runtime return zero; independent gateways may safely query and
    /// race the same positive receipt through the durable revision/placement/dispatch CAS.
    pub fn reconcile_pending_actions(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=256).contains(&limit) {
            return Err(ApiError::invalid_request(
                "action recovery limit must be 1..=256",
            ));
        }
        if self
            .recovery_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(0);
        }
        let _running = RecoveryRunningGuard(&self.recovery_running);
        let mut cursor = self.recovery_scan.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "action recovery state unavailable",
            )
        })?;
        let page = self
            .actions
            .scan_pending_actions(cursor.clone(), limit.min(MAX_ACTIONS_PER_PASS))
            .map_err(action_coordination_api_error)?;
        if page.actions().len() > limit.min(MAX_ACTIONS_PER_PASS) {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "action recovery page exceeds its bound",
            ));
        }
        let mut completed = 0;
        for durable in page.actions() {
            if durable.terminal().is_some() {
                continue;
            }
            if let Some(action) = self.recover_action_receipt(durable)?
                && action.state().is_terminal()
            {
                completed += 1;
                continue;
            }
            if matches!(durable.delivery(), ActionDeliveryEvidence::NotAttempted) {
                // Legacy claims have no immutable submission authority and must never be
                // expired based on age alone. Redis also checks its authoritative TIME while
                // atomically proving that this exact leased claim is still NotAttempted.
                let Some(lease) = durable.submission_lease() else {
                    continue;
                };
                let now = Utc::now();
                if now < lease.expires_at() {
                    continue;
                }
                let effective = match self.actions.expire_unattempted_action(
                    durable.tenant_id(),
                    durable.session_id(),
                    durable.action_id(),
                    durable.revision(),
                    durable.placement(),
                    lease,
                    now,
                ) {
                    Ok(effective) => effective,
                    Err(GatewayActionCoordinationError::StaleWrite(current)) => *current,
                    Err(GatewayActionCoordinationError::SubmissionLeaseNotExpired) => continue,
                    Err(error) => return Err(action_coordination_api_error(error)),
                };
                if effective.terminal().is_some() {
                    self.note_terminal_transition(&effective);
                    completed += 1;
                }
            }
        }
        *cursor = page.next_cursor().clone();
        Ok(completed)
    }

    /// Query an existing durable action without restoring a memory session. Only an exact
    /// terminal ownership proof can derive loss; unavailable or mismatched inspection leaves
    /// the existing action unchanged. Readiness is not required for terminal observations.
    pub(super) fn recover_action_receipt(
        &self,
        durable: &GatewayActionSnapshot,
    ) -> Result<Option<ActionSnapshot>, ApiError> {
        if durable.terminal().is_some() {
            return Ok(None);
        }
        let Some(route) = self.recovered_action_route(durable) else {
            return Ok(None);
        };
        let Some(proof) = self.inspect_owned_session(durable.placement(), &route.fence) else {
            return Ok(None);
        };
        // An available immutable terminal receipt takes precedence over deriving loss from
        // Closed/Failed. Never query an action that this gateway has not armed for dispatch.
        let recovered = if matches!(durable.delivery(), ActionDeliveryEvidence::NotAttempted) {
            None
        } else if let Ok(WorkerRpcResponse::Action(receipt)) = self
            .client_for_placement(durable.placement())?
            .request(WorkerRpcRequest::GetAction {
                fence: route.fence.clone(),
                action_id: durable.action_id().clone(),
            })
        {
            Some(self.persist_recovered_receipt(durable, &route, receipt)?)
        } else {
            None
        };
        if matches!(
            proof.session.lifecycle,
            WorkerSessionLifecycle::Closed | WorkerSessionLifecycle::Failed
        ) {
            self.record_terminal_session_proof(durable.placement(), &proof)?;
            let effective = self
                .actions
                .get_effective_action(
                    durable.tenant_id(),
                    durable.session_id(),
                    durable.action_id(),
                )
                .map_err(action_coordination_api_error)?
                .filter(|current| current.placement() == durable.placement())
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "lost-session action no longer matches its placement",
                    )
                })?;
            return coordinated_action_snapshot(&effective).map(Some);
        }
        Ok(recovered)
    }

    fn recovered_action_route(
        &self,
        durable: &GatewayActionSnapshot,
    ) -> Option<RecoveredActionRoute> {
        let placement = durable.placement();
        let directory = placement.directory_fence();
        if (self.fleet.is_none()
            && (directory.worker_id() != &self.placement.worker_id
                || directory.worker_epoch() != self.placement.worker_epoch
                || directory.placement_version() != self.placement.placement_version
                || placement.directory_revision() != self.placement.directory_revision))
            || self.client_for_placement(placement).is_err()
            || directory.session_incarnation() == 0
        {
            return None;
        }
        Some(RecoveredActionRoute {
            fence: WorkerSessionFence {
                tenant_id: durable.tenant_id().clone(),
                session_id: durable.session_id().clone(),
                worker_epoch: directory.worker_epoch(),
                placement_version: directory.placement_version(),
                session_incarnation: directory.session_incarnation(),
            },
        })
    }

    fn persist_recovered_receipt(
        &self,
        durable: &GatewayActionSnapshot,
        route: &RecoveredActionRoute,
        receipt: WorkerActionReceipt,
    ) -> Result<ActionSnapshot, ApiError> {
        if receipt.fence != route.fence
            || receipt.action_id != *durable.action_id()
            || receipt.action_sequence != durable.action_sequence()
            || receipt.idempotency_key != durable.idempotency_key()
            || receipt.canonical_request_hash != *durable.request_hash().as_bytes()
            || receipt.kind != durable.kind()
        {
            return coordinated_action_snapshot(durable);
        }
        let custody = match self.validated_terminal_custody(durable, &receipt) {
            Ok(custody) => custody,
            Err(_) => return coordinated_action_snapshot(durable),
        };
        let custody_requirement = receipt.custody_requirement;
        let detail = receipt.terminal_detail;
        let Ok(worker) = receipt.to_action_snapshot() else {
            return coordinated_action_snapshot(durable);
        };
        let Some(detail) = detail else {
            return Ok(worker);
        };
        self.persist_worker_action_snapshot(durable, &worker, detail, custody, custody_requirement)
    }

    /// Persist an already validated positive worker terminal receipt. Callers must first
    /// authenticate the exact worker and full session/placement fence: ActionSnapshot carries
    /// action facts, not routing authority. Both live completion and recovery use this bounded
    /// CAS retry so a committed exposure write with a lost reply cannot discard the result.
    pub(super) fn persist_worker_action_snapshot(
        &self,
        durable: &GatewayActionSnapshot,
        worker: &ActionSnapshot,
        detail: TerminalDetail,
        custody: Option<browserd_actions::TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
    ) -> Result<ActionSnapshot, ApiError> {
        if worker.action_id() != durable.action_id()
            || worker.action_sequence() != durable.action_sequence()
            || worker.request().idempotency_key().as_str() != durable.idempotency_key()
            || worker.request().canonical_request_hash() != durable.request_hash()
            || worker.request().kind() != durable.kind()
            || worker.terminal_detail() != Some(detail)
        {
            return coordinated_action_snapshot(durable);
        }
        let dispatch = match durable.delivery() {
            ActionDeliveryEvidence::DispatchArmed(dispatch)
            | ActionDeliveryEvidence::ExposurePossible(dispatch) => dispatch,
            ActionDeliveryEvidence::NotAttempted => return coordinated_action_snapshot(durable),
        };
        let mut expected = durable.clone();
        // A concurrent exposure mark can change only the revision while the positive worker
        // proof remains exact. A concurrent identical Unknown may also precede the resolved
        // worker receipt: retry its atomic resolution/custody commit once. The core still rejects
        // a different terminal source or resolution winner. Never replay the browser action.
        for _ in 0..2 {
            let recorded = match detail {
                TerminalDetail::Succeeded(digest) => {
                    self.actions.record_worker_result_with_custody(
                        expected.tenant_id(),
                        expected.session_id(),
                        expected.action_id(),
                        expected.revision(),
                        expected.placement(),
                        dispatch,
                        expected.action_sequence(),
                        BrowserResult::Succeeded(digest),
                        worker.result_content().map(<[u8]>::to_vec),
                        custody.clone(),
                        custody_requirement,
                        Utc::now(),
                    )
                }
                _ => self.actions.record_worker_terminal_with_custody(
                    expected.tenant_id(),
                    expected.session_id(),
                    expected.action_id(),
                    expected.revision(),
                    expected.placement(),
                    dispatch,
                    expected.action_sequence(),
                    detail,
                    custody.clone(),
                    custody_requirement,
                    Utc::now(),
                ),
            };
            let effective = match recorded {
                Ok(effective) => effective,
                Err(GatewayActionCoordinationError::StaleWrite(current))
                    if same_recovery_action(durable, &current)
                        && (current.terminal().is_none()
                            || (matches!(detail, TerminalDetail::OutcomeUnknown(_))
                                && current.terminal().is_some_and(|terminal| {
                                    terminal.detail() == detail
                                        && terminal.source()
                                            == browserd_actions::ActionTerminalSource::Worker
                                })
                                && worker.resolution().is_some()
                                && (current.resolution().is_none()
                                    || current.resolution() == worker.resolution()))) =>
                {
                    expected = *current;
                    continue;
                }
                Err(error) => self.effective_action_after_race(
                    durable.tenant_id(),
                    durable.session_id(),
                    durable.action_id(),
                    error,
                )?,
            };
            self.note_terminal_transition(&effective);
            return coordinated_action_snapshot(&effective);
        }
        coordinated_action_snapshot(&expected)
    }
}

fn same_recovery_action(first: &GatewayActionSnapshot, current: &GatewayActionSnapshot) -> bool {
    first.tenant_id() == current.tenant_id()
        && first.session_id() == current.session_id()
        && first.action_id() == current.action_id()
        && first.action_sequence() == current.action_sequence()
        && first.idempotency_key() == current.idempotency_key()
        && first.request_hash() == current.request_hash()
        && first.kind() == current.kind()
        && first.placement() == current.placement()
        && match (first.delivery(), current.delivery()) {
            (
                ActionDeliveryEvidence::DispatchArmed(first)
                | ActionDeliveryEvidence::ExposurePossible(first),
                ActionDeliveryEvidence::DispatchArmed(current)
                | ActionDeliveryEvidence::ExposurePossible(current),
            ) => first == current,
            _ => false,
        }
}
