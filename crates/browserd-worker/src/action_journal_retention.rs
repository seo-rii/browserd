//! Terminal custody and cleanup seals use the worker's durable WAL authority.

use super::*;

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    /// Read original terminal proof through the current authenticated serving incarnation.
    /// A missing pool or failed projection is unavailable evidence, never an unsupported origin.
    #[allow(clippy::too_many_arguments)]
    pub fn get_terminal_custody(
        &self,
        peer: &AuthenticatedPeer,
        expected_serving_worker_id: &WorkerId,
        expected_serving_worker_epoch: u64,
        scope: &JournalSessionScope,
        action_id: &ActionId,
        action_sequence: ActionSequence,
        kind: ActionKind,
    ) -> Result<TerminalCustodyReceipt, WorkerError> {
        self.authorize(peer)?;
        if expected_serving_worker_id != &self.config.worker_id
            || expected_serving_worker_epoch != self.config.worker_epoch
            || scope.validate().is_err()
            || scope.original_worker_id() != &self.config.worker_id
            || scope.fence().worker_epoch > self.config.worker_epoch
            || action_sequence.get() == 0
        {
            return Err(WorkerError::StaleFence);
        }
        let receipt = self
            .action_journal_pool
            .as_ref()
            .ok_or(WorkerError::DurabilityUnavailable)?
            .receipt(scope, action_id)
            .map_err(|_| WorkerError::DurabilityUnavailable)?
            .ok_or(WorkerError::ActionNotFound)?;
        if receipt.scope() != scope
            || receipt.action_id() != action_id
            || receipt.action_sequence() != action_sequence
            || receipt.kind() != kind
        {
            return Err(WorkerError::StaleFence);
        }
        Ok(receipt)
    }

    pub fn terminal_custody_receipt(
        &self,
        peer: &AuthenticatedPeer,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        fence: &OwnershipFence,
    ) -> Result<Option<TerminalCustodyReceipt>, WorkerError> {
        self.authorize(peer)?;
        self.validate_retained_journal_fence(fence)?;
        let Some(pool) = &self.action_journal_pool else {
            return Ok(None);
        };
        let scope = JournalSessionScope::new(
            tenant_id.clone(),
            session_id.clone(),
            fence.worker_id().clone(),
            fence.as_placement_fence(),
        )
        .map_err(|_| WorkerError::StaleFence)?;
        pool.receipt(&scope, action_id)
            .map_err(|_| WorkerError::DurabilityUnavailable)
    }

    pub fn ack_terminal_custody(
        &self,
        peer: &AuthenticatedPeer,
        expected_serving_worker_id: &WorkerId,
        expected_serving_worker_epoch: u64,
        receipt: &TerminalCustodyReceipt,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        if expected_serving_worker_id != &self.config.worker_id
            || expected_serving_worker_epoch != self.config.worker_epoch
            || receipt.original_worker_id() != &self.config.worker_id
            || receipt.fence().worker_epoch > self.config.worker_epoch
        {
            return Err(WorkerError::StaleFence);
        }
        receipt.validate().map_err(|_| WorkerError::StaleFence)?;
        self.action_journal_pool
            .as_ref()
            .ok_or(WorkerError::DurabilityUnavailable)?
            .ack_at(receipt, self.clock.now()?.get())
            .map_err(|_| WorkerError::DurabilityUnavailable)
    }

    pub fn release_terminal_custody(
        &self,
        peer: &AuthenticatedPeer,
        expected_serving_worker_id: &WorkerId,
        expected_serving_worker_epoch: u64,
        receipt: &TerminalCustodyReceipt,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        if expected_serving_worker_id != &self.config.worker_id
            || expected_serving_worker_epoch != self.config.worker_epoch
            || receipt.original_worker_id() != &self.config.worker_id
            || receipt.fence().worker_epoch > self.config.worker_epoch
        {
            return Err(WorkerError::StaleFence);
        }
        receipt.validate().map_err(|_| WorkerError::StaleFence)?;
        self.action_journal_pool
            .as_ref()
            .ok_or(WorkerError::DurabilityUnavailable)?
            .release_at(receipt, self.clock.now()?.get())
            .map_err(|_| WorkerError::DurabilityUnavailable)
    }

    fn validate_retained_journal_fence(&self, fence: &OwnershipFence) -> Result<(), WorkerError> {
        if fence.worker_id() != &self.config.worker_id
            || fence.worker_epoch() == 0
            || fence.worker_epoch() > self.config.worker_epoch
            || fence.placement_version() == 0
            || fence.session_incarnation() == 0
        {
            return Err(WorkerError::StaleFence);
        }
        Ok(())
    }

    pub(crate) fn seal_idle_action_journal(
        &self,
        executor: &SessionExecutor,
    ) -> Result<bool, WorkerError> {
        let Some(pool) = &self.action_journal_pool else {
            return Ok(true);
        };
        let Ok(_owner) = ActionOwner::claim(&executor.action_owner) else {
            return Ok(false);
        };
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        if !matches!(
            session.machine.lifecycle(),
            SessionLifecycle::Closed | SessionLifecycle::Failed
        ) || session.occupies_capacity
            || !session.pending_download_rollbacks.is_empty()
            || session.actions.values().any(|action| {
                matches!(
                    action.snapshot.status,
                    ActionStatus::PendingApproval | ActionStatus::Queued | ActionStatus::Running
                )
            })
        {
            return Ok(false);
        }
        let fence = session.machine.snapshot().owner_fence;
        let scope = JournalSessionScope::new(
            session.tenant_id.clone(),
            session.machine.session_id().clone(),
            fence.worker_id().clone(),
            fence.as_placement_fence(),
        )
        .map_err(|_| WorkerError::DurabilityUnavailable)?;
        // The serialized session and action owner prove positive cleanup and no live effect.
        // UTC starts at this observation; caller-supplied lifecycle timestamps cannot age it.
        pool.seal(&scope, self.clock.now()?.get())
            .map_err(|_| WorkerError::DurabilityUnavailable)?;
        Ok(true)
    }

    /// A bounded maintenance pass independent of readiness, heartbeat and live sessions.
    pub fn maintain_action_journals(
        &self,
        peer: &AuthenticatedPeer,
        limit: usize,
        deadline: Instant,
    ) -> Result<usize, WorkerError> {
        self.authorize(peer)?;
        if !(1..=256).contains(&limit) || Instant::now() >= deadline {
            return Err(WorkerError::InvalidConfiguration);
        }
        let Some(pool) = &self.action_journal_pool else {
            return Ok(0);
        };
        let candidates = {
            let mut cursor = self
                .journal_seal_cursor
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let worker = self.lock_worker()?;
            let mut ids = worker.sessions.keys().cloned().collect::<Vec<_>>();
            ids.sort();
            let start = cursor
                .as_ref()
                .map_or(0, |after| ids.partition_point(|id| id <= after));
            let selected = ids
                .iter()
                .cycle()
                .skip(start)
                .take(limit.min(ids.len()))
                .cloned()
                .collect::<Vec<_>>();
            *cursor = selected.last().cloned();
            selected
                .iter()
                .filter_map(|id| worker.sessions.get(id).cloned())
                .collect::<Vec<_>>()
        };
        for executor in candidates {
            if Instant::now() >= deadline {
                return Ok(0);
            }
            // A failed seal is conservative: the pool will keep that WAL charged and retained.
            let _ = self.seal_idle_action_journal(&executor);
        }
        self.reclaim_retired(self.clock.now()?);
        if Instant::now() >= deadline {
            return Ok(0);
        }
        pool.maintain(self.clock.now()?.get(), limit, deadline)
            .map_err(|_| WorkerError::DurabilityUnavailable)
    }
}
