//! Bounded retention of durable terminal action records, independent of browser liveness.
use super::*;
use browserd_coordination::{GatewayActionRetentionCursor, GatewayActionRetentionLimits};

/// Shared startup/migration limits. Invalid values are never included in returned errors.
pub fn action_retention_limits_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<GatewayActionRetentionLimits, GatewayConfigurationError> {
    const NAMESPACE: &str = "BROWSERD_ACTION_MAX_RETAINED_RECORDS";
    const SESSION: &str = "BROWSERD_ACTION_MAX_RETAINED_RECORDS_PER_SESSION";
    let defaults = GatewayActionRetentionLimits::default();
    let mut number =
        |name: &'static str, default: usize| -> Result<usize, GatewayConfigurationError> {
            let Some(value) = lookup(name) else {
                return Ok(default);
            };
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(GatewayConfigurationError::InvalidActionRetention(name));
            }
            value
                .parse()
                .map_err(|_| GatewayConfigurationError::InvalidActionRetention(name))
        };
    let namespace = number(NAMESPACE, defaults.namespace_records())?;
    let session = number(SESSION, defaults.session_records())?;
    // Attribute the namespace's own bound first; the second validation also checks the pair.
    GatewayActionRetentionLimits::new(namespace, 1)
        .map_err(|_| GatewayConfigurationError::InvalidActionRetention(NAMESPACE))?;
    GatewayActionRetentionLimits::new(namespace, session)
        .map_err(|_| GatewayConfigurationError::InvalidActionRetention(SESSION))
}

const MAX_RETENTION_RECORDS_PER_PASS: usize = 32;

struct RetentionRunningGuard<'a>(&'a AtomicBool);
impl Drop for RetentionRunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// Reclaim at most thirty-two records through the action coordinator's trusted clock.
    /// This path never contacts a worker or requires a live session or outbox delivery.
    /// Deferred records still advance the cursor so one pinned record cannot starve others.
    /// Missing responses preserve the cursor: durable removal is safe to rediscover/retry.
    pub fn maintain_action_retention(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=256).contains(&limit) {
            return Err(ApiError::invalid_request(
                "action retention limit must be 1..=256",
            ));
        }
        if self
            .retention_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(0);
        }
        let _running = RetentionRunningGuard(&self.retention_running);
        let mut cursor = self.retention_scan.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "action retention state unavailable",
            )
        })?;
        let limit = limit.min(MAX_RETENTION_RECORDS_PER_PASS);
        let page = self
            .actions
            .maintain_action_retention(cursor.clone(), limit)
            .map_err(action_coordination_api_error)?;
        if page.examined() > limit
            || page.reclaimed().checked_add(page.deferred()) != Some(page.examined())
        {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "action retention page exceeds its bound",
            ));
        }
        *cursor = if page.is_complete() {
            GatewayActionRetentionCursor::default()
        } else {
            page.next_cursor().clone()
        };
        Ok(page.reclaimed())
    }
}
