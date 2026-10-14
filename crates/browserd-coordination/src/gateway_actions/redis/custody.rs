//! Custody discovery is separate from source-event delivery. Standalone Redis, like recovery.
use super::*;

pub(super) const CUSTODY_SCRIPT: &str = r#"
local function custody_valid()
  for _, key in ipairs({KEYS[8], KEYS[9]}) do
    local kind = redis.call('TYPE', key)['ok']
    if kind ~= 'none' and (kind ~= 'zset' or redis.call('PTTL', key) ~= -1) then return false end
  end
  return redis.call('ZCARD', KEYS[8]) <= 65536 and redis.call('ZCARD', KEYS[9]) <= 256
end
"#;

impl RedisGatewayActionStore {
    pub(super) fn custody_index_key(&self) -> String {
        format!("{}:gateway-action:custody-v1", self.config.key_prefix)
    }

    pub(super) async fn scan_custody(
        &self,
        cursor: GatewayCustodyCursor,
        limit: usize,
    ) -> Result<GatewayCustodyPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidCustodyScanLimit);
        }
        let key = self.custody_index_key();
        let format = self.recovery_format_key();
        let after = cursor.after.as_ref().map_or_else(
            || "-".to_owned(),
            |(tenant, session, action)| {
                format!("({}", Self::recovery_member(tenant, session, action))
            },
        );
        let response: Vec<String> = self.execute(move |mut connection| async move {
            Script::new(r#"
if redis.call('TYPE', KEYS[2])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('HGET', KEYS[2], 'state') ~= 'ready' or redis.call('HGET', KEYS[2], 'version') ~= '5' then return {'invalid'} end
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind ~= 'none' and (kind ~= 'zset' or redis.call('PTTL', KEYS[1]) ~= -1) then return {'invalid'} end
if redis.call('ZCARD', KEYS[1]) > 65536 then return {'invalid'} end
return redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], '+', 'LIMIT', 0, ARGV[2])
"#).key(key).key(format).arg(after).arg(limit).invoke_async(&mut connection).await
        }).await?;
        if response.len() > limit {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let complete = response.len() < limit;
        let mut next_cursor = GatewayCustodyCursor::default();
        let mut entries = Vec::with_capacity(response.len());
        for member in response {
            let (tenant, session, action) = Self::parse_recovery_member(&member)?;
            let Some(current) = self.read_action(&tenant, &session, &action).await? else {
                let index = self.custody_index_key();
                let present: Option<f64> = self
                    .execute(move |mut connection| async move {
                        redis::cmd("ZSCORE")
                            .arg(index)
                            .arg(member)
                            .query_async(&mut connection)
                            .await
                    })
                    .await?;
                if present.is_some() {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                next_cursor.after = Some((tenant, session, action));
                continue;
            };
            // A concurrently completed ACK can remove a page member before this read.
            if let Some(entry) = current.snapshot.pending_custody() {
                entries.push(entry.clone());
            }
            next_cursor.after = Some((tenant, session, action));
        }
        if complete {
            next_cursor = GatewayCustodyCursor::default();
        }
        Ok(GatewayCustodyPage {
            entries,
            next_cursor,
            complete,
        })
    }

    pub(super) async fn ack_custody(
        &self,
        entry: &GatewayPendingCustody,
        release: bool,
    ) -> Result<(), GatewayActionCoordinationError> {
        let receipt = entry.receipt();
        receipt
            .validate()
            .map_err(|_| GatewayActionCoordinationError::InvalidCustodyReceipt)?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let current = self
                .read_action(
                    receipt.tenant_id(),
                    receipt.session_id(),
                    receipt.action_id(),
                )
                .await?
                .ok_or(GatewayActionCoordinationError::NotFound)?;
            let mut candidate = current.snapshot.clone();
            let changed = if release {
                candidate.complete_custody_release(entry)?
            } else {
                candidate.copy_custody_ack(entry)?
            };
            if !changed {
                return Ok(());
            }
            let placement = candidate.placement.clone();
            match self
                .cas_action(
                    receipt.tenant_id(),
                    receipt.session_id(),
                    receipt.action_id(),
                    &placement,
                    current.raw,
                    true,
                    candidate,
                    SessionMutation::Custody,
                    current.session_lost,
                    false,
                    None,
                )
                .await?
            {
                CasMutation::Applied(_) => return Ok(()),
                CasMutation::Changed => {}
            }
        }
        Err(GatewayActionCoordinationError::CustodyAckConflict)
    }
}

impl RedisGatewayActionStore {
    pub(super) async fn scan_custody_catchup(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidCustodyScanLimit);
        }
        timeout(
            self.config.command_timeout,
            self.scan_custody_catchup_inner(cursor, limit),
        )
        .await
        .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
    }

    async fn scan_custody_catchup_inner(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError> {
        let index = self.retained_index_key();
        let format = self.recovery_format_key();
        let after = cursor.after.as_ref().map_or_else(
            || "-".to_owned(),
            |(tenant, session, action)| {
                format!("({}", Self::recovery_member(tenant, session, action))
            },
        );
        let members: Vec<String> = self.execute(move |mut connection| async move {
            Script::new(r#"
if redis.call('TYPE', KEYS[2])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('HGET', KEYS[2], 'version') ~= '5' or redis.call('HGET', KEYS[2], 'state') ~= 'ready' then return {'invalid'} end
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind ~= 'none' and (kind ~= 'zset' or redis.call('PTTL', KEYS[1]) ~= -1) then return {'invalid'} end
local cap = tonumber(redis.call('HGET', KEYS[2], 'retained_global'))
if not cap or cap < 1 or cap > 1048576 or redis.call('ZCARD', KEYS[1]) > cap then return {'invalid'} end
return redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], '+', 'LIMIT', 0, ARGV[2])
"#).key(index).key(format).arg(after).arg(limit).invoke_async(&mut connection).await
        }).await?;
        if members.len() > limit {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let examined = members.len();
        let complete = examined < limit;
        let mut actions = Vec::new();
        let mut next_cursor = GatewayActionRecoveryCursor::default();
        for member in members {
            let (tenant, session, action) = Self::parse_recovery_member(&member)?;
            next_cursor.after = Some((tenant.clone(), session.clone(), action.clone()));
            let Some(row) = self.read_action(&tenant, &session, &action).await? else {
                // A legitimately expired Unsupported/non-worker row can disappear after this
                // inventory page. Never skip a surviving catalog entry with missing payload.
                let index = self.retained_index_key();
                let present: Option<f64> = self
                    .execute(move |mut connection| async move {
                        redis::cmd("ZSCORE")
                            .arg(index)
                            .arg(member)
                            .query_async(&mut connection)
                            .await
                    })
                    .await?;
                if present.is_some() {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                continue;
            };
            if row.snapshot.requires_terminal_custody_catchup() {
                actions.push(row.snapshot);
            }
        }
        Ok(GatewayTerminalCustodyCatchupPage {
            actions,
            next_cursor: if complete {
                GatewayActionRecoveryCursor::default()
            } else {
                next_cursor
            },
            complete,
            examined,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn attach_custody_catchup(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        receipt: TerminalCustodyReceipt,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let current = self
                .read_action(tenant_id, session_id, action_id)
                .await?
                .ok_or(GatewayActionCoordinationError::NotFound)?;
            if current.snapshot.placement() != placement {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            if current.snapshot.revision() != expected_revision {
                return Err(GatewayActionCoordinationError::StaleWrite(Box::new(
                    current.snapshot,
                )));
            }
            let mut candidate = current.snapshot.clone();
            let requirement_changed = candidate.merge_custody_requirement(
                Some(TerminalCustodyRequirement::Required),
                Some(&receipt),
                false,
            )?;
            let custody_changed = candidate.attach_terminal_custody_receipt(&receipt)?;
            if !requirement_changed && !custody_changed {
                return Ok(current.snapshot);
            }
            match self
                .cas_action(
                    tenant_id,
                    session_id,
                    action_id,
                    placement,
                    current.raw,
                    current.snapshot.pending_custody().is_some(),
                    candidate,
                    SessionMutation::Custody,
                    true,
                    false,
                    None,
                )
                .await?
            {
                CasMutation::Applied(snapshot) => return Ok(*snapshot),
                CasMutation::Changed => {}
            }
        }
        Err(GatewayActionCoordinationError::CustodyAckConflict)
    }
}
