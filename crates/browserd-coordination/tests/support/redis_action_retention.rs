use super::redis_action_custody::cases as custody_cases;
use super::*;
use browserd_coordination::{
    GatewayActionRetentionCursor, GatewayActionRetentionLimits, GatewayActionSnapshot,
    GatewayCustodyCursor,
};

async fn connection(f: &RedisFixture) -> redis::aio::MultiplexedConnection {
    redis::Client::open(f.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("connection")
}
fn scope(f: &RedisFixture, tenant: &TenantId, session: &SessionId) -> String {
    format!("{}:gateway-action:{{{tenant}:{session}}}", f.prefix)
}
async fn cancelled(
    f: &RedisFixture,
    tenant: &TenantId,
    session: &SessionId,
    key: &str,
) -> GatewayActionSnapshot {
    let claim = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                key,
                1,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(1),
        )
        .await
        .expect("claim")
        .into_snapshot();
    f.store
        .cancel_before_dispatch(
            tenant,
            session,
            claim.action_id(),
            claim.revision(),
            claim.placement(),
            at(2),
        )
        .await
        .expect("cancel")
}
async fn drain_events(store: &RedisGatewayActionStore, tenant: &TenantId, session: &SessionId) {
    for _ in 0..300 {
        let Some(event) = store
            .peek_event_projection(tenant, session)
            .await
            .expect("peek")
        else {
            return;
        };
        store.ack_event_projection(&event).await.expect("ack");
    }
    panic!("fixture has bounded events");
}
// No caller UTC can expire production data. This fixture moves the durable deadline while
// preserving the exact source watermark/index, modeling a Redis restart after the horizon.
pub(super) async fn set_deadline(f: &RedisFixture, row: &GatewayActionSnapshot, deadline: u64) {
    let namespace = scope(f, row.tenant_id(), row.session_id());
    let member = format!(
        "{}|{}|{}",
        row.tenant_id(),
        row.session_id(),
        row.action_id()
    );
    redis::Script::new(
        r#"
local old = redis.call('HGET', KEYS[1], ARGV[1])
local old_deadline, sequence = string.match(old, '^([0-9]+)|([0-9]+)$')
redis.call('ZREM', KEYS[2], string.rep('0', 20-#old_deadline) .. old_deadline .. '|' .. ARGV[2])
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3] .. '|' .. sequence)
redis.call('ZADD', KEYS[2], 0, string.rep('0', 20-#ARGV[3]) .. ARGV[3] .. '|' .. ARGV[2])
"#,
    )
    .key(format!("{namespace}:retention-v1"))
    .key(format!("{}:gateway-action:retention-v3", f.prefix))
    .arg(row.action_id().to_string())
    .arg(member)
    .arg(deadline)
    .invoke_async::<()>(&mut connection(f).await)
    .await
    .expect("fixture deadline");
}
async fn sweep(
    f: &RedisFixture,
    limit: usize,
) -> browserd_coordination::GatewayActionRetentionPage {
    f.store
        .maintain_action_retention(GatewayActionRetentionCursor::default(), limit)
        .await
        .expect("bounded maintenance")
}
async fn bounded_fixture(label: &str, global: usize, session: usize) -> Option<RedisFixture> {
    let endpoint = std::env::var("BROWSERD_REDIS_TEST_URL").ok()?;
    let prefix = format!("browserd-retention-{label}-{}", Uuid::new_v4());
    let config = RedisGatewayActionConfig::new(
        endpoint.clone(),
        prefix.clone(),
        StoreConfig::default(),
        32,
        Duration::from_secs(3),
    )
    .expect("config")
    .with_retention_limits(GatewayActionRetentionLimits::new(global, session).expect("limits"));
    let store = Arc::new(
        RedisGatewayActionStore::connect(config.clone())
            .await
            .expect("connect"),
    );
    Some(RedisFixture {
        config,
        store,
        endpoint,
        prefix,
    })
}

#[tokio::test]
async fn redis_retention_uses_server_time_and_fixed_horizon_then_exactly_reclaims_idempotency() {
    let Some(f) = redis_fixture("retention-fixed").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let first = cancelled(&f, &tenant, &session, "old").await;
    assert!(
        first.retain_until() >= Utc::now() + chrono::Duration::hours(23),
        "historical caller timestamps cannot expire a newly committed terminal"
    );
    let second = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "new",
                2,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(3),
        )
        .await
        .expect("later claim")
        .into_snapshot();
    let replay = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "old",
                1,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(4),
        )
        .await
        .expect("old key replay")
        .into_snapshot();
    assert_eq!(replay.retain_until(), first.retain_until());
    assert_eq!(
        replay.last_source_event_sequence(),
        first.last_source_event_sequence()
    );
    set_deadline(&f, &first, 1).await;
    assert_eq!(
        sweep(&f, 1).await.deferred(),
        1,
        "source projection custody must transfer first"
    );
    drain_events(&f.store, &tenant, &session).await;
    let page = sweep(&f, 1).await;
    assert_eq!(page.reclaimed(), 1);
    assert!(
        f.store
            .get_effective_action(&tenant, &session, first.action_id())
            .await
            .expect("get old")
            .is_none()
    );
    assert_eq!(
        f.store
            .get_effective_action(&tenant, &session, second.action_id())
            .await
            .expect("get pending")
            .expect("pending")
            .terminal(),
        None
    );
    let replay = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "old",
                1,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(5),
        )
        .await
        .expect("expired idempotency accepts new identity");
    assert_eq!(
        replay.snapshot().action_sequence().get(),
        3,
        "session highwater survives per-action reclamation"
    );
    let restarted = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart");
    assert!(
        restarted
            .get_effective_action(&tenant, &session, first.action_id())
            .await
            .expect("read after restart")
            .is_none()
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_fair_cursor_skips_pinned_head_and_wraps_with_hard_page_bounds() {
    let Some(f) = redis_fixture("retention-fair").await else {
        return;
    };
    let tenant = TenantId::new();
    let session1 = SessionId::new();
    let session2 = SessionId::new();
    let pinned = cancelled(&f, &tenant, &session1, "pinned").await;
    let ready = cancelled(&f, &tenant, &session2, "ready").await;
    set_deadline(&f, &pinned, 1).await;
    set_deadline(&f, &ready, 2).await;
    drain_events(&f.store, &tenant, &session2).await;
    let first = sweep(&f, 1).await;
    assert_eq!(
        (first.examined(), first.deferred(), first.reclaimed()),
        (1, 1, 0)
    );
    let second = f
        .store
        .maintain_action_retention(first.next_cursor().clone(), 1)
        .await
        .expect("advance past pin");
    assert_eq!(second.reclaimed(), 1);
    let tail = f
        .store
        .maintain_action_retention(second.next_cursor().clone(), 1)
        .await
        .expect("tail");
    assert!(tail.is_complete());
    assert_eq!(
        sweep(&f, 1).await.deferred(),
        1,
        "wrap revisits remaining obligation"
    );
    for limit in [0, 257] {
        assert!(matches!(
            f.store
                .maintain_action_retention(GatewayActionRetentionCursor::default(), limit)
                .await,
            Err(GatewayActionCoordinationError::InvalidRetentionScanLimit)
        ));
    }
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_custody_copy_and_release_both_pin_even_after_projection_ack() {
    let Some(f) = redis_fixture("retention-custody").await else {
        return;
    };
    let action = custody_cases::Action::new(f.store.as_ref()).await;
    let receipt = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    let terminal = action
        .terminal(f.store.as_ref(), receipt, action.armed.revision())
        .await
        .expect("terminal");
    set_deadline(&f, &terminal, 1).await;
    action.events(f.store.as_ref()).await;
    let copy = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("copy")
        .entries()[0]
        .clone();
    assert_eq!(sweep(&f, 1).await.deferred(), 1);
    f.store
        .ack_pending_custody(&copy, Utc::now())
        .await
        .expect("copy ack");
    let release = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("release")
        .entries()[0]
        .clone();
    assert!(release.is_release());
    assert_eq!(sweep(&f, 1).await.deferred(), 1);
    f.store
        .complete_custody_release(&release, Utc::now())
        .await
        .expect("release confirmed");
    assert_eq!(
        sweep(&f, 1).await.reclaimed(),
        1,
        "custody ACKs must not reset the old horizon"
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_resolution_keeps_monotonic_horizon_and_exact_event_watermark() {
    let Some(f) = redis_fixture("retention-resolution").await else {
        return;
    };
    let action = custody_cases::Action::new(f.store.as_ref()).await;
    let receipt = action.receipt(
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch),
        None,
    );
    let unknown = action
        .terminal(f.store.as_ref(), receipt, action.armed.revision())
        .await
        .expect("unknown");
    let future =
        u64::try_from((Utc::now() + chrono::Duration::days(4)).timestamp_millis()).expect("future");
    set_deadline(&f, &unknown, future).await;
    let resolved = f
        .store
        .resolve_unknown(
            &action.tenant,
            &action.session,
            &action.action,
            unknown.revision(),
            &action.placement,
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                42,
                "verified",
            ),
            Utc::now(),
        )
        .await
        .expect("resolution");
    assert_eq!(
        resolved.retain_until().timestamp_millis(),
        i64::try_from(future).expect("time")
    );
    assert_eq!(
        resolved.last_source_event_sequence(),
        unknown.last_source_event_sequence().map(|v| v + 1)
    );
    let same = f
        .store
        .resolve_unknown(
            &action.tenant,
            &action.session,
            &action.action,
            resolved.revision(),
            &action.placement,
            resolved.resolution().expect("resolution").clone(),
            Utc::now(),
        )
        .await
        .expect("resolution replay");
    assert_eq!(same.retain_until(), resolved.retain_until());
    assert_eq!(
        same.last_source_event_sequence(),
        resolved.last_source_event_sequence()
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_admission_counts_terminal_payloads_across_sessions_before_any_write() {
    let Some(f) = bounded_fixture("capacity", 2, 1).await else {
        return;
    };
    let tenant = TenantId::new();
    let first_session = SessionId::new();
    let second_session = SessionId::new();
    let first = cancelled(&f, &tenant, &first_session, "first").await;
    let rejected = claim_with_kind(
        tenant.clone(),
        first_session.clone(),
        ActionId::new(),
        "second",
        2,
        ActionKind::ReadOnly,
        placement(1, 1),
    );
    assert!(matches!(
        f.store.claim_action(rejected, at(3)).await,
        Err(GatewayActionCoordinationError::RetainedActionCapacity)
    ));
    let _second = cancelled(&f, &tenant, &second_session, "second").await;
    let third_session = SessionId::new();
    let third = claim_with_kind(
        tenant.clone(),
        third_session.clone(),
        ActionId::new(),
        "third",
        3,
        ActionKind::ReadOnly,
        placement(1, 1),
    );
    assert!(matches!(
        f.store.claim_action(third.clone(), at(3)).await,
        Err(GatewayActionCoordinationError::RetainedActionCapacity)
    ));
    assert!(
        f.store
            .get_effective_action(&tenant, &third_session, third.proposed_action_id())
            .await
            .expect("no partial admission")
            .is_none()
    );
    set_deadline(&f, &first, 1).await;
    drain_events(&f.store, &tenant, &first_session).await;
    assert_eq!(sweep(&f, 1).await.reclaimed(), 1);
    assert_eq!(
        f.store
            .claim_action(third, at(4))
            .await
            .expect("released capacity")
            .snapshot()
            .action_sequence()
            .get(),
        1
    );
    delete_fixture(&f).await;
}

async fn mark_v2_ready(f: &RedisFixture) {
    super::redis_action_recovery::strip_v3_retention(f).await;
    redis::cmd("HSET")
        .arg(format!("{}:gateway-action:recovery-format", f.prefix))
        .arg("version")
        .arg("2")
        .arg("state")
        .arg("ready")
        .query_async::<()>(&mut connection(f).await)
        .await
        .expect("v2 ready fixture");
}
async fn migrate(
    config: &RedisGatewayActionConfig,
) -> browserd_coordination::RedisGatewayActionMigrationProgress {
    for _ in 0..4096 {
        let progress =
            RedisGatewayActionStore::migrate_recovery_format(config.clone(), true, Utc::now())
                .await
                .expect("bounded migration step");
        if progress.complete() {
            return progress;
        }
    }
    panic!("bounded fixture migration");
}

#[tokio::test]
async fn redis_retention_v2_upgrade_preserves_custody_release_and_pre_source_terminal_readability()
{
    let Some(f) = redis_fixture("retention-v2-upgrade").await else {
        return;
    };
    let action = custody_cases::Action::new(f.store.as_ref()).await;
    let receipt = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    action
        .terminal(f.store.as_ref(), receipt, action.armed.revision())
        .await
        .expect("terminal");
    let copy = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("copy")
        .entries()[0]
        .clone();
    f.store
        .ack_pending_custody(&copy, Utc::now())
        .await
        .expect("copy ack");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let legacy = cancelled(&f, &tenant, &session, "pre-source").await;
    let namespace = scope(&f, &tenant, &session);
    redis::pipe()
        .cmd("DEL")
        .arg(format!("{namespace}:events-v1"))
        .ignore()
        .cmd("HDEL")
        .arg(format!("{namespace}:session"))
        .arg("event_sequence")
        .arg("event_ack_sequence")
        .ignore()
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("pre-source journal fixture");
    mark_v2_ready(&f).await;
    assert!(matches!(
        RedisGatewayActionStore::connect(f.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationRequired)
    ));
    let first =
        RedisGatewayActionStore::migrate_recovery_format(f.config.clone(), true, Utc::now())
            .await
            .expect("start v3");
    assert!(!first.complete());
    assert!(matches!(
        RedisGatewayActionStore::connect(f.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
    ));
    let progress = migrate(&f.config).await;
    assert_eq!(progress.retention_backfilled_actions(), 2);
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("v3 restart");
    let release = reopened
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("release survives")
        .entries()[0]
        .clone();
    assert!(release.is_release());
    assert_eq!(release.receipt(), copy.receipt());
    let row = reopened
        .get_effective_action(&tenant, &session, legacy.action_id())
        .await
        .expect("legacy readable")
        .expect("known terminal");
    assert_eq!(row.terminal(), legacy.terminal());
    assert_eq!(row.last_source_event_sequence(), None);
    set_deadline(&f, &row, 1).await;
    assert_eq!(
        reopened
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("legacy conservatively pinned")
            .deferred(),
        1
    );
    let repeat = migrate(&f.config).await;
    assert_eq!(repeat.retention_backfilled_actions(), 2);
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_migration_oversize_preserves_payload_and_resumes_after_explicit_cap_raise()
{
    let Some(f) = redis_fixture("retention-migration-cap").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let first = cancelled(&f, &tenant, &session, "first").await;
    let second = cancelled(&f, &tenant, &session, "second").await;
    mark_v2_ready(&f).await;
    let low = f
        .config
        .clone()
        .with_retention_limits(GatewayActionRetentionLimits::new(1, 1).expect("low"));
    let mut rejected = false;
    for _ in 0..4096 {
        match RedisGatewayActionStore::migrate_recovery_format(low.clone(), true, Utc::now()).await
        {
            Err(GatewayActionCoordinationError::RetainedActionCapacity) => {
                rejected = true;
                break;
            }
            Ok(progress) => assert!(
                !progress.complete(),
                "oversize migration cannot enable writers"
            ),
            other => panic!("unexpected migration result: {other:?}"),
        }
    }
    assert!(rejected);
    let namespace = scope(&f, &tenant, &session);
    for action in [first.action_id(), second.action_id()] {
        let exists: bool = redis::cmd("HEXISTS")
            .arg(format!("{namespace}:actions"))
            .arg(action.to_string())
            .query_async(&mut connection(&f).await)
            .await
            .expect("preserved payload");
        assert!(exists);
    }
    let raised =
        low.with_retention_limits(GatewayActionRetentionLimits::new(2, 2).expect("raised"));
    assert_eq!(migrate(&raised).await.retention_backfilled_actions(), 2);
    let store = RedisGatewayActionStore::connect(raised)
        .await
        .expect("raised restart");
    assert!(
        store
            .get_effective_action(&tenant, &session, first.action_id())
            .await
            .expect("read")
            .is_some()
    );
    assert!(
        store
            .get_effective_action(&tenant, &session, second.action_id())
            .await
            .expect("read")
            .is_some()
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_exact_source_watermark_and_loss_pending_order_above_float_precision() {
    let Some(f) = redis_fixture("retention-exact-u64").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let seed = cancelled(&f, &tenant, &session, "seed").await;
    drain_events(&f.store, &tenant, &session).await;
    let namespace = scope(&f, &tenant, &session);
    redis::cmd("HSET")
        .arg(format!("{namespace}:session"))
        .arg("last_action_sequence")
        .arg("9007199254740991")
        .arg("event_sequence")
        .arg("9007199254740991")
        .arg("event_ack_sequence")
        .arg("9007199254740991")
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("exact highwater fixture");
    let mut ids = [ActionId::new(), ActionId::new()];
    ids.sort_by_key(ToString::to_string);
    let first = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ids[1].clone(),
                "first",
                2,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(3),
        )
        .await
        .expect("first")
        .into_snapshot();
    let second = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ids[0].clone(),
                "second",
                3,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(3),
        )
        .await
        .expect("second")
        .into_snapshot();
    let loss = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        placement(1, 1),
        Uuid::now_v7(),
    );
    f.store
        .mark_session_lost(&loss, at(4))
        .await
        .expect("loss commit");
    assert_eq!(
        f.store
            .materialize_session_loss(&loss, 1, at(5))
            .await
            .expect("oldest only"),
        1
    );
    let terminal = f
        .store
        .get_effective_action(&tenant, &session, first.action_id())
        .await
        .expect("first read")
        .expect("first");
    assert!(
        terminal.terminal().is_some(),
        "lex member must select earlier sequence despite reverse UUID order"
    );
    assert_eq!(
        f.store
            .get_effective_action(&tenant, &session, second.action_id())
            .await
            .expect("second read")
            .expect("second")
            .last_source_event_sequence(),
        None,
        "second terminal is derived but not materialized yet"
    );
    assert_eq!(
        terminal.last_source_event_sequence(),
        Some(9_007_199_254_740_993)
    );
    set_deadline(&f, &terminal, 1).await;
    let loss_event = f
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("loss event")
        .expect("event");
    assert_eq!(loss_event.sequence(), 9_007_199_254_740_992);
    f.store
        .ack_event_projection(&loss_event)
        .await
        .expect("ack earlier");
    assert_eq!(
        sweep(&f, 1).await.deferred(),
        1,
        "one-less watermark must not round upward"
    );
    let terminal_event = f
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("terminal event")
        .expect("event");
    f.store
        .ack_event_projection(&terminal_event)
        .await
        .expect("exact ack");
    // The loss producer still has another pending row, but completed read-only data can retire.
    assert_eq!(sweep(&f, 1).await.reclaimed(), 1);
    assert!(
        f.store
            .get_effective_action(&tenant, &session, seed.action_id())
            .await
            .expect("unexpired seed")
            .is_some()
    );
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_retention_corrupt_identity_mapping_never_deletes_payload() {
    let Some(f) = redis_fixture("retention-corrupt-identity").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let terminal = cancelled(&f, &tenant, &session, "identity").await;
    set_deadline(&f, &terminal, 1).await;
    drain_events(&f.store, &tenant, &session).await;
    let namespace = scope(&f, &tenant, &session);
    redis::cmd("HSET")
        .arg(format!("{namespace}:idempotency"))
        .arg("identity")
        .arg(ActionId::new().to_string())
        .query_async::<()>(&mut connection(&f).await)
        .await
        .expect("identity corruption fixture");
    assert!(matches!(
        f.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await,
        Err(GatewayActionCoordinationError::InvalidRedisResponse)
    ));
    let exists: bool = redis::cmd("HEXISTS")
        .arg(format!("{namespace}:actions"))
        .arg(terminal.action_id().to_string())
        .query_async(&mut connection(&f).await)
        .await
        .expect("payload preserved");
    assert!(exists);
    delete_fixture(&f).await;
}

#[tokio::test]
async fn redis_v3_nonzero_pending_score_rejects_loss_materialization_before_payload_write() {
    let Some(f) = redis_fixture("retention-pending-score").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let row = f
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "pending",
                1,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(1),
        )
        .await
        .expect("claim")
        .into_snapshot();
    let namespace = scope(&f, &tenant, &session);
    let loss = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        placement(1, 1),
        Uuid::now_v7(),
    );
    f.store.mark_session_lost(&loss, at(2)).await.expect("loss");
    let mut connection = connection(&f).await;
    let before: String = redis::cmd("HGET")
        .arg(format!("{namespace}:actions"))
        .arg(row.action_id().to_string())
        .query_async(&mut connection)
        .await
        .expect("raw before");
    redis::cmd("ZADD")
        .arg(format!("{namespace}:pending-v3"))
        .arg(1)
        .arg(format!(
            "{:020}|{}",
            row.action_sequence().get(),
            row.action_id()
        ))
        .query_async::<()>(&mut connection)
        .await
        .expect("corrupt score fixture");
    assert!(
        f.store
            .materialize_session_loss(&loss, 1, at(3))
            .await
            .is_err()
    );
    let after: String = redis::cmd("HGET")
        .arg(format!("{namespace}:actions"))
        .arg(row.action_id().to_string())
        .query_async(&mut connection)
        .await
        .expect("raw after");
    assert_eq!(
        after, before,
        "invalid physical order never commits a materialized terminal"
    );
    delete_fixture(&f).await;
}
