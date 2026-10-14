#![allow(clippy::expect_used, clippy::panic)]

#[path = "support/redis_fleet_admission.rs"]
mod redis_fleet_admission;

#[path = "support/redis_action_custody.rs"]
mod redis_action_custody;

#[path = "support/redis_terminal_custody_catchup.rs"]
mod redis_terminal_custody_catchup;

#[path = "support/redis_action_retention.rs"]
mod redis_action_retention;

#[path = "support/redis_action_recovery.rs"]
mod redis_action_recovery;

#[path = "support/redis_session_loss_recovery.rs"]
mod redis_session_loss_recovery;

#[path = "support/redis_session_directory.rs"]
mod redis_session_directory;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use browserd_actions::{
    ActionKind, ActionSequence, BrowserResult, CanonicalRequestHash, DispatchId,
    KnownFailureReason, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind, ResultDigest,
    TerminalDetail, TransportLoss,
};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionClaimOutcome, GatewayActionCoordination,
    GatewayActionCoordinationError, GatewayActionPlacement, GatewayEventProjection,
    GatewayEventScanCursor, MINIMUM_IDEMPOTENCY_RETENTION, OutboxAppend, RedisGatewayActionConfig,
    RedisGatewayActionStore, SessionLossClaim, SessionLossOutcome, StoreConfig,
};
use browserd_core::{ActionId, PrincipalId, SessionId, TenantId, WorkerId};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

struct RedisFixture {
    config: RedisGatewayActionConfig,
    store: Arc<RedisGatewayActionStore>,
    endpoint: String,
    prefix: String,
}

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, second)
        .single()
        .expect("test timestamp should be valid")
}

fn placement(worker_epoch: u64, directory_revision: u64) -> GatewayActionPlacement {
    GatewayActionPlacement::new(
        DirectoryFence::new(
            WorkerId::new("redis-gateway-action-worker").expect("worker ID should be valid"),
            worker_epoch,
            17,
            3,
        )
        .expect("directory fence should be valid"),
        directory_revision,
    )
    .expect("gateway action placement should be valid")
}

fn claim(
    tenant_id: TenantId,
    session_id: SessionId,
    proposed_action_id: ActionId,
    idempotency_key: impl Into<String>,
    request_byte: u8,
    placement: GatewayActionPlacement,
) -> ClaimGatewayAction {
    claim_with_kind(
        tenant_id,
        session_id,
        proposed_action_id,
        idempotency_key,
        request_byte,
        ActionKind::Mutating,
        placement,
    )
}

fn claim_with_kind(
    tenant_id: TenantId,
    session_id: SessionId,
    proposed_action_id: ActionId,
    idempotency_key: impl Into<String>,
    request_byte: u8,
    kind: ActionKind,
    placement: GatewayActionPlacement,
) -> ClaimGatewayAction {
    ClaimGatewayAction::new(
        tenant_id,
        session_id,
        proposed_action_id,
        idempotency_key,
        CanonicalRequestHash::new([request_byte; 32]),
        kind,
        placement,
    )
    .expect("gateway action claim should be valid")
}

async fn redis_fixture(label: &str) -> Option<RedisFixture> {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis gateway action test: BROWSERD_REDIS_TEST_URL is unset");
        return None;
    };
    let prefix = format!("browserd-gateway-action-{label}-{}", Uuid::new_v4());
    let config = RedisGatewayActionConfig::new(
        endpoint.clone(),
        prefix.clone(),
        StoreConfig::default(),
        32,
        Duration::from_secs(2),
    )
    .expect("Redis gateway action config should validate");
    let store = Arc::new(
        RedisGatewayActionStore::connect(config.clone())
            .await
            .expect("Redis gateway action store should connect"),
    );
    Some(RedisFixture {
        config,
        store,
        endpoint,
        prefix,
    })
}

async fn keys_with_prefix(endpoint: &str, prefix: &str) -> Vec<String> {
    let client = redis::Client::open(endpoint).expect("Redis endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis fixture connection should open");
    let pattern = format!("{prefix}:*");
    let mut cursor = 0_u64;
    let mut keys = Vec::new();
    loop {
        let (next, mut batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(128_u16)
            .query_async(&mut connection)
            .await
            .expect("Redis test namespace should be scannable");
        keys.append(&mut batch);
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    keys
}

async fn delete_fixture(fixture: &RedisFixture) {
    let keys = keys_with_prefix(&fixture.endpoint, &fixture.prefix).await;
    if keys.is_empty() {
        return;
    }
    let client = redis::Client::open(fixture.endpoint.as_str())
        .expect("Redis endpoint should validate for cleanup");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis cleanup connection should open");
    redis::cmd("UNLINK")
        .arg(keys)
        .query_async::<usize>(&mut connection)
        .await
        .expect("isolated Redis test keys should be removable");
}

#[tokio::test]
async fn redis_projection_discovery_bounds_result_pages_without_scanning_one_key_at_a_time() {
    let Some(fixture) = redis_fixture("projection-noisy-discovery").await else {
        return;
    };
    let tenant = TenantId::new();
    let placement = placement(1, 1);
    let mut expected = HashSet::new();
    for index in 0..8 {
        let session = SessionId::new();
        let action = ActionId::new();
        let claimed = fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    action.clone(),
                    format!("noisy-projection-{index}"),
                    1,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("claim");
        fixture
            .store
            .cancel_before_dispatch(
                &tenant,
                &session,
                &action,
                claimed.snapshot().revision(),
                &placement,
                at(2),
            )
            .await
            .expect("cancel");
        expected.insert(session);
    }
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let mut noise = redis::pipe();
    for index in 0..4_096 {
        noise
            .cmd("SET")
            .arg(format!("{}:scan-noise:{index}", fixture.prefix))
            .arg("unrelated")
            .arg("PX")
            .arg(300_000_u64)
            .ignore();
    }
    noise
        .query_async::<()>(&mut connection)
        .await
        .expect("private noise fixture");
    let database_keys: usize = redis::cmd("DBSIZE")
        .query_async(&mut connection)
        .await
        .expect("database size");
    // COUNT is a hint: allow eight times the scan work expected with COUNT 128,
    // plus separate pages for every matching scope buffered by the opaque cursor.
    // This budget measures progress rather than machine-dependent milliseconds.
    let page_budget = database_keys.div_ceil(16) + expected.len() + 16;
    let sweep = tokio::time::timeout(Duration::from_secs(30), async {
        let mut cursor = GatewayEventScanCursor::default();
        let mut found = HashSet::new();
        let mut bounded_pages = true;
        for calls in 1..=page_budget {
            let page = fixture
                .store
                .scan_event_sessions(cursor, 1)
                .await
                .expect("scan");
            bounded_pages &= page.sessions().len() <= 1;
            for scope in page.sessions() {
                assert_eq!(scope.tenant_id(), &tenant);
                found.insert(scope.session_id().clone());
            }
            cursor = page.next_cursor().clone();
            if page.is_complete() {
                return (true, found, bounded_pages, calls);
            }
        }
        (false, found, bounded_pages, page_budget)
    })
    .await;
    delete_fixture(&fixture).await;
    let (complete, found, bounded_pages, calls) = sweep.expect("bounded discovery sweep");
    assert!(
        bounded_pages,
        "logical discovery pages must retain their limit"
    );
    assert!(
        complete,
        "one-result discovery made insufficient progress: {calls} pages for {database_keys} keys"
    );
    assert_eq!(found, expected, "no buffered discovery scope may be lost");
}

#[tokio::test]
async fn redis_projection_journal_survives_payload_expiry_and_exact_ack() {
    let Some(fixture) = redis_fixture("projection-restart").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    for index in 0..2 {
        let action = ActionId::new();
        let claimed = fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    action.clone(),
                    format!("projection-{index}"),
                    1,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("claim");
        fixture
            .store
            .cancel_before_dispatch(
                &tenant,
                &session,
                &action,
                claimed.snapshot().revision(),
                &placement,
                at(2),
            )
            .await
            .expect("cancel");
    }
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let namespace = format!("{}:gateway-action:{{{tenant}:{session}}}", fixture.prefix);
    // Simulate ordinary source payload TTL expiry independently of the persistent relay intent.
    redis::cmd("DEL")
        .arg(format!("{namespace}:actions"))
        .arg(format!("{namespace}:idempotency"))
        .arg(format!("{namespace}:pending-v3"))
        .query_async::<usize>(&mut connection)
        .await
        .expect("expire payloads");
    let ttl: i64 = redis::cmd("PTTL")
        .arg(format!("{namespace}:events-v1"))
        .query_async(&mut connection)
        .await
        .expect("journal ttl");
    assert_eq!(ttl, -1);
    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("restart");
    let found = tokio::time::timeout(Duration::from_secs(10), async {
        let mut cursor = GatewayEventScanCursor::default();
        let mut found = false;
        loop {
            let page = restarted
                .scan_event_sessions(cursor, 1)
                .await
                .expect("scan");
            assert!(page.sessions().len() <= 1);
            found |= page
                .sessions()
                .iter()
                .any(|scope| scope.session_id() == &session);
            cursor = page.next_cursor().clone();
            if page.is_complete() {
                return found;
            }
        }
    })
    .await
    .expect("complete discovery sweep within test timeout");
    assert!(
        found,
        "persistent journal must be rediscoverable after restart"
    );
    let first = restarted
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("first");
    assert_eq!(first.sequence(), 1);
    let forged = GatewayEventProjection::new(
        tenant.clone(),
        session.clone(),
        1,
        OutboxAppend::action_terminal(tenant.clone(), session.clone(), ActionId::new(), 1),
    )
    .expect("well-formed different payload");
    assert_eq!(
        restarted.ack_event_projection(&forged).await,
        Err(GatewayActionCoordinationError::EventAckConflict)
    );
    restarted
        .ack_event_projection(&first)
        .await
        .expect("ack first");
    let second = restarted
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("second");
    assert_eq!(second.sequence(), 2);
    restarted
        .ack_event_projection(&first)
        .await
        .expect("stale ack");
    assert_eq!(
        restarted
            .peek_event_projection(&tenant, &session)
            .await
            .expect("peek"),
        Some(second.clone())
    );
    restarted
        .ack_event_projection(&second)
        .await
        .expect("ack second");
    assert!(
        restarted
            .peek_event_projection(&tenant, &session)
            .await
            .expect("empty")
            .is_none()
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_projection_corruption_rejects_terminal_commit_atomically() {
    let Some(fixture) = redis_fixture("projection-corrupt").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let action = ActionId::new();
    let placement = placement(1, 1);
    let claimed = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                action.clone(),
                "corrupt",
                1,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("claim")
        .into_snapshot();
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    redis::cmd("SET")
        .arg(format!(
            "{}:gateway-action:{{{tenant}:{session}}}:events-v1",
            fixture.prefix
        ))
        .arg("wrong-type")
        .query_async::<()>(&mut connection)
        .await
        .expect("corrupt journal");
    assert_eq!(
        fixture
            .store
            .cancel_before_dispatch(
                &tenant,
                &session,
                &action,
                claimed.revision(),
                &placement,
                at(2)
            )
            .await,
        Err(GatewayActionCoordinationError::InvalidRedisResponse)
    );
    assert_eq!(
        fixture
            .store
            .get_effective_action(&tenant, &session, &action)
            .await
            .expect("unchanged"),
        Some(claimed)
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_projection_sequences_remain_exact_above_lua_integer_precision() {
    let Some(fixture) = redis_fixture("projection-integer").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let action = ActionId::new();
    let placement = placement(1, 1);
    let claimed = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                action.clone(),
                "integer",
                1,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("claim")
        .into_snapshot();
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let session_key = format!(
        "{}:gateway-action:{{{tenant}:{session}}}:session",
        fixture.prefix
    );
    let previous = 9_007_199_254_740_992_u64;
    redis::cmd("HSET")
        .arg(&session_key)
        .arg("event_sequence")
        .arg(previous.to_string())
        .arg("event_ack_sequence")
        .arg(previous.to_string())
        .query_async::<usize>(&mut connection)
        .await
        .expect("simulate high acknowledged sequence");
    fixture
        .store
        .cancel_before_dispatch(
            &tenant,
            &session,
            &action,
            claimed.revision(),
            &placement,
            at(2),
        )
        .await
        .expect("cancel");
    let projection = fixture
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("projection");
    assert_eq!(projection.sequence(), previous + 1);
    fixture
        .store
        .ack_event_projection(&projection)
        .await
        .expect("exact ack");
    let ack: String = redis::cmd("HGET")
        .arg(session_key)
        .arg("event_ack_sequence")
        .query_async(&mut connection)
        .await
        .expect("read ack");
    assert_eq!(ack, (previous + 1).to_string());
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_loss_projection_marker_survives_ack_and_materializes_every_batch() {
    let Some(fixture) = redis_fixture("projection-loss").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    for index in 0..3 {
        fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("loss-{index}"),
                    1,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("claim");
    }
    let loss = SessionLossClaim::new(tenant.clone(), session.clone(), placement, Uuid::now_v7());
    fixture
        .store
        .mark_session_lost(&loss, at(2))
        .await
        .expect("loss");
    let event = fixture
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("loss");
    fixture
        .store
        .ack_event_projection(&event)
        .await
        .expect("ack loss");
    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("restart");
    let found_claim = tokio::time::timeout(Duration::from_secs(10), async {
        let mut cursor = GatewayEventScanCursor::default();
        let mut found_claim = None;
        loop {
            let page = restarted
                .scan_event_sessions(cursor, 1)
                .await
                .expect("scan");
            for scope in page.sessions() {
                if scope.session_id() == &session {
                    found_claim = scope.loss_claim().cloned();
                }
            }
            cursor = page.next_cursor().clone();
            if page.is_complete() {
                return found_claim;
            }
        }
    })
    .await
    .expect("complete loss discovery sweep within test timeout");
    assert_eq!(found_claim, Some(loss.clone()));
    for sequence in 2..=4 {
        assert_eq!(
            restarted
                .materialize_session_loss(&loss, 1, at(3))
                .await
                .expect("batch"),
            1
        );
        let event = restarted
            .peek_event_projection(&tenant, &session)
            .await
            .expect("peek")
            .expect("action");
        assert_eq!(event.sequence(), sequence);
        restarted
            .ack_event_projection(&event)
            .await
            .expect("ack action");
    }
    let event_keys = keys_with_prefix(&fixture.endpoint, &fixture.prefix)
        .await
        .into_iter()
        .filter(|key| key.ends_with(":events-v1"))
        .count();
    assert_eq!(
        event_keys, 0,
        "finished loss marker and acknowledged events must disappear"
    );
    delete_fixture(&fixture).await;
}

#[test]
fn redis_gateway_action_config_validates_bounds_and_redacts_endpoint() {
    let config = RedisGatewayActionConfig::new(
        "redis://browserd:do-not-log-this@127.0.0.1/",
        "browserd-gateway-actions",
        StoreConfig::default(),
        32,
        Duration::from_secs(2),
    )
    .expect("bounded Redis config should validate");
    let debug = format!("{config:?}");
    assert!(!debug.contains("do-not-log-this"));
    assert!(!debug.contains("redis://"));
    assert!(debug.contains("REDACTED"));

    assert!(
        RedisGatewayActionConfig::new(
            "",
            "browserd-gateway-actions",
            StoreConfig::default(),
            32,
            Duration::from_secs(2),
        )
        .is_err()
    );
    assert!(
        RedisGatewayActionConfig::new(
            "redis://127.0.0.1/",
            "invalid {cluster tag}",
            StoreConfig::default(),
            32,
            Duration::from_secs(2),
        )
        .is_err()
    );
    assert!(
        RedisGatewayActionConfig::new(
            "redis://127.0.0.1/",
            "browserd-gateway-actions",
            StoreConfig::default(),
            0,
            Duration::from_secs(2),
        )
        .is_err()
    );
    assert!(
        RedisGatewayActionConfig::new(
            "redis://127.0.0.1/",
            "browserd-gateway-actions",
            StoreConfig::default(),
            32,
            Duration::ZERO,
        )
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_exact_retry_recovers_one_action_id_and_placement_is_exact_cas() {
    let Some(fixture) = redis_fixture("exact-cas").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let current = placement(11, 41);
    let action_id = ActionId::new();
    let created = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "stable-action-key",
                1,
                current.clone(),
            ),
            at(1),
        )
        .await
        .expect("initial Redis action claim should succeed");
    assert!(matches!(created, GatewayActionClaimOutcome::Created(_)));
    assert!(
        created.snapshot().retain_until() - created.snapshot().created_at()
            >= chrono::Duration::from_std(MINIMUM_IDEMPOTENCY_RETENTION)
                .expect("minimum retention should fit chrono")
    );

    let exact_retry = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                ActionId::new(),
                "stable-action-key",
                1,
                current.clone(),
            ),
            at(2),
        )
        .await
        .expect("exact retry should recover the persisted claim");
    assert!(matches!(
        exact_retry,
        GatewayActionClaimOutcome::Existing(_)
    ));
    assert_eq!(exact_retry.snapshot().action_id(), &action_id);

    for stale in [placement(11, 40), placement(12, 41)] {
        assert_eq!(
            fixture
                .store
                .claim_action(
                    claim(
                        tenant_id.clone(),
                        session_id.clone(),
                        ActionId::new(),
                        "stale-placement-key",
                        2,
                        stale,
                    ),
                    at(3),
                )
                .await,
            Err(GatewayActionCoordinationError::PlacementMismatch)
        );
    }

    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("a separate Redis action store should connect");
    let recovered = restarted
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("persisted action lookup should succeed")
        .expect("persisted action should be visible to a separate store instance");
    assert_eq!(recovered.action_id(), &action_id);
    delete_fixture(&fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_concurrent_duplicate_claim_has_one_created_action_id() {
    const CLAIMANTS: usize = 64;
    let Some(fixture) = redis_fixture("duplicate-claim").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(13, 43);
    let barrier = Arc::new(tokio::sync::Barrier::new(CLAIMANTS + 1));
    let mut tasks = Vec::with_capacity(CLAIMANTS);
    for _ in 0..CLAIMANTS {
        let store = Arc::clone(&fixture.store);
        let barrier = Arc::clone(&barrier);
        let claim = claim(
            tenant_id.clone(),
            session_id.clone(),
            ActionId::new(),
            "duplicate-action-key",
            3,
            placement.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.claim_action(claim, at(1)).await
        }));
    }

    barrier.wait().await;
    let mut created = 0;
    let mut action_ids = HashSet::new();
    let mut duplicate_sequences = HashSet::new();
    for task in tasks {
        let outcome = task
            .await
            .expect("Redis claim task should join")
            .expect("concurrent exact claim should succeed");
        created += usize::from(matches!(outcome, GatewayActionClaimOutcome::Created(_)));
        action_ids.insert(outcome.snapshot().action_id().clone());
        duplicate_sequences.insert(outcome.snapshot().action_sequence().get());
    }
    assert_eq!(created, 1);
    assert_eq!(action_ids.len(), 1);
    assert_eq!(duplicate_sequences, HashSet::from([1]));

    let barrier = Arc::new(tokio::sync::Barrier::new(CLAIMANTS + 1));
    let mut tasks = Vec::with_capacity(CLAIMANTS);
    for index in 0..CLAIMANTS {
        let store = Arc::clone(&fixture.store);
        let barrier = Arc::clone(&barrier);
        let claim = claim(
            tenant_id.clone(),
            session_id.clone(),
            ActionId::new(),
            format!("distinct-action-{index}"),
            index as u8,
            placement.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.claim_action(claim, at(2)).await
        }));
    }
    barrier.wait().await;
    let mut sequences = Vec::with_capacity(CLAIMANTS);
    for task in tasks {
        let outcome = task
            .await
            .expect("Redis distinct claim task should join")
            .expect("concurrent distinct claim should succeed");
        sequences.push(outcome.snapshot().action_sequence().get());
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (2..=65).collect::<Vec<_>>());
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_loss_derivation_distinguishes_not_attempted_from_dispatch_armed() {
    let Some(fixture) = redis_fixture("loss-derivation").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(17, 47);
    let not_attempted_id = ActionId::new();
    let armed_id = ActionId::new();
    let not_attempted = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                not_attempted_id.clone(),
                "not-attempted",
                5,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("not-attempted action should be persisted");
    let armed = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                armed_id.clone(),
                "dispatch-armed",
                7,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("dispatch-intent action should be persisted");
    let dispatch_id = DispatchId::new();
    fixture
        .store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &armed_id,
            armed.snapshot().revision(),
            &placement,
            dispatch_id,
            at(2),
        )
        .await
        .expect("dispatch must be durably armed before a send-capable handoff");

    let loss = SessionLossClaim::new(
        tenant_id.clone(),
        session_id.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    assert_eq!(
        fixture
            .store
            .mark_session_lost(&loss, at(3))
            .await
            .expect("session loss should linearize"),
        SessionLossOutcome::Recorded
    );

    let known = fixture
        .store
        .get_effective_action(&tenant_id, &session_id, &not_attempted_id)
        .await
        .expect("not-attempted lookup should succeed")
        .expect("not-attempted action should exist");
    let unknown = fixture
        .store
        .get_effective_action(&tenant_id, &session_id, &armed_id)
        .await
        .expect("armed lookup should succeed")
        .expect("armed action should exist");
    assert_eq!(
        known.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );
    assert_eq!(
        unknown.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );
    assert_eq!(known.revision(), not_attempted.snapshot().revision());

    let exact_retry = fixture
        .store
        .claim_action(
            claim(
                tenant_id,
                session_id,
                ActionId::new(),
                "dispatch-armed",
                7,
                placement,
            ),
            at(4),
        )
        .await
        .expect("retry after loss should recover the existing terminal action");
    assert_eq!(exact_retry.snapshot().action_id(), &armed_id);
    assert_eq!(
        exact_retry
            .snapshot()
            .terminal()
            .map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );
    delete_fixture(&fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redis_worker_result_and_loss_write_have_one_stable_winner() {
    const RACES: u8 = 24;
    let Some(fixture) = redis_fixture("loss-result-race").await else {
        return;
    };
    for iteration in 0..RACES {
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let placement = placement(19, u64::from(iteration) + 51);
        let action_id = ActionId::new();
        let claimed = fixture
            .store
            .claim_action(
                claim(
                    tenant_id.clone(),
                    session_id.clone(),
                    action_id.clone(),
                    format!("loss-write-race-{iteration}"),
                    iteration,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("racing action should be claimed");
        let dispatch_id = DispatchId::new();
        let armed = fixture
            .store
            .arm_dispatch(
                &tenant_id,
                &session_id,
                &action_id,
                claimed.snapshot().revision(),
                &placement,
                dispatch_id.clone(),
                at(2),
            )
            .await
            .expect("racing action should be armed");
        let loss = SessionLossClaim::new(
            tenant_id.clone(),
            session_id.clone(),
            placement.clone(),
            Uuid::now_v7(),
        );
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let result_store = Arc::clone(&fixture.store);
        let result_barrier = Arc::clone(&barrier);
        let result_tenant = tenant_id.clone();
        let result_session = session_id.clone();
        let result_action = action_id.clone();
        let result_placement = placement.clone();
        let result_dispatch = dispatch_id;
        let result = tokio::spawn(async move {
            result_barrier.wait().await;
            result_store
                .record_worker_result(
                    &result_tenant,
                    &result_session,
                    &result_action,
                    armed.revision(),
                    &result_placement,
                    &result_dispatch,
                    ActionSequence::new(1),
                    BrowserResult::Succeeded(ResultDigest::new([9; 32])),
                    None,
                    at(3),
                )
                .await
        });
        let loss_store = Arc::clone(&fixture.store);
        let loss_barrier = Arc::clone(&barrier);
        let lost = tokio::spawn(async move {
            loss_barrier.wait().await;
            loss_store.mark_session_lost(&loss, at(3)).await
        });

        barrier.wait().await;
        let result = result.await.expect("worker result task should join");
        assert_eq!(
            lost.await
                .expect("worker loss task should join")
                .expect("worker loss should become the durable fence"),
            SessionLossOutcome::Recorded
        );
        let effective = fixture
            .store
            .get_effective_action(&tenant_id, &session_id, &action_id)
            .await
            .expect("effective racing action lookup should succeed")
            .expect("racing action should exist");
        match result {
            Ok(snapshot) => {
                assert_eq!(
                    snapshot.terminal().map(|terminal| terminal.detail()),
                    Some(TerminalDetail::Succeeded(ResultDigest::new([9; 32])))
                );
                assert_eq!(effective.terminal(), snapshot.terminal());
            }
            Err(GatewayActionCoordinationError::SessionLost) => assert_eq!(
                effective.terminal().map(|terminal| terminal.detail()),
                Some(TerminalDetail::OutcomeUnknown(
                    OutcomeUnknownReason::WorkerLost
                ))
            ),
            other => assert_eq!(other, Err(GatewayActionCoordinationError::SessionLost)),
        }
    }
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_session_action_keys_share_hash_tag_and_live_loss_fence_has_no_ttl() {
    let Some(fixture) = redis_fixture("hash-slot-loss-retention").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(23, 79);
    fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                ActionId::new(),
                "slot-contract",
                11,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("slot contract action should be persisted");
    let loss_id = Uuid::now_v7();
    let loss = SessionLossClaim::new(tenant_id.clone(), session_id.clone(), placement, loss_id);
    fixture
        .store
        .mark_session_lost(&loss, at(2))
        .await
        .expect("slot contract loss fence should be persisted");

    let keys = keys_with_prefix(&fixture.endpoint, &fixture.prefix).await;
    assert!(
        keys.len() >= 2,
        "session state and retained action/idempotency state must be separate keys"
    );
    let expected_hash_tag = format!("{{{tenant_id}:{session_id}}}");
    let retained_catalog = format!("{}:gateway-action:retained-v3", fixture.prefix);
    let retention_index = format!("{}:gateway-action:retention-v3", fixture.prefix);
    assert!(
        keys.iter()
            .filter(|key| {
                !key.contains(":recovery-") && *key != &retained_catalog && *key != &retention_index
            })
            .all(|key| key.contains(&expected_hash_tag)),
        "every session/action/loss/idempotency key must share the exact tenant/session Redis hash tag: {keys:?}"
    );

    let client = redis::Client::open(fixture.endpoint.as_str())
        .expect("Redis endpoint should validate for invariant inspection");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis invariant inspection connection should open");
    let expected_loss_id = loss_id.to_string();
    let mut persistent_loss_hashes = Vec::new();
    for key in &keys {
        let key_type: String = redis::cmd("TYPE")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("coordination key type should be readable");
        if key_type != "hash" {
            continue;
        }
        let stored_loss_id: Option<String> = redis::cmd("HGET")
            .arg(key)
            .arg("loss_id")
            .query_async(&mut connection)
            .await
            .expect("coordination hash should be readable");
        if stored_loss_id.as_deref() != Some(expected_loss_id.as_str()) {
            continue;
        }
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("loss fence TTL should be readable");
        assert_eq!(
            ttl, -1,
            "the live session/loss hash must not expire with retained action keys"
        );
        persistent_loss_hashes.push(key.clone());
    }
    assert_eq!(
        persistent_loss_hashes.len(),
        1,
        "one non-expiring session hash must own the durable loss fence"
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_unknown_resolution_does_not_require_terminal_action_in_pending_index() {
    let Some(fixture) = redis_fixture("unknown-resolution").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(29, 83);
    let action_id = ActionId::new();
    let claimed = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "unknown-resolution",
                13,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("action should be claimed");
    let dispatch_id = DispatchId::new();
    let armed = fixture
        .store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &action_id,
            claimed.snapshot().revision(),
            &placement,
            dispatch_id.clone(),
            at(2),
        )
        .await
        .expect("action should own the mutation lane");
    let unknown = fixture
        .store
        .record_transport_loss(
            &tenant_id,
            &session_id,
            &action_id,
            armed.revision(),
            &placement,
            &dispatch_id,
            TransportLoss::Ambiguous(OutcomeUnknownReason::TimeoutAfterDispatch),
            at(3),
        )
        .await
        .expect("transport loss should become terminal unknown");
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        4_000,
        "verified by a post-loss read",
    );
    let resolved = fixture
        .store
        .resolve_unknown(
            &tenant_id,
            &session_id,
            &action_id,
            unknown.revision(),
            &placement,
            annotation.clone(),
            at(4),
        )
        .await
        .expect("terminal unknown should resolve without pending membership");
    assert_eq!(resolved.resolution(), Some(&annotation));

    let next = fixture
        .store
        .claim_action(
            claim(
                tenant_id,
                session_id,
                ActionId::new(),
                "mutation-after-resolution",
                14,
                placement,
            ),
            at(5),
        )
        .await
        .expect("resolution should reopen mutation admission");
    assert!(matches!(next, GatewayActionClaimOutcome::Created(_)));
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_materialized_worker_loss_unknown_can_be_resolved_and_annotation_persists() {
    let Some(fixture) = redis_fixture("materialized-loss-resolution").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(31, 89);
    let action_id = ActionId::new();
    let claimed = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "materialized-loss-resolution",
                15,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("action should be claimed");
    let armed = fixture
        .store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &action_id,
            claimed.snapshot().revision(),
            &placement,
            DispatchId::new(),
            at(2),
        )
        .await
        .expect("mutation should be dispatch-armed before session loss");
    assert!(armed.terminal().is_none());

    let loss = SessionLossClaim::new(
        tenant_id.clone(),
        session_id.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    assert_eq!(
        fixture
            .store
            .mark_session_lost(&loss, at(3))
            .await
            .expect("session loss should linearize"),
        SessionLossOutcome::Recorded
    );
    assert_eq!(
        fixture
            .store
            .materialize_session_loss(&loss, 100, at(4))
            .await
            .expect("dispatch-armed mutation should materialize after loss"),
        1
    );
    let materialized = fixture
        .store
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("materialized action lookup should succeed")
        .expect("materialized action should remain queryable");
    assert_eq!(
        materialized.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );

    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        5_000,
        "confirmed from external state after worker loss",
    );
    let resolved = fixture
        .store
        .resolve_unknown(
            &tenant_id,
            &session_id,
            &action_id,
            materialized.revision(),
            &placement,
            annotation.clone(),
            at(5),
        )
        .await
        .expect("materialized worker-loss unknown should accept caller resolution");
    assert_eq!(resolved.resolution(), Some(&annotation));
    assert_eq!(
        resolved.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );

    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("separate Redis action store should reconnect");
    let persisted = restarted
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("resolved action should be readable after reconnect")
        .expect("resolved action should remain retained");
    assert_eq!(persisted.resolution(), Some(&annotation));
    assert_eq!(
        persisted.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_unknown_mutation_holds_action_keys_persistent_until_resolution() {
    let Some(fixture) = redis_fixture("unknown-mutation-retention-hold").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(37, 97);
    let action_id = ActionId::new();
    let claimed = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "retention-hold-mutation",
                17,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("mutation should be claimed");
    let dispatch_id = DispatchId::new();
    let armed = fixture
        .store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &action_id,
            claimed.snapshot().revision(),
            &placement,
            dispatch_id.clone(),
            at(2),
        )
        .await
        .expect("live mutation should arm its dispatch");

    let client = redis::Client::open(fixture.endpoint.as_str())
        .expect("Redis endpoint should validate for TTL inspection");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("Redis TTL inspection connection should open");
    let keys = keys_with_prefix(&fixture.endpoint, &fixture.prefix).await;
    let mut session_keys = Vec::new();
    let mut retained_keys = Vec::new();
    let mut retained_types = Vec::new();
    for key in keys.into_iter().filter(|key| {
        [":session", ":actions", ":idempotency", ":pending-v3"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
    }) {
        let key_type: String = redis::cmd("TYPE")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("coordination key type should be readable");
        let stored_placement: Option<String> = if key_type == "hash" {
            redis::cmd("HGET")
                .arg(&key)
                .arg("placement")
                .query_async(&mut connection)
                .await
                .expect("coordination hash should expose its placement field")
        } else {
            None
        };
        if stored_placement.is_some() {
            session_keys.push(key);
        } else {
            let ttl: i64 = redis::cmd("PTTL")
                .arg(&key)
                .query_async(&mut connection)
                .await
                .expect("armed coordination key TTL should be readable");
            assert_eq!(
                ttl, -1,
                "an armed mutation must hold every non-session coordination key persistent"
            );
            retained_keys.push(key);
            retained_types.push(key_type);
        }
    }
    assert_eq!(
        session_keys.len(),
        1,
        "one hash carrying placement must be the persistent session key"
    );
    retained_types.sort_unstable();
    assert_eq!(
        retained_types,
        ["hash".to_owned(), "hash".to_owned(), "zset".to_owned()]
    );

    let unknown = fixture
        .store
        .record_transport_loss(
            &tenant_id,
            &session_id,
            &action_id,
            armed.revision(),
            &placement,
            &dispatch_id,
            TransportLoss::Ambiguous(OutcomeUnknownReason::TimeoutAfterDispatch),
            at(3),
        )
        .await
        .expect("ambiguous transport loss should require reconciliation");
    let mut persistent_hashes = 0;
    let mut missing_keys = 0;
    for key in &retained_keys {
        let key_type: String = redis::cmd("TYPE")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("unknown coordination key type should be readable");
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("unknown coordination key TTL should be readable");
        match key_type.as_str() {
            "hash" => {
                assert_eq!(
                    ttl, -1,
                    "OutcomeUnknown must retain its action and idempotency hashes indefinitely"
                );
                persistent_hashes += 1;
            }
            "none" => {
                assert_eq!(ttl, -2);
                missing_keys += 1;
            }
            other => panic!("unexpected key type after terminal unknown: {other}"),
        }
    }
    assert_eq!(persistent_hashes, 2);
    assert_eq!(
        missing_keys, 1,
        "the terminal mutation should be removed from the pending index"
    );

    let read_only = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant_id.clone(),
                session_id.clone(),
                ActionId::new(),
                "read-during-retention-hold",
                18,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(4),
        )
        .await
        .expect("read-only reconciliation should remain available during OutcomeUnknown");
    assert!(matches!(read_only, GatewayActionClaimOutcome::Created(_)));
    for key in &retained_keys {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("held coordination key TTL should be readable after a read-only claim");
        assert_eq!(
            ttl, -1,
            "a read-only claim must not turn the unresolved mutation hold into a finite TTL"
        );
    }

    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        6_000,
        "verified by reconciliation read while the Redis hold was active",
    );
    fixture
        .store
        .resolve_unknown(
            &tenant_id,
            &session_id,
            &action_id,
            unknown.revision(),
            &placement,
            annotation,
            at(5),
        )
        .await
        .expect("resolving the unknown mutation should release the retention hold");

    for key in &retained_keys {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("remaining read retains TTL");
        assert_eq!(
            ttl, -1,
            "resolving one mutation must not expire a pending read-only action"
        );
    }
    fixture
        .store
        .cancel_before_dispatch(
            &tenant_id,
            &session_id,
            read_only.snapshot().action_id(),
            read_only.snapshot().revision(),
            &placement,
            at(6),
        )
        .await
        .expect("finish remaining pending read");
    for key in &retained_keys {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("released coordination key TTL should be readable");
        if key.ends_with(":pending-v3") {
            assert_eq!(ttl, -2, "last completed action removes the pending index");
        } else {
            assert_eq!(
                ttl, -1,
                "v3 reclaims individual records after their fixed horizons"
            );
        }
    }
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_read_only_unknown_can_be_resolved_without_a_mutation_lane() {
    let Some(fixture) = redis_fixture("read-only-unknown-resolution").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(41, 101);
    let action_id = ActionId::new();
    let claimed = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "read-only-unknown-resolution",
                19,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("read-only action should be claimed");
    let dispatch_id = DispatchId::new();
    let armed = fixture
        .store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &action_id,
            claimed.snapshot().revision(),
            &placement,
            dispatch_id.clone(),
            at(2),
        )
        .await
        .expect("read-only dispatch should arm without owning the mutation lane");
    let unknown = fixture
        .store
        .record_transport_loss(
            &tenant_id,
            &session_id,
            &action_id,
            armed.revision(),
            &placement,
            &dispatch_id,
            TransportLoss::Ambiguous(OutcomeUnknownReason::TimeoutAfterDispatch),
            at(3),
        )
        .await
        .expect("read-only transport loss should become terminal unknown");
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::Abandoned,
        PrincipalId::new(),
        4_000,
        "read-only result was no longer needed",
    );
    let resolved = fixture
        .store
        .resolve_unknown(
            &tenant_id,
            &session_id,
            &action_id,
            unknown.revision(),
            &placement,
            annotation.clone(),
            at(4),
        )
        .await
        .expect("read-only unknown should resolve without a mutation lane pointer");
    assert_eq!(resolved.resolution(), Some(&annotation));
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_succeeded_result_body_survives_serialization_and_a_store_restart() {
    // R01: a succeeded action's result body must round-trip through Redis and be readable by a
    // separate store instance (a restarted gateway), not only its digest.
    let Some(fixture) = redis_fixture("result-body-durability").await else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let action_id = ActionId::new();
    let placement = placement(17, 61);
    let claimed = fixture
        .store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "result-body-durability",
                9,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("claim should persist");
    let action_sequence = claimed.snapshot().action_sequence();
    let dispatch_id = DispatchId::new();
    let armed = fixture
        .store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &action_id,
            claimed.snapshot().revision(),
            &placement,
            dispatch_id.clone(),
            at(2),
        )
        .await
        .expect("dispatch must arm before a worker result");

    let body = br#"{"text":"durable result body via redis"}"#.to_vec();
    let digest = ResultDigest::new([7; 32]);
    let recorded = fixture
        .store
        .record_worker_result(
            &tenant_id,
            &session_id,
            &action_id,
            armed.revision(),
            &placement,
            &dispatch_id,
            action_sequence,
            BrowserResult::Succeeded(digest),
            Some(body.clone()),
            at(3),
        )
        .await
        .expect("worker result should record");
    assert_eq!(recorded.result_content(), Some(body.as_slice()));

    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("a separate Redis action store should connect");
    let recovered = restarted
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("persisted action lookup should succeed")
        .expect("persisted action should be visible after a restart");
    assert_eq!(
        recovered.result_content(),
        Some(body.as_slice()),
        "the result body, not just its digest, survives Redis and a store restart"
    );
    assert_eq!(
        recovered.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::Succeeded(digest))
    );
    delete_fixture(&fixture).await;
}
