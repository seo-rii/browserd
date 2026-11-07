use super::*;
use browserd_actions::ActionDeliveryEvidence;
use browserd_coordination::{GatewayActionRecoveryCursor, GatewayActionSubmissionLease};

fn lease(now: chrono::DateTime<Utc>, milliseconds: i64) -> GatewayActionSubmissionLease {
    let expires = now + chrono::Duration::milliseconds(milliseconds);
    GatewayActionSubmissionLease::new(Uuid::now_v7(), 1, expires, expires).expect("lease")
}

async fn connection(fixture: &RedisFixture) -> redis::aio::MultiplexedConnection {
    redis::Client::open(fixture.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("connection")
}

fn namespace(fixture: &RedisFixture, tenant: &TenantId, session: &SessionId) -> String {
    format!("{}:gateway-action:{{{tenant}:{session}}}", fixture.prefix)
}

#[tokio::test]
async fn redis_pending_read_only_survives_restart_and_releases_ttl_only_when_terminal() {
    let Some(fixture) = redis_fixture("recovery-read-ttl").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let claimed = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "read",
                1,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("claim");
    let mut connection = connection(&fixture).await;
    let namespace = namespace(&fixture, &tenant, &session);
    for suffix in ["actions", "idempotency", "pending-v3"] {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(format!("{namespace}:{suffix}"))
            .query_async(&mut connection)
            .await
            .expect("ttl");
        assert_eq!(
            ttl, -1,
            "even an unattempted read is a durable pending obligation"
        );
    }
    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("restart");
    let page = restarted
        .scan_pending_actions(GatewayActionRecoveryCursor::default(), 1)
        .await
        .expect("bounded discovery");
    assert_eq!(page.actions(), &[claimed.snapshot().clone()]);
    assert!(!page.is_complete());
    let tail = restarted
        .scan_pending_actions(page.next_cursor().clone(), 1)
        .await
        .expect("empty tail");
    assert!(tail.is_complete());
    assert!(tail.actions().is_empty());
    restarted
        .cancel_before_dispatch(
            &tenant,
            &session,
            claimed.snapshot().action_id(),
            0,
            &placement,
            at(2),
        )
        .await
        .expect("terminal");
    assert!(
        restarted
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .expect("scan")
            .actions()
            .is_empty()
    );
    for suffix in ["actions", "idempotency"] {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(format!("{namespace}:{suffix}"))
            .query_async(&mut connection)
            .await
            .expect("retention");
        assert_eq!(
            ttl, -1,
            "terminal payload has a fixed individual horizon, no hash TTL"
        );
    }
    assert!(
        restarted
            .peek_event_projection(&tenant, &session)
            .await
            .expect("projection")
            .is_some()
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_owned_dispatch_requires_exact_lease_oldest_action_and_all_kind_lane() {
    let Some(fixture) = redis_fixture("recovery-owned-lane").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let now = Utc::now();
    let first_lease = lease(now, 60_000);
    let first = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "first-read",
                1,
                ActionKind::ReadOnly,
                placement.clone(),
            )
            .with_submission_lease(first_lease.clone()),
            now,
        )
        .await
        .expect("first");
    let second_lease = lease(now, 60_000);
    let second = fixture
        .store
        .claim_action(
            claim(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "second-mutation",
                2,
                placement.clone(),
            )
            .with_submission_lease(second_lease.clone()),
            now,
        )
        .await
        .expect("second");
    let first = first.snapshot();
    let second = second.snapshot();
    assert!(matches!(
        fixture
            .store
            .arm_dispatch(
                &tenant,
                &session,
                first.action_id(),
                first.revision(),
                &placement,
                DispatchId::new(),
                now
            )
            .await,
        Err(GatewayActionCoordinationError::SubmissionLeaseRequired)
    ));
    assert!(matches!(
        fixture
            .store
            .arm_dispatch_owned(
                &tenant,
                &session,
                first.action_id(),
                first.revision(),
                &placement,
                DispatchId::new(),
                &second_lease,
                now
            )
            .await,
        Err(GatewayActionCoordinationError::SubmissionLeaseMismatch)
    ));
    assert!(
        matches!(fixture.store.arm_dispatch_owned(&tenant, &session, second.action_id(), second.revision(), &placement, DispatchId::new(), &second_lease, now).await, Err(GatewayActionCoordinationError::ActionDispatchInFlight { action_id }) if &action_id == first.action_id())
    );
    let first_dispatch = DispatchId::new();
    let armed = fixture
        .store
        .arm_dispatch_owned(
            &tenant,
            &session,
            first.action_id(),
            first.revision(),
            &placement,
            first_dispatch.clone(),
            &first_lease,
            now,
        )
        .await
        .expect("read owns dispatch");
    assert!(matches!(
        fixture
            .store
            .arm_dispatch_owned(
                &tenant,
                &session,
                second.action_id(),
                second.revision(),
                &placement,
                DispatchId::new(),
                &second_lease,
                now
            )
            .await,
        Err(GatewayActionCoordinationError::ActionDispatchInFlight { .. })
    ));
    fixture
        .store
        .record_worker_result(
            &tenant,
            &session,
            first.action_id(),
            armed.revision(),
            &placement,
            &first_dispatch,
            first.action_sequence(),
            BrowserResult::Succeeded(ResultDigest::new([1; 32])),
            None,
            now,
        )
        .await
        .expect("finish read");
    let second_dispatch = DispatchId::new();
    fixture
        .store
        .arm_dispatch_owned(
            &tenant,
            &session,
            second.action_id(),
            second.revision(),
            &placement,
            second_dispatch,
            &second_lease,
            now,
        )
        .await
        .expect("released lane");
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_server_clock_blocks_early_expiry_and_late_owner_with_a_stale_timestamp() {
    let Some(fixture) = redis_fixture("recovery-server-clock").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let now = Utc::now();
    let owner = lease(now, 500);
    let request = claim(
        tenant.clone(),
        session.clone(),
        ActionId::new(),
        "expiry",
        1,
        placement.clone(),
    )
    .with_submission_lease(owner.clone());
    let claimed = fixture
        .store
        .claim_action(request.clone(), now)
        .await
        .expect("claim");
    let snapshot = claimed.snapshot();
    assert!(matches!(
        fixture
            .store
            .expire_unattempted_action(
                &tenant,
                &session,
                snapshot.action_id(),
                snapshot.revision(),
                &placement,
                &owner,
                now + chrono::Duration::seconds(10)
            )
            .await,
        Err(GatewayActionCoordinationError::SubmissionLeaseNotExpired)
    ));
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(matches!(
        fixture
            .store
            .arm_dispatch_owned(
                &tenant,
                &session,
                snapshot.action_id(),
                snapshot.revision(),
                &placement,
                DispatchId::new(),
                &owner,
                now
            )
            .await,
        Err(GatewayActionCoordinationError::SubmissionLeaseExpired)
    ));
    let expired = fixture
        .store
        .expire_unattempted_action(
            &tenant,
            &session,
            snapshot.action_id(),
            snapshot.revision(),
            &placement,
            &owner,
            Utc::now(),
        )
        .await
        .expect("expired exact owner");
    assert_eq!(
        expired.terminal().expect("terminal").detail(),
        TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
    );
    assert!(matches!(
        expired.delivery(),
        ActionDeliveryEvidence::NotAttempted
    ));
    assert!(
        fixture
            .store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .expect("scan")
            .actions()
            .is_empty()
    );
    let replay = fixture
        .store
        .claim_action(request, Utc::now())
        .await
        .expect("expired original lease still replays identity");
    assert_eq!(replay.snapshot(), &expired);
    assert!(matches!(
        fixture
            .store
            .arm_dispatch_owned(
                &tenant,
                &session,
                snapshot.action_id(),
                snapshot.revision(),
                &placement,
                DispatchId::new(),
                &owner,
                now
            )
            .await,
        Err(GatewayActionCoordinationError::StaleWrite(_))
    ));
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_global_recovery_pages_are_bounded_and_cover_multiple_tenants_and_sessions() {
    let Some(fixture) = redis_fixture("recovery-pages").await else {
        return;
    };
    let mut expected = HashSet::new();
    for index in 0..33 {
        let claimed = fixture
            .store
            .claim_action(
                claim(
                    TenantId::new(),
                    SessionId::new(),
                    ActionId::new(),
                    format!("action-{index}"),
                    1,
                    placement(1, 1),
                ),
                at(1),
            )
            .await
            .expect("claim");
        expected.insert(claimed.snapshot().action_id().clone());
    }
    for invalid in [0, 257] {
        assert!(matches!(
            fixture
                .store
                .scan_pending_actions(GatewayActionRecoveryCursor::default(), invalid)
                .await,
            Err(GatewayActionCoordinationError::InvalidRecoveryScanLimit)
        ));
    }
    let mut cursor = GatewayActionRecoveryCursor::default();
    let mut seen = HashSet::new();
    for _ in 0..6 {
        let page = fixture
            .store
            .scan_pending_actions(cursor, 7)
            .await
            .expect("page");
        assert!(page.actions().len() <= 7);
        for action in page.actions() {
            assert!(seen.insert(action.action_id().clone()));
        }
        cursor = page.next_cursor().clone();
        if page.is_complete() {
            break;
        }
    }
    assert_eq!(seen, expected);
    assert_eq!(cursor, GatewayActionRecoveryCursor::default());
    assert_eq!(
        fixture
            .store
            .scan_pending_actions(cursor, 7)
            .await
            .expect("wrap")
            .actions()
            .len(),
        7
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_pending_capacity_is_atomic_and_existing_identity_still_replays_when_full() {
    let Some(fixture) = redis_fixture("recovery-capacity").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let original = claim(
        tenant.clone(),
        session.clone(),
        ActionId::new(),
        "original",
        1,
        placement.clone(),
    );
    let first = fixture
        .store
        .claim_action(original.clone(), at(1))
        .await
        .expect("first");
    for index in 1..256 {
        fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("pending-{index}"),
                    1,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("bounded pending");
    }
    let rejected = ActionId::new();
    assert!(matches!(
        fixture
            .store
            .claim_action(
                claim(
                    tenant.clone(),
                    session.clone(),
                    rejected.clone(),
                    "over-limit",
                    1,
                    placement.clone()
                ),
                at(1)
            )
            .await,
        Err(GatewayActionCoordinationError::PendingActionCapacity)
    ));
    assert!(
        fixture
            .store
            .get_effective_action(&tenant, &session, &rejected)
            .await
            .expect("no partial write")
            .is_none()
    );
    assert_eq!(
        fixture
            .store
            .claim_action(original, at(2))
            .await
            .expect("replay while full")
            .snapshot(),
        first.snapshot()
    );
    let loss = SessionLossClaim::new(tenant.clone(), session.clone(), placement, Uuid::now_v7());
    fixture
        .store
        .mark_session_lost(&loss, at(3))
        .await
        .expect("loss marker");
    assert_eq!(
        fixture
            .store
            .materialize_session_loss(&loss, 256, at(4))
            .await
            .expect("bounded materialization"),
        256
    );
    assert!(
        fixture
            .store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .expect("loss removes every pending member")
            .actions()
            .is_empty()
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_corrupt_global_index_rejects_claim_before_any_session_write() {
    let Some(fixture) = redis_fixture("recovery-corrupt-index").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    redis::cmd("SET")
        .arg(format!(
            "{}:gateway-action:recovery-v2:pending",
            fixture.prefix
        ))
        .arg("wrong-type")
        .query_async::<()>(&mut connection)
        .await
        .expect("corrupt isolated index");
    assert!(matches!(
        fixture
            .store
            .claim_action(
                claim(
                    tenant,
                    session,
                    ActionId::new(),
                    "must-not-create",
                    1,
                    placement(1, 1)
                ),
                at(1)
            )
            .await,
        Err(GatewayActionCoordinationError::InvalidRedisResponse)
    ));
    let exists: usize = redis::cmd("EXISTS")
        .arg(format!("{namespace}:session"))
        .arg(format!("{namespace}:actions"))
        .arg(format!("{namespace}:idempotency"))
        .query_async(&mut connection)
        .await
        .expect("no mutation");
    assert_eq!(exists, 0);
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_explicit_offline_migration_resumes_and_preserves_old_receipts_and_events() {
    let Some(fixture) = redis_fixture("recovery-migration").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let not_attempted = fixture
        .store
        .claim_action(
            claim(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "unattempted",
                1,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("unattempted");
    let armed = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "armed",
                2,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("armed claim");
    let armed = fixture
        .store
        .arm_dispatch(
            &tenant,
            &session,
            armed.snapshot().action_id(),
            0,
            &placement,
            DispatchId::new(),
            at(2),
        )
        .await
        .expect("legacy dispatch");
    let terminal = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "terminal",
                3,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("terminal claim");
    let terminal = fixture
        .store
        .cancel_before_dispatch(
            &tenant,
            &session,
            terminal.snapshot().action_id(),
            0,
            &placement,
            at(3),
        )
        .await
        .expect("terminal");
    let event = fixture
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("event")
        .expect("projection");
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    let terminal_raw: String = redis::cmd("HGET")
        .arg(format!("{namespace}:actions"))
        .arg(terminal.action_id().to_string())
        .query_async(&mut connection)
        .await
        .expect("raw terminal");
    redis::pipe()
        .cmd("DEL")
        .arg(format!("{}:gateway-action:recovery-format", fixture.prefix))
        .arg(format!(
            "{}:gateway-action:recovery-v2:pending",
            fixture.prefix
        ))
        .ignore()
        .cmd("HDEL")
        .arg(format!("{namespace}:session"))
        .arg("active_dispatch")
        .ignore()
        .cmd("HDEL")
        .arg(format!("{namespace}:session"))
        .arg(format!("@dispatch:{}", armed.action_id()))
        .ignore()
        .query_async::<()>(&mut connection)
        .await
        .expect("legacy fixture format");
    strip_v3_retention(&fixture).await;
    assert!(matches!(
        RedisGatewayActionStore::connect(fixture.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationRequired)
    ));
    assert!(matches!(
        RedisGatewayActionStore::migrate_recovery_format(fixture.config.clone(), false, Utc::now())
            .await,
        Err(GatewayActionCoordinationError::OfflineMigrationConfirmationRequired)
    ));
    let first =
        RedisGatewayActionStore::migrate_recovery_format(fixture.config.clone(), true, Utc::now())
            .await
            .expect("begin migration");
    assert!(!first.complete());
    assert!(matches!(
        RedisGatewayActionStore::connect(fixture.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
    ));
    let mut complete = false;
    for _ in 0..4096 {
        // A fresh connection per invocation models process interruption after every committed step.
        let progress = RedisGatewayActionStore::migrate_recovery_format(
            fixture.config.clone(),
            true,
            Utc::now(),
        )
        .await
        .expect("resume migration");
        if progress.complete() {
            assert_eq!(progress.migrated_actions(), 2);
            complete = true;
            break;
        }
    }
    assert!(complete, "bounded fixture namespace must finish migration");
    let store = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("new format ready");
    let pending = store
        .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
        .await
        .expect("backfilled discovery");
    assert_eq!(pending.actions().len(), 2);
    let sealed = store
        .get_effective_action(&tenant, &session, not_attempted.snapshot().action_id())
        .await
        .expect("sealed read")
        .expect("existing action");
    let seal = sealed
        .submission_lease()
        .expect("migration assigns exact expired authority");
    assert!(seal.expires_at() < Utc::now());
    let repeated =
        RedisGatewayActionStore::migrate_recovery_format(fixture.config.clone(), true, Utc::now())
            .await
            .expect("idempotent migration");
    assert!(repeated.complete());
    assert_eq!(
        store
            .get_effective_action(&tenant, &session, sealed.action_id())
            .await
            .expect("read")
            .expect("action")
            .submission_lease(),
        Some(seal)
    );
    assert_eq!(
        store
            .get_effective_action(&tenant, &session, armed.action_id())
            .await
            .expect("armed read")
            .as_ref(),
        Some(&armed)
    );
    assert_eq!(
        store
            .peek_event_projection(&tenant, &session)
            .await
            .expect("same event"),
        Some(event)
    );
    let after_raw: String = redis::cmd("HGET")
        .arg(format!("{namespace}:actions"))
        .arg(terminal.action_id().to_string())
        .query_async(&mut connection)
        .await
        .expect("preserved raw terminal");
    assert_eq!(after_raw, terminal_raw);
    let expired = store
        .expire_unattempted_action(
            &tenant,
            &session,
            sealed.action_id(),
            sealed.revision(),
            &placement,
            seal,
            Utc::now(),
        )
        .await
        .expect("sealed legacy proof allows non-delivery");
    assert_eq!(
        expired.terminal().expect("known").detail(),
        TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
    );
    delete_fixture(&fixture).await;
}

async fn remove_recovery_format(fixture: &RedisFixture) {
    strip_v3_retention(fixture).await;
    redis::cmd("DEL")
        .arg(format!("{}:gateway-action:recovery-format", fixture.prefix))
        .arg(format!(
            "{}:gateway-action:recovery-v2:pending",
            fixture.prefix
        ))
        .query_async::<()>(&mut connection(fixture).await)
        .await
        .expect("model legacy namespace before offline migration");
}

async fn migrate_until_discovered(fixture: &RedisFixture) {
    let mut connection = connection(fixture).await;
    for _ in 0..4096 {
        let progress = RedisGatewayActionStore::migrate_recovery_format(
            fixture.config.clone(),
            true,
            Utc::now(),
        )
        .await
        .expect("discover legacy scope");
        assert!(
            !progress.complete(),
            "fixture scope must be discovered first"
        );
        let raw: String = redis::cmd("HGET")
            .arg(format!("{}:gateway-action:recovery-format", fixture.prefix))
            .arg("cursor")
            .query_async(&mut connection)
            .await
            .expect("durable migration cursor");
        let cursor: serde_json::Value = serde_json::from_str(&raw).expect("cursor JSON");
        if cursor["sessions"]
            .as_array()
            .is_some_and(|sessions| !sessions.is_empty())
        {
            assert!(
                cursor["current"].is_null(),
                "stop before selecting or pinning the scope"
            );
            return;
        }
    }
    panic!("bounded fixture discovery did not finish");
}

pub(super) async fn finish_migration(fixture: &RedisFixture) -> RedisGatewayActionStore {
    for _ in 0..4096 {
        let progress = RedisGatewayActionStore::migrate_recovery_format(
            fixture.config.clone(),
            true,
            Utc::now(),
        )
        .await
        .expect("resume offline migration");
        if progress.complete() {
            return RedisGatewayActionStore::connect(fixture.config.clone())
                .await
                .expect("completed format is ready");
        }
    }
    panic!("bounded fixture migration did not finish");
}

#[tokio::test]
async fn redis_migration_discovery_pins_finite_ttl_before_interrupted_next_step() {
    let Some(fixture) = redis_fixture("migration-discovery-ttl").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let mut ids = Vec::new();
    for index in 0..2 {
        let claimed = fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("legacy-{index}"),
                    index,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("legacy unattempted read");
        ids.push(claimed.snapshot().action_id().clone());
    }
    remove_recovery_format(&fixture).await;
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    for suffix in ["actions", "idempotency", "pending"] {
        redis::cmd("PEXPIRE")
            .arg(format!("{namespace}:{suffix}"))
            .arg(3000_u64)
            .query_async::<()>(&mut connection)
            .await
            .expect("legacy finite TTL");
    }
    migrate_until_discovered(&fixture).await;
    for suffix in ["actions", "idempotency", "pending"] {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(format!("{namespace}:{suffix}"))
            .query_async(&mut connection)
            .await
            .expect("pinned at discovery");
        assert_eq!(ttl, -1, "discovery must pin before the next invocation");
    }
    // No migration process exists during this delay; it exceeds the original finite TTL.
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let store = finish_migration(&fixture).await;
    let pending = store
        .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
        .await
        .expect("durable discovery");
    assert_eq!(pending.actions().len(), ids.len());
    for id in ids {
        let row = store
            .get_effective_action(&tenant, &session, &id)
            .await
            .expect("read")
            .expect("legacy obligation survives the interruption");
        assert_eq!(row.delivery(), &ActionDeliveryEvidence::NotAttempted);
        assert!(row.submission_lease().expect("sealed lease").expires_at() < Utc::now());
    }
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_migration_rejects_discovered_payload_disappearance_instead_of_empty_success() {
    let Some(fixture) = redis_fixture("migration-discovery-loss").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "legacy",
                1,
                ActionKind::ReadOnly,
                placement(1, 1),
            ),
            at(1),
        )
        .await
        .expect("legacy read");
    remove_recovery_format(&fixture).await;
    migrate_until_discovered(&fixture).await;
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    redis::cmd("DEL")
        .arg(format!("{namespace}:actions"))
        .arg(format!("{namespace}:idempotency"))
        .arg(format!("{namespace}:pending"))
        .query_async::<()>(&mut connection)
        .await
        .expect("external payload loss fixture");
    let mut rejected = false;
    for _ in 0..3 {
        match RedisGatewayActionStore::migrate_recovery_format(
            fixture.config.clone(),
            true,
            Utc::now(),
        )
        .await
        {
            Err(GatewayActionCoordinationError::InvalidRedisResponse) => {
                rejected = true;
                break;
            }
            Ok(progress) => assert!(
                !progress.complete(),
                "missing discovered data must never become ready"
            ),
            Err(error) => panic!("unexpected migration failure: {error:?}"),
        }
    }
    assert!(rejected, "inventory mismatch must stop the selected scope");
    assert!(matches!(
        RedisGatewayActionStore::connect(fixture.config.clone()).await,
        Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
    ));
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_server_clock_bounds_fresh_claim_and_owned_arm_but_not_existing_replay() {
    let Some(fixture) = redis_fixture("recovery-clock-upper-bound").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let now = Utc::now();
    let fast_clock = now + chrono::Duration::hours(1);
    let invalid_lease = lease(fast_clock, 60_000);
    let invalid_claim = claim_with_kind(
        tenant.clone(),
        session.clone(),
        ActionId::new(),
        "future-clock",
        1,
        ActionKind::ReadOnly,
        placement.clone(),
    )
    .with_submission_lease(invalid_lease.clone());
    assert!(matches!(
        fixture.store.claim_action(invalid_claim, fast_clock).await,
        Err(GatewayActionCoordinationError::InvalidSubmissionLease)
    ));
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    let exists: usize = redis::cmd("EXISTS")
        .arg(format!("{namespace}:session"))
        .arg(format!("{namespace}:actions"))
        .arg(format!("{namespace}:idempotency"))
        .query_async(&mut connection)
        .await
        .expect("rejected before writes");
    assert_eq!(exists, 0);

    let accepted_lease = lease(now, 60_000);
    let valid_claim = claim_with_kind(
        tenant.clone(),
        session.clone(),
        ActionId::new(),
        "accepted",
        2,
        ActionKind::ReadOnly,
        placement.clone(),
    )
    .with_submission_lease(accepted_lease.clone());
    let accepted = fixture
        .store
        .claim_action(valid_claim.clone(), now)
        .await
        .expect("valid claim");
    let replay = fixture
        .store
        .claim_action(valid_claim.with_submission_lease(invalid_lease), fast_clock)
        .await
        .expect("persisted identity precedes fresh lease checks");
    assert_eq!(replay.snapshot(), accepted.snapshot());

    // Model a record admitted by a predecessor with an unchecked future deadline. The exact
    // owner still must pass the authoritative server-time bound at the effect arm boundary.
    let oversized_deadline = GatewayActionSubmissionLease::new(
        *accepted_lease.token(),
        accepted_lease.generation(),
        accepted_lease.expires_at(),
        fast_clock,
    )
    .expect("structural lease");
    let action = accepted.snapshot().action_id();
    let raw: String = redis::cmd("HGET")
        .arg(format!("{namespace}:actions"))
        .arg(action.to_string())
        .query_async(&mut connection)
        .await
        .expect("persisted row");
    let mut row: serde_json::Value = serde_json::from_str(&raw).expect("row JSON");
    row["submission_lease"] = serde_json::to_value(&oversized_deadline).expect("lease JSON");
    let modified = serde_json::to_string(&row).expect("updated fixture JSON");
    redis::cmd("HSET")
        .arg(format!("{namespace}:actions"))
        .arg(action.to_string())
        .arg(&modified)
        .query_async::<()>(&mut connection)
        .await
        .expect("clock-skew fixture row");
    assert!(matches!(
        fixture
            .store
            .arm_dispatch_owned(
                &tenant,
                &session,
                action,
                accepted.snapshot().revision(),
                &placement,
                DispatchId::new(),
                &oversized_deadline,
                now
            )
            .await,
        Err(GatewayActionCoordinationError::InvalidSubmissionLease)
    ));
    let after: String = redis::cmd("HGET")
        .arg(format!("{namespace}:actions"))
        .arg(action.to_string())
        .query_async(&mut connection)
        .await
        .expect("unchanged row");
    assert_eq!(after, modified);
    assert!(
        fixture
            .store
            .peek_event_projection(&tenant, &session)
            .await
            .expect("events")
            .is_none()
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_owned_arm_orders_exact_sequences_above_double_integer_precision() {
    let Some(fixture) = redis_fixture("recovery-exact-large-sequence").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let now = Utc::now();
    let seed = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "seed",
                1,
                ActionKind::ReadOnly,
                placement.clone(),
            ),
            now,
        )
        .await
        .expect("session fence");
    fixture
        .store
        .cancel_before_dispatch(
            &tenant,
            &session,
            seed.snapshot().action_id(),
            0,
            &placement,
            now,
        )
        .await
        .expect("terminal seed");
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    redis::cmd("HSET")
        .arg(format!("{namespace}:session"))
        .arg("last_action_sequence")
        .arg("9007199254740991")
        .query_async::<()>(&mut connection)
        .await
        .expect("large exact sequence");
    let mut ids = [ActionId::new(), ActionId::new()];
    ids.sort_by_key(ToString::to_string);
    let ownership = lease(now, 60_000);
    let first = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ids[1].clone(),
                "first",
                2,
                ActionKind::ReadOnly,
                placement.clone(),
            )
            .with_submission_lease(ownership.clone()),
            now,
        )
        .await
        .expect("first exact action");
    let second = fixture
        .store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ids[0].clone(),
                "second",
                3,
                ActionKind::ReadOnly,
                placement.clone(),
            )
            .with_submission_lease(ownership.clone()),
            now,
        )
        .await
        .expect("second exact action");
    assert_eq!(
        first.snapshot().action_sequence().get(),
        9_007_199_254_740_992
    );
    assert_eq!(
        second.snapshot().action_sequence().get(),
        9_007_199_254_740_993
    );
    let scored: Vec<(String, f64)> = redis::cmd("ZRANGE")
        .arg(format!("{namespace}:pending-v3"))
        .arg(0)
        .arg(-1)
        .arg("WITHSCORES")
        .query_async(&mut connection)
        .await
        .expect("physical score order");
    assert_eq!(
        scored[0].0,
        format!(
            "{:020}|{}",
            first.snapshot().action_sequence().get(),
            first.snapshot().action_id()
        )
    );
    assert_eq!(
        scored[1].0,
        format!(
            "{:020}|{}",
            second.snapshot().action_sequence().get(),
            second.snapshot().action_id()
        )
    );
    assert_eq!(scored[0].1, 0.0);
    assert_eq!(
        scored[0].1, scored[1].1,
        "all exact sequence members use score zero"
    );
    assert!(
        matches!(fixture.store.arm_dispatch_owned(&tenant, &session, second.snapshot().action_id(),
        0, &placement, DispatchId::new(), &ownership, now).await,
        Err(GatewayActionCoordinationError::ActionDispatchInFlight { action_id }) if &action_id == first.snapshot().action_id())
    );
    fixture
        .store
        .arm_dispatch_owned(
            &tenant,
            &session,
            first.snapshot().action_id(),
            0,
            &placement,
            DispatchId::new(),
            &ownership,
            now,
        )
        .await
        .expect("exact oldest can arm");
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_migrated_multiple_armed_reads_keep_the_lane_until_every_dispatch_finishes() {
    let Some(fixture) = redis_fixture("migration-multiple-armed").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let namespace = namespace(&fixture, &tenant, &session);
    let mut connection = connection(&fixture).await;
    let mut armed = Vec::new();
    for index in 0..2 {
        let claimed = fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("armed-{index}"),
                    index,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("legacy claim");
        let dispatch = DispatchId::new();
        let row = fixture
            .store
            .arm_dispatch(
                &tenant,
                &session,
                claimed.snapshot().action_id(),
                0,
                &placement,
                dispatch.clone(),
                at(2),
            )
            .await
            .expect("legacy parallel read arm");
        redis::cmd("HDEL")
            .arg(format!("{namespace}:session"))
            .arg("active_dispatch")
            .arg(format!("@dispatch:{}", row.action_id()))
            .query_async::<()>(&mut connection)
            .await
            .expect("old format had no all-kind lane");
        armed.push((row, dispatch));
    }
    remove_recovery_format(&fixture).await;
    let store = finish_migration(&fixture).await;
    let active: String = redis::cmd("HGET")
        .arg(format!("{namespace}:session"))
        .arg("active_dispatch")
        .query_async(&mut connection)
        .await
        .expect("migrated active lane");
    assert_eq!(
        active,
        armed[0].0.action_id().to_string(),
        "migration chooses exact oldest independently of HSCAN order"
    );
    for (row, _) in &armed {
        let marker: String = redis::cmd("HGET")
            .arg(format!("{namespace}:session"))
            .arg(format!("@dispatch:{}", row.action_id()))
            .query_async(&mut connection)
            .await
            .expect("dispatch marker is in permanent session state");
        assert_eq!(marker, "1");
        assert_eq!(
            store
                .get_effective_action(&tenant, &session, row.action_id())
                .await
                .expect("read")
                .as_ref(),
            Some(row)
        );
    }
    let now = Utc::now();
    let ownership = lease(now, 60_000);
    let fresh = store
        .claim_action(
            claim_with_kind(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "fresh",
                3,
                ActionKind::ReadOnly,
                placement.clone(),
            )
            .with_submission_lease(ownership.clone()),
            now,
        )
        .await
        .expect("fresh pending claim");
    for (row, dispatch) in &armed {
        assert!(
            matches!(store.arm_dispatch_owned(&tenant, &session, fresh.snapshot().action_id(), 0,
            &placement, DispatchId::new(), &ownership, now).await,
            Err(GatewayActionCoordinationError::ActionDispatchInFlight { action_id }) if &action_id == row.action_id())
        );
        store
            .record_worker_result(
                &tenant,
                &session,
                row.action_id(),
                row.revision(),
                &placement,
                dispatch,
                row.action_sequence(),
                BrowserResult::Succeeded(ResultDigest::new([1; 32])),
                None,
                now,
            )
            .await
            .expect("complete one legacy dispatch");
    }
    store
        .arm_dispatch_owned(
            &tenant,
            &session,
            fresh.snapshot().action_id(),
            0,
            &placement,
            DispatchId::new(),
            &ownership,
            now,
        )
        .await
        .expect("lane releases after final legacy completion");
    delete_fixture(&fixture).await;
}

// Construct actual v2 storage from the current public fixture, preserving every payload and
// custody record. The legacy floating-point pending score is intentionally modeled here only.
pub(super) async fn strip_v3_retention(fixture: &RedisFixture) {
    let keys = keys_with_prefix(&fixture.endpoint, &fixture.prefix).await;
    let mut connection = connection(fixture).await;
    for key in keys {
        if let Some(namespace) = key.strip_suffix(":pending-v3") {
            let members: Vec<String> = redis::cmd("ZRANGE")
                .arg(&key)
                .arg(0)
                .arg(-1)
                .query_async(&mut connection)
                .await
                .expect("v3 pending fixture");
            for member in members {
                let (sequence, action) = member.split_once('|').expect("exact pending member");
                let sequence: u64 = sequence.parse().expect("sequence");
                redis::cmd("ZADD")
                    .arg(format!("{namespace}:pending"))
                    .arg(sequence)
                    .arg(action)
                    .query_async::<()>(&mut connection)
                    .await
                    .expect("v2 pending fixture");
            }
        }
        if [
            ":pending-v3",
            ":retention-v1",
            ":retained-v3",
            ":retention-v3",
        ]
        .iter()
        .any(|suffix| key.ends_with(suffix))
        {
            redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut connection)
                .await
                .expect("remove v3-only index");
        }
    }
}
