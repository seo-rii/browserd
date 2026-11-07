use super::*;
use browserd_coordination::GatewayActionRecoveryCursor;

async fn connection(fixture: &RedisFixture) -> redis::aio::MultiplexedConnection {
    redis::Client::open(fixture.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("fixture connection")
}

fn scope_key(
    fixture: &RedisFixture,
    tenant: &TenantId,
    session: &SessionId,
    suffix: &str,
) -> String {
    format!(
        "{}:gateway-action:{{{tenant}:{session}}}:{suffix}",
        fixture.prefix
    )
}

#[tokio::test]
async fn redis_concurrent_loss_proposals_adopt_one_canonical_identity_and_one_event() {
    let Some(fixture) = redis_fixture("canonical-loss-race").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();
    let mut proposed = HashSet::new();
    for _ in 0..16 {
        let loss_id = Uuid::now_v7();
        proposed.insert(loss_id);
        let claim =
            SessionLossClaim::new(tenant.clone(), session.clone(), placement.clone(), loss_id);
        let store = Arc::clone(&fixture.store);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .ensure_session_lost(&claim, at(2))
                .await
                .expect("canonical receipt")
        }));
    }
    let mut canonical = None;
    let mut recorded = 0;
    for task in tasks {
        let receipt = task.await.expect("concurrent producer");
        recorded += usize::from(receipt.outcome() == SessionLossOutcome::Recorded);
        assert_eq!(receipt.claim().tenant_id(), &tenant);
        assert_eq!(receipt.claim().session_id(), &session);
        assert_eq!(receipt.claim().placement(), &placement);
        assert!(proposed.contains(receipt.claim().loss_id()));
        if let Some(claim) = &canonical {
            assert_eq!(receipt.claim(), claim);
        } else {
            canonical = Some(receipt.into_claim());
        }
    }
    assert_eq!(recorded, 1);
    let projection = fixture
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("single lost projection");
    assert_eq!(projection.sequence(), 1);
    assert_eq!(
        projection.append(),
        &OutboxAppend::session_lost(tenant.clone(), session.clone(), 1)
    );
    fixture
        .store
        .ack_event_projection(&projection)
        .await
        .expect("sink acknowledgement");
    let reopened = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("restart");
    let retry = SessionLossClaim::new(tenant.clone(), session.clone(), placement, Uuid::now_v7());
    let receipt = reopened
        .ensure_session_lost(&retry, at(3))
        .await
        .expect("restart retry");
    assert_eq!(Some(receipt.claim()), canonical.as_ref());
    assert_eq!(receipt.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert!(
        reopened
            .peek_event_projection(&tenant, &session)
            .await
            .expect("no duplicate")
            .is_none()
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_no_action_loss_strict_replay_and_response_retry_survive_event_ack_and_restart() {
    let Some(fixture) = redis_fixture("canonical-loss-empty").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let first = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    assert_eq!(
        fixture
            .store
            .mark_session_lost(&first, at(1))
            .await
            .expect("initial empty loss"),
        SessionLossOutcome::Recorded
    );
    assert_eq!(
        fixture
            .store
            .mark_session_lost(&first, at(2))
            .await
            .expect("strict same-ID retry"),
        SessionLossOutcome::AlreadyRecorded
    );
    let replacement = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    assert_eq!(
        fixture.store.mark_session_lost(&replacement, at(2)).await,
        Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
    );
    assert_eq!(
        fixture
            .store
            .materialize_session_loss(&first, 1, at(2))
            .await
            .expect("empty materialization"),
        0
    );
    let projection = fixture
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("loss event");
    assert_eq!(projection.sequence(), 1);
    fixture
        .store
        .ack_event_projection(&projection)
        .await
        .expect("ack");
    let reopened = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("restart");
    let adopted = reopened
        .ensure_session_lost(&replacement, at(3))
        .await
        .expect("canonical identity remains after ACK");
    assert_eq!(adopted.claim(), &first);
    assert_eq!(adopted.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert_eq!(
        reopened
            .mark_session_lost(&first, at(3))
            .await
            .expect("strict after ACK"),
        SessionLossOutcome::AlreadyRecorded
    );
    assert_eq!(
        reopened
            .materialize_session_loss(adopted.claim(), 1, at(3))
            .await
            .expect("empty after ACK"),
        0
    );
    assert!(
        reopened
            .peek_event_projection(&tenant, &session)
            .await
            .expect("no duplicate")
            .is_none()
    );
    let absent = ActionId::new();
    assert_eq!(
        reopened
            .get_effective_action(&tenant, &session, &absent)
            .await
            .expect("an empty loss tombstone has no action"),
        None
    );
    assert_eq!(
        reopened
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    absent,
                    "after-loss",
                    1,
                    ActionKind::ReadOnly,
                    placement.clone()
                ),
                at(3)
            )
            .await,
        Err(GatewayActionCoordinationError::SessionLost)
    );
    let mut connection = connection(&fixture).await;
    let payload_keys: usize = redis::cmd("EXISTS")
        .arg(scope_key(&fixture, &tenant, &session, "actions"))
        .arg(scope_key(&fixture, &tenant, &session, "idempotency"))
        .arg(scope_key(&fixture, &tenant, &session, "pending-v3"))
        .query_async(&mut connection)
        .await
        .expect("empty scope payload");
    assert_eq!(payload_keys, 0);
    let ttl: i64 = redis::cmd("PTTL")
        .arg(scope_key(&fixture, &tenant, &session, "session"))
        .query_async(&mut connection)
        .await
        .expect("permanent authority");
    assert_eq!(ttl, -1);

    // Commit a separate loss, deliberately discard its reply, then retry from a fresh connection
    // with a different proposal. No client-side remembered UUID is necessary for convergence.
    let ambiguous_session = SessionId::new();
    let committed = SessionLossClaim::new(
        tenant.clone(),
        ambiguous_session.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    let _ = reopened
        .ensure_session_lost(&committed, at(4))
        .await
        .expect("commit whose receipt is discarded");
    let after_reply_loss = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("new producer");
    let retry = SessionLossClaim::new(
        tenant.clone(),
        ambiguous_session.clone(),
        placement,
        Uuid::now_v7(),
    );
    let receipt = after_reply_loss
        .ensure_session_lost(&retry, at(5))
        .await
        .expect("recover committed identity");
    assert_eq!(receipt.claim(), &committed);
    assert_eq!(receipt.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert_eq!(
        after_reply_loss
            .peek_event_projection(&tenant, &ambiguous_session)
            .await
            .expect("peek")
            .expect("event")
            .sequence(),
        1
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_canonical_loss_rejects_every_changed_fence_and_keeps_tenant_session_scopes_separate()
{
    let Some(fixture) = redis_fixture("canonical-loss-scope").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let original_placement = placement(1, 1);
    let original = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        original_placement.clone(),
        Uuid::now_v7(),
    );
    fixture
        .store
        .ensure_session_lost(&original, at(1))
        .await
        .expect("initial authority");
    for (worker, worker_epoch, shard_id, shard_epoch, revision) in [
        ("other-worker", 1, 17, 3, 1),
        ("redis-gateway-action-worker", 2, 17, 3, 1),
        ("redis-gateway-action-worker", 1, 18, 3, 1),
        ("redis-gateway-action-worker", 1, 17, 4, 1),
        ("redis-gateway-action-worker", 1, 17, 3, 2),
    ] {
        let changed = GatewayActionPlacement::new(
            DirectoryFence::new(
                WorkerId::new(worker).expect("worker"),
                worker_epoch,
                shard_id,
                shard_epoch,
            )
            .expect("fence"),
            revision,
        )
        .expect("placement");
        let proposed =
            SessionLossClaim::new(tenant.clone(), session.clone(), changed, Uuid::now_v7());
        assert_eq!(
            fixture.store.ensure_session_lost(&proposed, at(2)).await,
            Err(GatewayActionCoordinationError::PlacementMismatch)
        );
        assert_eq!(
            fixture.store.mark_session_lost(&proposed, at(2)).await,
            Err(GatewayActionCoordinationError::PlacementMismatch)
        );
    }
    for (other_tenant, other_session) in [
        (TenantId::new(), session.clone()),
        (tenant.clone(), SessionId::new()),
    ] {
        let isolated = SessionLossClaim::new(
            other_tenant.clone(),
            other_session.clone(),
            original_placement.clone(),
            Uuid::now_v7(),
        );
        let receipt = fixture
            .store
            .ensure_session_lost(&isolated, at(2))
            .await
            .expect("independent exact scope");
        assert_eq!(receipt.claim(), &isolated);
        assert_eq!(receipt.outcome(), SessionLossOutcome::Recorded);
        assert_ne!(receipt.claim().loss_id(), original.loss_id());
        assert_eq!(
            fixture
                .store
                .peek_event_projection(&other_tenant, &other_session)
                .await
                .expect("scope event")
                .expect("projection")
                .sequence(),
            1
        );
    }
    let invalid = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        original_placement,
        Uuid::new_v4(),
    );
    assert_eq!(
        fixture.store.ensure_session_lost(&invalid, at(2)).await,
        Err(GatewayActionCoordinationError::InvalidSessionLossId)
    );
    assert_eq!(
        fixture
            .store
            .ensure_session_lost(&original, at(3))
            .await
            .expect("original unchanged")
            .claim(),
        &original
    );
    assert_eq!(
        fixture
            .store
            .peek_event_projection(&tenant, &session)
            .await
            .expect("original event")
            .expect("projection")
            .sequence(),
        1
    );
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_no_action_loss_exception_never_hides_a_missing_active_obligation() {
    let Some(fixture) = redis_fixture("canonical-loss-missing-obligation").await else {
        return;
    };
    let tenant = TenantId::new();
    let mut connection = connection(&fixture).await;
    for obligation in [
        "active_mutation",
        "unresolved_mutation",
        "active_dispatch",
        "pending",
    ] {
        let session = SessionId::new();
        let placement = placement(1, 1);
        let first = SessionLossClaim::new(
            tenant.clone(),
            session.clone(),
            placement.clone(),
            Uuid::now_v7(),
        );
        fixture
            .store
            .ensure_session_lost(&first, at(1))
            .await
            .expect("legitimate empty loss");
        let action = ActionId::new();
        if obligation == "pending" {
            redis::cmd("ZADD")
                .arg(scope_key(&fixture, &tenant, &session, "pending-v3"))
                .arg(1)
                .arg(action.to_string())
                .query_async::<()>(&mut connection)
                .await
                .expect("orphan pending fixture");
        } else {
            redis::cmd("HSET")
                .arg(scope_key(&fixture, &tenant, &session, "session"))
                .arg(obligation)
                .arg(action.to_string())
                .query_async::<()>(&mut connection)
                .await
                .expect("orphan active fixture");
        }
        let retry =
            SessionLossClaim::new(tenant.clone(), session.clone(), placement, Uuid::now_v7());
        assert_eq!(
            fixture.store.ensure_session_lost(&retry, at(2)).await,
            Err(GatewayActionCoordinationError::InvalidRedisResponse),
            "{obligation}"
        );
        assert_eq!(
            fixture.store.mark_session_lost(&first, at(2)).await,
            Err(GatewayActionCoordinationError::InvalidRedisResponse),
            "{obligation}"
        );
        assert_eq!(
            fixture
                .store
                .get_effective_action(&tenant, &session, &action)
                .await,
            Err(GatewayActionCoordinationError::InvalidRedisResponse),
            "{obligation}"
        );
        assert_eq!(
            fixture
                .store
                .claim_action(
                    claim_with_kind(
                        tenant.clone(),
                        session.clone(),
                        ActionId::new(),
                        "after-corruption",
                        1,
                        ActionKind::ReadOnly,
                        first.placement().clone()
                    ),
                    at(2)
                )
                .await,
            Err(GatewayActionCoordinationError::InvalidRedisResponse),
            "{obligation}"
        );
        let persisted: String = redis::cmd("HGET")
            .arg(scope_key(&fixture, &tenant, &session, "session"))
            .arg("loss_id")
            .query_async(&mut connection)
            .await
            .expect("unmodified canonical ID");
        assert_eq!(persisted, first.loss_id().to_string());
        assert_eq!(
            fixture
                .store
                .peek_event_projection(&tenant, &session)
                .await
                .expect("unchanged event")
                .expect("projection")
                .sequence(),
            1
        );
    }
    delete_fixture(&fixture).await;
}

#[tokio::test]
async fn redis_canonical_loss_materializes_bounded_batches_and_releases_pending_discovery() {
    let Some(fixture) = redis_fixture("canonical-loss-bounded").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement(1, 1);
    let mut actions = Vec::new();
    for index in 0..5 {
        let claimed = fixture
            .store
            .claim_action(
                claim_with_kind(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("pending-{index}"),
                    index,
                    ActionKind::ReadOnly,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("pending claim");
        actions.push(claimed.into_snapshot());
    }
    let proposed = SessionLossClaim::new(
        tenant.clone(),
        session.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    let canonical = fixture
        .store
        .ensure_session_lost(&proposed, at(2))
        .await
        .expect("loss")
        .into_claim();
    let second = SessionLossClaim::new(tenant.clone(), session.clone(), placement, Uuid::now_v7());
    assert_eq!(
        fixture
            .store
            .materialize_session_loss(&second, 2, at(3))
            .await,
        Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
    );
    let adopted = fixture
        .store
        .ensure_session_lost(&second, at(3))
        .await
        .expect("adopt existing ID");
    assert_eq!(adopted.claim(), &canonical);
    let initial = fixture
        .store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("lost event");
    fixture
        .store
        .ack_event_projection(&initial)
        .await
        .expect("ACK initial event");
    let reopened = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("restart after loss event ACK");
    let mut projected = 1;
    for (expected_batch, remaining) in [(2, 3), (2, 1), (1, 0)] {
        assert_eq!(
            reopened
                .materialize_session_loss(&canonical, 2, at(4))
                .await
                .expect("bounded batch"),
            expected_batch
        );
        let pending = reopened
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .expect("pending discovery");
        assert_eq!(pending.actions().len(), remaining);
        for _ in 0..expected_batch {
            let event = reopened
                .peek_event_projection(&tenant, &session)
                .await
                .expect("action event")
                .expect("one event per materialized action");
            projected += 1;
            assert_eq!(event.sequence(), projected);
            reopened
                .ack_event_projection(&event)
                .await
                .expect("ACK action projection");
        }
        assert!(
            reopened
                .peek_event_projection(&tenant, &session)
                .await
                .expect("bounded batch has no extra events")
                .is_none()
        );
        assert_eq!(
            reopened
                .ensure_session_lost(&second, at(5))
                .await
                .expect("canonical after batch")
                .claim(),
            &canonical
        );
    }
    assert_eq!(
        projected, 6,
        "one session loss and one terminal projection per action"
    );
    assert_eq!(
        reopened
            .materialize_session_loss(&canonical, 2, at(5))
            .await
            .expect("all materialized"),
        0
    );
    for action in actions {
        assert!(
            reopened
                .get_effective_action(&tenant, &session, action.action_id())
                .await
                .expect("read effective terminal")
                .expect("durable action")
                .terminal()
                .is_some()
        );
    }
    let mut connection = connection(&fixture).await;
    let marker: Option<String> = redis::cmd("HGET")
        .arg(scope_key(&fixture, &tenant, &session, "session"))
        .arg("event_loss_claim")
        .query_async(&mut connection)
        .await
        .expect("materialization marker");
    assert!(marker.is_none());
    let saved_id: String = redis::cmd("HGET")
        .arg(scope_key(&fixture, &tenant, &session, "session"))
        .arg("loss_id")
        .query_async(&mut connection)
        .await
        .expect("canonical authority survives");
    assert_eq!(saved_id, canonical.loss_id().to_string());
    assert!(
        reopened
            .peek_event_projection(&tenant, &session)
            .await
            .expect("no replay events")
            .is_none()
    );
    delete_fixture(&fixture).await;
}
