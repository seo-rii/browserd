use super::*;
#[path = "gateway_custody_cases.rs"]
pub(super) mod cases;
#[tokio::test]
async fn redis_custody_terminal_and_ack_idempotency() {
    if let Some(f) = redis_fixture("custody-idempotency").await {
        cases::terminal_commit_and_ack_are_independent_and_idempotent(f.store.as_ref()).await;
    }
}
#[tokio::test]
async fn redis_custody_receipt_scope_rejection_is_atomic() {
    if let Some(f) = redis_fixture("custody-scope").await {
        cases::invalid_receipt_preserves_pending_action_and_source_journal(f.store.as_ref()).await;
    }
}
#[tokio::test]
async fn redis_custody_resolution_supersedes_old_ack() {
    if let Some(f) = redis_fixture("custody-resolution").await {
        cases::resolution_supersedes_exact_pending_receipt_and_rejects_old_ack(f.store.as_ref())
            .await;
    }
}
#[tokio::test]
async fn redis_custody_already_resolved_worker_atomic_commit() {
    if let Some(f) = redis_fixture("custody-resolved-first").await {
        cases::already_resolved_worker_receipt_commits_two_events_atomically(f.store.as_ref())
            .await;
    }
}
#[tokio::test]
async fn redis_custody_unknown_adopts_resolution_exactly() {
    if let Some(f) = redis_fixture("custody-resolved-later").await {
        cases::existing_unknown_adopts_worker_resolution_without_overwriting_winner(
            f.store.as_ref(),
        )
        .await;
    }
}
#[tokio::test]
async fn redis_custody_bounded_discovery_and_late_attachment() {
    if let Some(f) = redis_fixture("custody-cursor").await {
        cases::bounded_cursor_and_late_receipt_attachment(f.store.as_ref()).await;
    }
}

#[tokio::test]
async fn redis_custody_restart_pins_payload_and_idempotency_until_exact_ack() {
    let Some(f) = redis_fixture("custody-retention").await else {
        return;
    };
    let action = cases::Action::new(f.store.as_ref()).await;
    let receipt = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    action
        .terminal(f.store.as_ref(), receipt.clone(), action.armed.revision())
        .await
        .expect("terminal");
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart");
    let entry = reopened
        .scan_pending_custody(browserd_coordination::GatewayCustodyCursor::default(), 1)
        .await
        .expect("rediscover")
        .entries()[0]
        .clone();
    assert_eq!(entry.receipt(), &receipt);
    let mut connection = redis::Client::open(f.endpoint.as_str())
        .expect("endpoint")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    for suffix in ["actions", "idempotency", "custody-v1"] {
        let key = format!(
            "{}:gateway-action:{{{}:{}}}:{suffix}",
            f.prefix, action.tenant, action.session
        );
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("ttl");
        assert_eq!(ttl, -1, "pending custody survives TTL: {suffix}");
    }
    action.events(&reopened).await;
    assert_eq!(
        reopened
            .scan_pending_custody(browserd_coordination::GatewayCustodyCursor::default(), 1)
            .await
            .expect("independent")
            .entries(),
        std::slice::from_ref(&entry)
    );
    reopened
        .ack_pending_custody(&entry, Utc::now())
        .await
        .expect("ack");
    reopened
        .ack_pending_custody(&entry, Utc::now())
        .await
        .expect("ack retry");
    for suffix in ["actions", "idempotency", "custody-v1"] {
        let key = format!(
            "{}:gateway-action:{{{}:{}}}:{suffix}",
            f.prefix, action.tenant, action.session
        );
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("release ttl");
        assert_eq!(ttl, -1, "copy ACK must retain TTL pin until final release");
    }
    let after_ack_restart = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart after copy ACK");
    cases::release_entry(&after_ack_restart, &entry).await;
    for suffix in ["actions", "idempotency"] {
        let key = format!(
            "{}:gateway-action:{{{}:{}}}:{suffix}",
            f.prefix, action.tenant, action.session
        );
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("ttl");
        assert_eq!(
            ttl, -1,
            "confirmed transfer permits individual GC, not hash TTL"
        );
    }
}
#[tokio::test]
async fn redis_custody_historical_ack_survives_gateway_only_resolution() {
    if let Some(f) = redis_fixture("custody-historical").await {
        cases::gateway_only_resolution_preserves_historical_ack_without_new_obligation(
            f.store.as_ref(),
        )
        .await;
    }
}
#[tokio::test]
async fn redis_custody_competing_terminal_winner_never_creates_custody() {
    if let Some(f) = redis_fixture("custody-competing").await {
        cases::conflicting_winner_never_transfers_custody(f.store.as_ref()).await;
    }
}
#[tokio::test]
async fn redis_custody_capacity_backpressures_before_acceptance() {
    if let Some(f) = redis_fixture("custody-capacity").await {
        cases::custody_reserves_bounded_session_capacity_until_ack(f.store.as_ref()).await;
    }
}

#[tokio::test]
async fn redis_notifying_terminal_and_resolved_terminal_keep_zero_event_retention_metadata_then_reclaim()
 {
    for resolved in [false, true] {
        let Some(f) = redis_fixture(if resolved {
            "notifying-resolved-retention"
        } else {
            "notifying-terminal-retention"
        })
        .await
        else {
            return;
        };
        let fixture =
            cases::notifying_terminal_has_no_legacy_events(f.store.as_ref(), resolved).await;
        super::redis_action_retention::set_deadline(&f, &fixture.snapshot, 1).await;
        let reopened = RedisGatewayActionStore::connect(f.config.clone())
            .await
            .expect("restart preserves capability and zero source sequence");
        let before = reopened
            .maintain_action_retention(
                browserd_coordination::GatewayActionRetentionCursor::default(),
                32,
            )
            .await
            .expect("indexed even with no legacy event");
        assert_eq!(before.examined(), 1);
        assert_eq!(before.reclaimed(), 0);
        assert_eq!(before.deferred(), 1);
        reopened
            .ack_pending_custody(&fixture.copy, Utc::now())
            .await
            .expect("copy ACK");
        assert_eq!(
            reopened
                .maintain_action_retention(
                    browserd_coordination::GatewayActionRetentionCursor::default(),
                    32
                )
                .await
                .expect("release still pending")
                .reclaimed(),
            0
        );
        cases::release_entry(&reopened, &fixture.copy).await;
        let after = reopened
            .maintain_action_retention(
                browserd_coordination::GatewayActionRetentionCursor::default(),
                32,
            )
            .await
            .expect("positive release");
        assert_eq!(after.examined(), 1);
        assert_eq!(
            after.reclaimed(),
            1,
            "validated notification capability allows zero-event terminal GC"
        );
        assert!(
            reopened
                .get_effective_action(
                    &fixture.action.tenant,
                    &fixture.action.session,
                    &fixture.action.action
                )
                .await
                .expect("individual GC")
                .is_none()
        );
    }
}
#[tokio::test]
async fn redis_notifying_resolution_preserves_prior_legacy_sequence_even_without_new_event() {
    let Some(f) = redis_fixture("notifying-legacy-source-watermark").await else {
        return;
    };
    let fixture = cases::notifying_resolution_preserves_old_legacy_event(f.store.as_ref()).await;
    super::redis_action_retention::set_deadline(&f, &fixture.snapshot, 1).await;
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart");
    let persisted = reopened
        .get_effective_action(
            &fixture.action.tenant,
            &fixture.action.session,
            &fixture.action.action,
        )
        .await
        .expect("row")
        .expect("persisted action");
    assert_eq!(persisted.last_source_event_sequence(), Some(1));
    let custody = reopened
        .scan_pending_custody(browserd_coordination::GatewayCustodyCursor::default(), 32)
        .await
        .expect("persisted source capability");
    assert_eq!(custody.entries()[0].receipt(), fixture.copy.receipt());
    assert!(
        custody.entries()[0]
            .receipt()
            .notification_source()
            .is_some()
    );
    reopened
        .ack_pending_custody(&fixture.copy, Utc::now())
        .await
        .expect("copy ACK");
    cases::release_entry(&reopened, &fixture.copy).await;
    assert_eq!(
        reopened
            .maintain_action_retention(
                browserd_coordination::GatewayActionRetentionCursor::default(),
                32
            )
            .await
            .expect("legacy event pins GC")
            .reclaimed(),
        0
    );
    assert_eq!(
        fixture.action.events(&reopened).await,
        vec![fixture.legacy_revision.expect("legacy revision")]
    );
    assert_eq!(
        reopened
            .maintain_action_retention(
                browserd_coordination::GatewayActionRetentionCursor::default(),
                32
            )
            .await
            .expect("legacy ACK + custody release")
            .reclaimed(),
        1
    );
}

#[tokio::test]
async fn redis_gateway_only_resolution_after_notifying_terminal_waits_for_its_typed_event_ack() {
    let Some(f) = redis_fixture("notifying-gateway-resolution-source").await else {
        return;
    };
    let fixture = cases::gateway_only_resolution_of_notifying_terminal_emits_its_own_typed_event(
        f.store.as_ref(),
    )
    .await;
    super::redis_action_retention::set_deadline(&f, &fixture.snapshot, 1).await;
    let reopened = RedisGatewayActionStore::connect(f.config.clone())
        .await
        .expect("restart preserves Gateway-owned projection watermark");
    let before = reopened
        .maintain_action_retention(
            browserd_coordination::GatewayActionRetentionCursor::default(),
            32,
        )
        .await
        .expect("retention indexed");
    assert_eq!(before.examined(), 1);
    assert_eq!(
        before.reclaimed(),
        0,
        "Gateway-owned resolution still awaits its event ACK"
    );
    assert_eq!(
        fixture.action.events(&reopened).await,
        vec![
            fixture
                .legacy_revision
                .expect("Gateway projection revision")
        ]
    );
    assert_eq!(
        reopened
            .maintain_action_retention(
                browserd_coordination::GatewayActionRetentionCursor::default(),
                32,
            )
            .await
            .expect("typed event ACK permits GC")
            .reclaimed(),
        1
    );
}

#[tokio::test]
async fn redis_replacement_worker_notifying_resolution_creates_no_gateway_projection() {
    if let Some(f) = redis_fixture("notifying-worker-resolution-source").await {
        cases::replacement_notifying_resolution_never_duplicates_the_worker_event(f.store.as_ref())
            .await;
    }
}
