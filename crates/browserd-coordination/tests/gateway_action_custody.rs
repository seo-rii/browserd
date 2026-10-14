#![allow(clippy::expect_used)]
#[path = "support/gateway_custody_cases.rs"]
mod cases;
use browserd_coordination::{MemoryCoordinationDatabase, MemoryGatewayActionStore, StoreConfig};
fn store() -> MemoryGatewayActionStore {
    MemoryGatewayActionStore::attach(
        MemoryCoordinationDatabase::default(),
        StoreConfig::default(),
    )
}
#[tokio::test]
async fn terminal_and_ack_idempotency() {
    cases::terminal_commit_and_ack_are_independent_and_idempotent(&store()).await;
}
#[tokio::test]
async fn receipt_scope_rejection_is_atomic() {
    cases::invalid_receipt_preserves_pending_action_and_source_journal(&store()).await;
}
#[tokio::test]
async fn resolution_supersedes_old_ack() {
    cases::resolution_supersedes_exact_pending_receipt_and_rejects_old_ack(&store()).await;
}
#[tokio::test]
async fn already_resolved_worker_atomic_commit() {
    cases::already_resolved_worker_receipt_commits_two_events_atomically(&store()).await;
}
#[tokio::test]
async fn unknown_adopts_resolution_exactly() {
    cases::existing_unknown_adopts_worker_resolution_without_overwriting_winner(&store()).await;
}
#[tokio::test]
async fn bounded_discovery_and_late_attachment() {
    cases::bounded_cursor_and_late_receipt_attachment(&store()).await;
}
#[tokio::test]
async fn historical_ack_survives_gateway_only_resolution() {
    cases::gateway_only_resolution_preserves_historical_ack_without_new_obligation(&store()).await;
}
#[tokio::test]
async fn competing_terminal_winner_never_creates_custody() {
    cases::conflicting_winner_never_transfers_custody(&store()).await;
}

#[tokio::test]
async fn memory_reattach_and_blocking_actor_preserve_exact_obligation() {
    use browserd_actions::{KnownFailureReason, TerminalDetail};
    use browserd_coordination::{
        CoordinationActorConfig, GatewayActionBlockingClient, GatewayActionCoordination,
        GatewayCustodyCursor,
    };
    use std::sync::Arc;
    let database = MemoryCoordinationDatabase::default();
    let original = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let action = cases::Action::new(&original).await;
    let receipt = action.receipt(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        None,
    );
    action
        .terminal(&original, receipt.clone(), action.armed.revision())
        .await
        .expect("terminal");
    drop(original);
    let reopened = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    assert_eq!(
        reopened
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("retained")
            .entries()[0]
            .receipt(),
        &receipt
    );
    let client =
        GatewayActionBlockingClient::spawn(Arc::new(reopened), CoordinationActorConfig::default())
            .expect("actor");
    tokio::task::spawn_blocking(move || {
        let page = client
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .expect("actor scan");
        assert_eq!(page.entries()[0].receipt(), &receipt);
        client
            .ack_pending_custody(&page.entries()[0], chrono::Utc::now())
            .expect("actor ack");
        let release = client
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .expect("actor release")
            .entries()[0]
            .clone();
        assert!(release.is_release());
        client
            .complete_custody_release(&release, chrono::Utc::now())
            .expect("actor complete release");
        assert!(
            client
                .scan_pending_custody(GatewayCustodyCursor::default(), 1)
                .expect("actor scan")
                .entries()
                .is_empty()
        );
    })
    .await
    .expect("blocking test");
}
#[tokio::test]
async fn custody_capacity_backpressures_before_acceptance() {
    cases::custody_reserves_bounded_session_capacity_until_ack(&store()).await;
}

struct RetentionClock(std::sync::atomic::AtomicI64);
impl browserd_coordination::GatewayActionRetentionClock for RetentionClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
            .expect("fixture time")
    }
}
async fn retention_page(
    store: &MemoryGatewayActionStore,
) -> browserd_coordination::GatewayActionRetentionPage {
    use browserd_coordination::GatewayActionCoordination;
    store
        .maintain_action_retention(
            browserd_coordination::GatewayActionRetentionCursor::default(),
            32,
        )
        .await
        .expect("notification terminal remains indexed")
}
#[tokio::test]
async fn notifying_terminal_and_resolved_terminal_retain_until_positive_custody_release_then_reclaim()
 {
    use browserd_coordination::GatewayActionCoordination;
    for resolved in [false, true] {
        let clock = std::sync::Arc::new(RetentionClock(std::sync::atomic::AtomicI64::new(
            chrono::Utc::now().timestamp_millis(),
        )));
        let store = store().with_retention_clock(clock.clone());
        let fixture = cases::notifying_terminal_has_no_legacy_events(&store, resolved).await;
        clock.0.store(
            fixture.snapshot.retain_until().timestamp_millis() + 1,
            std::sync::atomic::Ordering::SeqCst,
        );
        let before = retention_page(&store).await;
        assert_eq!(before.examined(), 1);
        assert_eq!(before.reclaimed(), 0);
        assert_eq!(before.deferred(), 1);
        store
            .ack_pending_custody(&fixture.copy, chrono::Utc::now())
            .await
            .expect("positive copy ACK");
        assert_eq!(
            retention_page(&store).await.reclaimed(),
            0,
            "copy ACK still pins final release"
        );
        cases::release_entry(&store, &fixture.copy).await;
        let after = retention_page(&store).await;
        assert_eq!(after.examined(), 1);
        assert_eq!(
            after.reclaimed(),
            1,
            "notification capability proves that no legacy source-event watermark is needed"
        );
        assert!(
            store
                .get_effective_action(
                    &fixture.action.tenant,
                    &fixture.action.session,
                    &fixture.action.action
                )
                .await
                .expect("reclaimed")
                .is_none()
        );
    }
}
#[tokio::test]
async fn notifying_resolution_keeps_prior_legacy_event_ack_as_a_retention_requirement() {
    use browserd_coordination::GatewayActionCoordination;
    let clock = std::sync::Arc::new(RetentionClock(std::sync::atomic::AtomicI64::new(
        chrono::Utc::now().timestamp_millis(),
    )));
    let store = store().with_retention_clock(clock.clone());
    let fixture = cases::notifying_resolution_preserves_old_legacy_event(&store).await;
    clock.0.store(
        fixture.snapshot.retain_until().timestamp_millis() + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    store
        .ack_pending_custody(&fixture.copy, chrono::Utc::now())
        .await
        .expect("copy ACK");
    cases::release_entry(&store, &fixture.copy).await;
    assert_eq!(
        retention_page(&store).await.reclaimed(),
        0,
        "the original legacy projection is still pending"
    );
    assert_eq!(
        fixture.action.events(&store).await,
        vec![fixture.legacy_revision.expect("legacy revision")]
    );
    assert_eq!(retention_page(&store).await.reclaimed(), 1);
}

#[tokio::test]
async fn gateway_only_resolution_after_notifying_terminal_waits_for_its_typed_event_ack() {
    let clock = std::sync::Arc::new(RetentionClock(std::sync::atomic::AtomicI64::new(
        chrono::Utc::now().timestamp_millis(),
    )));
    let store = store().with_retention_clock(clock.clone());
    let fixture =
        cases::gateway_only_resolution_of_notifying_terminal_emits_its_own_typed_event(&store)
            .await;
    clock.0.store(
        fixture.snapshot.retain_until().timestamp_millis() + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let before = retention_page(&store).await;
    assert_eq!(before.examined(), 1);
    assert_eq!(
        before.reclaimed(),
        0,
        "Gateway-owned resolution still awaits its event ACK"
    );
    assert_eq!(
        fixture.action.events(&store).await,
        vec![
            fixture
                .legacy_revision
                .expect("Gateway projection revision")
        ]
    );
    assert_eq!(retention_page(&store).await.reclaimed(), 1);
}

#[tokio::test]
async fn replacement_worker_notifying_resolution_creates_no_gateway_projection() {
    cases::replacement_notifying_resolution_never_duplicates_the_worker_event(&store()).await;
}
