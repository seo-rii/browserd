#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use browserd_coordination::{
    DirectoryEntry, DirectoryFence, DirectoryKey, DirectoryMutation, DirectorySnapshot,
    EphemeralCoordinationError, EphemeralCoordinationStore, ManualCoordinationClock,
    MemoryEphemeralCoordinationStore, OneTimeCapability, OneTimeConsume, OneTimeIssue,
};
use browserd_core::{SessionId, TenantId, WorkerId};
use tokio::sync::Barrier;

fn directory_entry(worker_epoch: u64, placement_version: u64) -> DirectoryEntry {
    DirectoryEntry::new(
        DirectoryKey::new(TenantId::new(), SessionId::new()),
        DirectoryFence::new(
            WorkerId::new("ephemeral-conformance-worker").expect("worker ID should validate"),
            worker_epoch,
            placement_version,
            3,
        )
        .expect("directory fence should validate"),
        "worker-rpc://ephemeral-conformance",
    )
    .expect("directory entry should validate")
}

#[tokio::test]
async fn stale_worker_epoch_and_placement_version_cannot_alias_a_live_directory() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock);
    let current = directory_entry(9, 12);
    assert_eq!(
        store
            .register_directory(current.clone(), Duration::from_secs(30))
            .await
            .expect("current registration should work"),
        DirectoryMutation::Applied
    );

    let stale_epoch = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(current.fence().worker_id().clone(), 8, 13, 3)
            .expect("stale epoch fixture should validate"),
        "worker-rpc://stale-epoch",
    )
    .expect("stale entry should validate");
    let stale_placement = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(current.fence().worker_id().clone(), 9, 11, 3)
            .expect("stale placement fixture should validate"),
        "worker-rpc://stale-placement",
    )
    .expect("stale entry should validate");

    assert_eq!(
        store
            .register_directory(stale_epoch, Duration::from_secs(30))
            .await
            .expect("stale registration should return a fenced result"),
        DirectoryMutation::FenceMismatch
    );
    assert_eq!(
        store
            .register_directory(stale_placement, Duration::from_secs(30))
            .await
            .expect("stale registration should return a fenced result"),
        DirectoryMutation::FenceMismatch
    );
    assert_eq!(
        store
            .resolve_directory(current.key())
            .await
            .expect("directory lookup should work")
            .expect("current directory should remain live")
            .entry(),
        &current
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_exact_directory_mutations_have_one_cas_winner() {
    let clock = ManualCoordinationClock::new();
    let store = Arc::new(MemoryEphemeralCoordinationStore::new(clock));
    let entry = directory_entry(4, 7);
    store
        .register_directory(entry.clone(), Duration::from_secs(30))
        .await
        .expect("registration should work");
    let snapshot = store
        .resolve_directory(entry.key())
        .await
        .expect("lookup should work")
        .expect("directory should exist");
    let barrier = Arc::new(Barrier::new(33));
    let mut mutations = Vec::new();
    for index in 0..32 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let snapshot = snapshot.clone();
        mutations.push(tokio::spawn(async move {
            barrier.wait().await;
            if index % 2 == 0 {
                store
                    .renew_directory(&snapshot, Duration::from_secs(60))
                    .await
            } else {
                store.remove_directory(&snapshot).await
            }
        }));
    }
    barrier.wait().await;

    let mut applied = 0;
    for mutation in mutations {
        if mutation
            .await
            .expect("mutation task should join")
            .expect("mutation should return a CAS result")
            == DirectoryMutation::Applied
        {
            applied += 1;
        }
    }
    assert_eq!(applied, 1, "one immutable snapshot may win CAS only once");
}

#[tokio::test]
async fn equal_directory_version_is_idempotent_only_for_the_exact_binding() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let current = directory_entry(7, 9);
    assert_eq!(
        store
            .register_directory(current.clone(), Duration::from_secs(30))
            .await
            .expect("initial registration should work"),
        DirectoryMutation::Applied
    );
    assert_eq!(
        store
            .register_directory(current.clone(), Duration::from_secs(30))
            .await
            .expect("exact retry should work"),
        DirectoryMutation::AlreadyApplied
    );

    let other_worker = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(
            WorkerId::new("different-worker").expect("worker should validate"),
            7,
            9,
            3,
        )
        .expect("fence should validate"),
        current.endpoint(),
    )
    .expect("entry should validate");
    let other_endpoint = DirectoryEntry::new(
        current.key().clone(),
        current.fence().clone(),
        "worker-rpc://different-endpoint",
    )
    .expect("entry should validate");
    assert_eq!(
        store
            .register_directory(other_worker, Duration::from_secs(30))
            .await
            .expect("conflict should be explicit"),
        DirectoryMutation::FenceMismatch
    );
    assert_eq!(
        store
            .register_directory(other_endpoint, Duration::from_secs(30))
            .await
            .expect("conflict should be explicit"),
        DirectoryMutation::FenceMismatch
    );
}

#[tokio::test]
async fn higher_placement_version_atomically_transfers_the_directory() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let current = directory_entry(7, 9);
    store
        .register_directory(current.clone(), Duration::from_secs(30))
        .await
        .expect("initial registration should work");
    let old_snapshot = store
        .resolve_directory(current.key())
        .await
        .expect("lookup should work")
        .expect("current directory should exist");
    let transferred = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(
            WorkerId::new("replacement-worker").expect("worker should validate"),
            1,
            10,
            3,
        )
        .expect("fence should validate"),
        "worker-rpc://replacement",
    )
    .expect("entry should validate");
    assert_eq!(
        store
            .register_directory(transferred.clone(), Duration::from_secs(30))
            .await
            .expect("higher placement should transfer"),
        DirectoryMutation::Applied
    );
    assert_eq!(
        store
            .remove_directory(&old_snapshot)
            .await
            .expect("old owner removal should be fenced"),
        DirectoryMutation::CasMismatch
    );
    assert_eq!(
        store
            .resolve_directory(current.key())
            .await
            .expect("lookup should work")
            .expect("replacement should remain")
            .entry(),
        &transferred
    );
}

#[tokio::test]
async fn same_worker_epoch_and_session_incarnation_rollbacks_are_fenced() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let current = directory_entry(7, 9);
    store
        .register_directory(current.clone(), Duration::from_secs(30))
        .await
        .expect("initial registration should work");

    let stale_worker_epoch = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(current.fence().worker_id().clone(), 6, 10, 3)
            .expect("stale worker epoch fixture should validate"),
        "worker-rpc://stale-worker-epoch",
    )
    .expect("entry should validate");
    let stale_incarnation = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(
            WorkerId::new("replacement-worker").expect("worker should validate"),
            1,
            10,
            2,
        )
        .expect("stale incarnation fixture should validate"),
        "worker-rpc://stale-incarnation",
    )
    .expect("entry should validate");
    assert_eq!(
        store
            .register_directory(stale_worker_epoch, Duration::from_secs(30))
            .await
            .expect("rollback should be explicit"),
        DirectoryMutation::FenceMismatch
    );
    assert_eq!(
        store
            .register_directory(stale_incarnation, Duration::from_secs(30))
            .await
            .expect("rollback should be explicit"),
        DirectoryMutation::FenceMismatch
    );

    let next_incarnation = DirectoryEntry::new(
        current.key().clone(),
        DirectoryFence::new(
            WorkerId::new("replacement-worker").expect("worker should validate"),
            1,
            10,
            4,
        )
        .expect("new incarnation fixture should validate"),
        "worker-rpc://new-incarnation",
    )
    .expect("entry should validate");
    assert_eq!(
        store
            .register_directory(next_incarnation, Duration::from_secs(30))
            .await
            .expect("new incarnation transfer should work"),
        DirectoryMutation::Applied
    );
}

#[tokio::test]
async fn renew_and_remove_cas_include_the_entire_directory_entry() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let entry = directory_entry(3, 5);
    store
        .register_directory(entry.clone(), Duration::from_secs(30))
        .await
        .expect("registration should work");
    let snapshot = store
        .resolve_directory(entry.key())
        .await
        .expect("lookup should work")
        .expect("directory should exist");
    let forged_entry = DirectoryEntry::new(
        entry.key().clone(),
        entry.fence().clone(),
        "worker-rpc://forged-endpoint",
    )
    .expect("forged fixture should validate structurally");
    let forged = DirectorySnapshot::from_persisted(
        forged_entry,
        snapshot.revision(),
        snapshot.expires_at_millis(),
    )
    .expect("forged snapshot should validate structurally");
    assert_eq!(
        store
            .renew_directory(&forged, Duration::from_secs(30))
            .await
            .expect("renew should return CAS result"),
        DirectoryMutation::CasMismatch
    );
    assert_eq!(
        store
            .remove_directory(&forged)
            .await
            .expect("remove should return CAS result"),
        DirectoryMutation::CasMismatch
    );
}

#[tokio::test]
async fn directory_ttl_uses_store_time_and_expired_ownership_cannot_be_renewed() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let entry = directory_entry(5, 2);
    store
        .register_directory(entry.clone(), Duration::from_secs(5))
        .await
        .expect("registration should work");
    let snapshot = store
        .resolve_directory(entry.key())
        .await
        .expect("lookup should work")
        .expect("directory should exist before expiry");

    clock.advance(Duration::from_secs(5));
    assert!(
        store
            .resolve_directory(entry.key())
            .await
            .expect("expired lookup should work")
            .is_none()
    );
    assert_eq!(
        store
            .renew_directory(&snapshot, Duration::from_secs(30))
            .await
            .expect("expired renewal should return a fenced result"),
        DirectoryMutation::Expired
    );
}

#[tokio::test]
async fn ttl_endpoint_and_revision_bounds_fail_closed() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let entry = directory_entry(2, 4);
    assert_eq!(
        DirectoryFence::new(
            WorkerId::new("invalid-incarnation-worker").expect("worker should validate"),
            2,
            4,
            0,
        ),
        Err(EphemeralCoordinationError::InvalidInput)
    );
    assert_eq!(
        store
            .register_directory(entry.clone(), Duration::ZERO)
            .await,
        Err(EphemeralCoordinationError::InvalidInput)
    );
    assert_eq!(
        store
            .register_directory(entry.clone(), Duration::from_secs(301))
            .await,
        Err(EphemeralCoordinationError::InvalidInput)
    );
    for endpoint in [
        "",
        " worker-rpc://leading",
        "worker-rpc://trailing ",
        "worker\nrpc",
    ] {
        assert_eq!(
            DirectoryEntry::new(entry.key().clone(), entry.fence().clone(), endpoint),
            Err(EphemeralCoordinationError::InvalidInput)
        );
    }
    assert_eq!(
        DirectoryEntry::new(entry.key().clone(), entry.fence().clone(), "x".repeat(2049)),
        Err(EphemeralCoordinationError::InvalidInput)
    );

    let exhausted = DirectorySnapshot::from_persisted(entry, u64::MAX, 30_000)
        .expect("persisted fixture should validate");
    let exhausted_store = MemoryEphemeralCoordinationStore::from_snapshot(
        ManualCoordinationClock::new(),
        exhausted.clone(),
    );
    assert_eq!(
        exhausted_store
            .renew_directory(&exhausted, Duration::from_secs(30))
            .await,
        Err(EphemeralCoordinationError::RevisionExhausted)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_four_concurrent_one_time_consumers_have_exactly_one_winner() {
    let clock = ManualCoordinationClock::new();
    let store = Arc::new(MemoryEphemeralCoordinationStore::new(clock));
    let capability = OneTimeCapability::new(
        TenantId::new(),
        SessionId::new(),
        "viewer-ticket-conformance-secret",
    )
    .expect("capability should validate");
    assert_eq!(
        store
            .issue_one_time(capability.clone(), Duration::from_secs(30))
            .await
            .expect("capability issue should work"),
        OneTimeIssue::Issued
    );
    let barrier = Arc::new(Barrier::new(65));
    let mut consumers = Vec::new();
    for _ in 0..64 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let capability = capability.clone();
        consumers.push(tokio::spawn(async move {
            barrier.wait().await;
            store.consume_one_time(&capability).await
        }));
    }
    barrier.wait().await;

    let mut consumed = 0;
    for consumer in consumers {
        if consumer
            .await
            .expect("consumer task should join")
            .expect("consume should return an atomic result")
            == OneTimeConsume::Consumed
        {
            consumed += 1;
        }
    }
    assert_eq!(consumed, 1);
}

#[tokio::test]
async fn one_time_capabilities_are_namespaced_and_cannot_be_rearmed() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let first = OneTimeCapability::new(
        TenantId::new(),
        SessionId::new(),
        "same-raw-secret-across-namespaces",
    )
    .expect("first capability should validate");
    let second = OneTimeCapability::new(
        TenantId::new(),
        SessionId::new(),
        "same-raw-secret-across-namespaces",
    )
    .expect("second capability should validate");
    assert_eq!(
        store
            .issue_one_time(first.clone(), Duration::from_secs(30))
            .await
            .expect("first issue should work"),
        OneTimeIssue::Issued
    );
    assert_eq!(
        store
            .issue_one_time(second.clone(), Duration::from_secs(30))
            .await
            .expect("second issue should work"),
        OneTimeIssue::Issued
    );
    assert_eq!(
        store.consume_one_time(&first).await.expect("first consume"),
        OneTimeConsume::Consumed
    );
    assert_eq!(
        store
            .consume_one_time(&second)
            .await
            .expect("second consume"),
        OneTimeConsume::Consumed
    );

    assert_eq!(
        store
            .issue_one_time(first.clone(), Duration::from_secs(60))
            .await
            .expect("reissue result should be explicit"),
        OneTimeIssue::AlreadyConsumed
    );
    clock.advance(Duration::from_secs(31));
    assert_eq!(
        store.consume_one_time(&first).await.expect("reconsume"),
        OneTimeConsume::AlreadyConsumed,
        "reissue must not rearm a consumed capability or extend its TTL"
    );
}

#[tokio::test]
async fn missing_and_expired_one_time_capabilities_are_both_fail_closed_consumed() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let missing = OneTimeCapability::new(
        TenantId::new(),
        SessionId::new(),
        "missing-one-time-capability",
    )
    .expect("capability should validate");
    assert_eq!(
        store
            .consume_one_time(&missing)
            .await
            .expect("missing consume"),
        OneTimeConsume::AlreadyConsumed
    );

    let expired = OneTimeCapability::new(
        TenantId::new(),
        SessionId::new(),
        "expired-one-time-capability",
    )
    .expect("capability should validate");
    store
        .issue_one_time(expired.clone(), Duration::from_millis(1))
        .await
        .expect("issue should work");
    clock.advance(Duration::from_millis(1));
    assert_eq!(
        store
            .consume_one_time(&expired)
            .await
            .expect("expired consume"),
        OneTimeConsume::AlreadyConsumed
    );
}

#[tokio::test]
async fn consumed_capability_tombstone_is_bounded_to_the_store_maximum_ttl() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let capability = OneTimeCapability::new(
        TenantId::new(),
        SessionId::new(),
        "bounded-consumed-tombstone",
    )
    .expect("capability should validate");
    assert_eq!(
        store
            .issue_one_time(capability.clone(), Duration::from_millis(1))
            .await
            .expect("issue should work"),
        OneTimeIssue::Issued
    );
    assert_eq!(
        store
            .consume_one_time(&capability)
            .await
            .expect("consume should work"),
        OneTimeConsume::Consumed
    );
    clock.advance(Duration::from_secs(299));
    assert_eq!(
        store
            .issue_one_time(capability.clone(), Duration::from_secs(1))
            .await
            .expect("reissue result should be explicit"),
        OneTimeIssue::AlreadyConsumed
    );
    clock.advance(Duration::from_secs(2));
    assert_eq!(
        store
            .issue_one_time(capability, Duration::from_secs(1))
            .await
            .expect("expired tombstone should be collected"),
        OneTimeIssue::Issued
    );
}

#[tokio::test]
async fn unavailable_coordination_fails_closed_for_new_admission_and_consumption() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock);
    let entry = directory_entry(2, 1);
    let capability = OneTimeCapability::new(
        entry.key().tenant_id().clone(),
        entry.key().session_id().clone(),
        "viewer-ticket-unavailable-secret",
    )
    .expect("capability should validate");
    store.set_available(false);

    assert_eq!(
        store
            .register_directory(entry, Duration::from_secs(30))
            .await,
        Err(EphemeralCoordinationError::Unavailable)
    );
    assert_eq!(
        store
            .issue_one_time(capability.clone(), Duration::from_secs(30))
            .await,
        Err(EphemeralCoordinationError::Unavailable)
    );
    assert_eq!(
        store.consume_one_time(&capability).await,
        Err(EphemeralCoordinationError::Unavailable)
    );
}
