#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use browserd_actions::{
    ActionDeliveryEvidence, ActionKind, ActionTerminalSource, BrowserResult, CanonicalRequestHash,
    DispatchId, KnownFailureReason, ResultDigest, TerminalDetail,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionBlockingClient,
    GatewayActionClaimOutcome, GatewayActionCoordination, GatewayActionCoordinationError,
    GatewayActionPlacement, GatewayActionRecoveryCursor, GatewayActionRetentionLimits,
    GatewayActionSnapshot, GatewayActionSubmissionLease, MAX_PENDING_ACTIONS_PER_NAMESPACE,
    MAX_PENDING_ACTIONS_PER_SESSION, MemoryGatewayActionStore,
};
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

fn at(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 11, 0, 0, second)
        .single()
        .unwrap()
}

fn lease(second: u32) -> GatewayActionSubmissionLease {
    GatewayActionSubmissionLease::new(Uuid::now_v7(), 1, at(second), at(second)).unwrap()
}

struct Scope {
    tenant: TenantId,
    session: SessionId,
    placement: GatewayActionPlacement,
}

impl Scope {
    fn new() -> Self {
        Self {
            tenant: TenantId::new(),
            session: SessionId::new(),
            placement: GatewayActionPlacement::new(
                DirectoryFence::new(WorkerId::new("recovery-worker").unwrap(), 1, 2, 3).unwrap(),
                4,
            )
            .unwrap(),
        }
    }

    fn claim(
        &self,
        key: &str,
        kind: ActionKind,
        owner: Option<GatewayActionSubmissionLease>,
    ) -> ClaimGatewayAction {
        let claim = ClaimGatewayAction::new(
            self.tenant.clone(),
            self.session.clone(),
            ActionId::new(),
            key,
            CanonicalRequestHash::new([7; 32]),
            kind,
            self.placement.clone(),
        )
        .unwrap();
        match owner {
            Some(owner) => claim.with_submission_lease(owner),
            None => claim,
        }
    }

    async fn arm(
        &self,
        store: &MemoryGatewayActionStore,
        snapshot: &GatewayActionSnapshot,
        owner: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        store
            .arm_dispatch_owned(
                &self.tenant,
                &self.session,
                snapshot.action_id(),
                snapshot.revision(),
                &self.placement,
                DispatchId::new(),
                owner,
                now,
            )
            .await
    }

    async fn expire(
        &self,
        store: &MemoryGatewayActionStore,
        snapshot: &GatewayActionSnapshot,
        owner: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        store
            .expire_unattempted_action(
                &self.tenant,
                &self.session,
                snapshot.action_id(),
                snapshot.revision(),
                &self.placement,
                owner,
                now,
            )
            .await
    }
}

#[tokio::test]
async fn same_key_does_not_transfer_submission_authority_and_legacy_arm_cannot_bypass_it() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let original = lease(5);
    let other = lease(5);
    let first = store
        .claim_action(
            scope.claim("same", ActionKind::ReadOnly, Some(original.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    let retry = store
        .claim_action(
            scope.claim("same", ActionKind::ReadOnly, Some(other.clone())),
            at(1),
        )
        .await
        .unwrap();
    assert!(matches!(retry, GatewayActionClaimOutcome::Existing(_)));
    assert_eq!(retry.snapshot().submission_lease(), Some(&original));
    assert_eq!(
        scope.arm(&store, &first, &other, at(1)).await,
        Err(GatewayActionCoordinationError::SubmissionLeaseMismatch)
    );
    assert_eq!(
        store
            .arm_dispatch(
                &scope.tenant,
                &scope.session,
                first.action_id(),
                first.revision(),
                &scope.placement,
                DispatchId::new(),
                at(1)
            )
            .await,
        Err(GatewayActionCoordinationError::SubmissionLeaseRequired)
    );
    assert!(scope.arm(&store, &first, &original, at(1)).await.is_ok());
}

#[tokio::test]
async fn exact_expired_unattempted_lease_records_non_delivery_once_with_terminal_event() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let owner = lease(3);
    let first = store
        .claim_action(
            scope.claim("expires", ActionKind::Mutating, Some(owner.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    assert_eq!(
        scope.expire(&store, &first, &owner, at(2)).await,
        Err(GatewayActionCoordinationError::SubmissionLeaseNotExpired)
    );
    assert_eq!(
        scope.expire(&store, &first, &lease(3), at(3)).await,
        Err(GatewayActionCoordinationError::SubmissionLeaseMismatch)
    );
    let expired = scope.expire(&store, &first, &owner, at(3)).await.unwrap();
    assert_eq!(expired.delivery(), &ActionDeliveryEvidence::NotAttempted);
    assert_eq!(
        expired.terminal().unwrap().detail(),
        TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
    );
    assert_eq!(
        expired.terminal().unwrap().source(),
        ActionTerminalSource::ProvenNonDelivery
    );
    assert_eq!(
        scope.expire(&store, &first, &owner, at(4)).await.unwrap(),
        expired
    );
    assert!(scope.arm(&store, &first, &owner, at(4)).await.is_err());
    let event = store
        .peek_event_projection(&scope.tenant, &scope.session)
        .await
        .unwrap()
        .unwrap();
    store.ack_event_projection(&event).await.unwrap();
    assert!(
        store
            .peek_event_projection(&scope.tenant, &scope.session)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 1)
            .await
            .unwrap()
            .actions()
            .is_empty()
    );
    // Original timestamps may have expired, but an exact request still returns its durable result.
    let replay = store
        .claim_action(
            scope.claim("expires", ActionKind::Mutating, Some(owner)),
            at(4),
        )
        .await
        .unwrap();
    assert_eq!(replay.snapshot(), &expired);
}

#[tokio::test]
async fn expiry_and_delayed_arm_have_one_cas_winner() {
    let store = Arc::new(MemoryGatewayActionStore::default());
    let scope = Arc::new(Scope::new());
    let owner = lease(5);
    let snapshot = store
        .claim_action(
            scope.claim("race", ActionKind::ReadOnly, Some(owner.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let arm = {
        let (store, scope, barrier, owner, snapshot) = (
            Arc::clone(&store),
            Arc::clone(&scope),
            Arc::clone(&barrier),
            owner.clone(),
            snapshot.clone(),
        );
        tokio::spawn(async move {
            barrier.wait().await;
            scope.arm(&store, &snapshot, &owner, at(4)).await
        })
    };
    let expire = {
        let (store, scope, barrier, owner, snapshot) = (
            Arc::clone(&store),
            Arc::clone(&scope),
            Arc::clone(&barrier),
            owner.clone(),
            snapshot.clone(),
        );
        tokio::spawn(async move {
            barrier.wait().await;
            scope.expire(&store, &snapshot, &owner, at(5)).await
        })
    };
    barrier.wait().await;
    let (armed, expired) = (arm.await.unwrap(), expire.await.unwrap());
    assert_ne!(armed.is_ok(), expired.is_ok());
    let final_state = store
        .get_effective_action(&scope.tenant, &scope.session, snapshot.action_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_state.revision(), 1);
    assert_ne!(
        matches!(
            final_state.delivery(),
            ActionDeliveryEvidence::DispatchArmed(_)
        ),
        final_state.terminal().is_some()
    );
}

#[tokio::test]
async fn owned_dispatch_cannot_overtake_an_earlier_unattempted_or_running_read_only_action() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let first_lease = lease(2);
    let next_lease = lease(9);
    let first = store
        .claim_action(
            scope.claim("first", ActionKind::ReadOnly, Some(first_lease.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    let next = store
        .claim_action(
            scope.claim("next", ActionKind::ReadOnly, Some(next_lease.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    assert_eq!(
        scope.arm(&store, &next, &next_lease, at(1)).await,
        Err(GatewayActionCoordinationError::ActionDispatchInFlight {
            action_id: first.action_id().clone()
        })
    );
    let first = scope
        .arm(&store, &first, &first_lease, at(1))
        .await
        .unwrap();
    assert_eq!(
        scope.arm(&store, &next, &next_lease, at(2)).await,
        Err(GatewayActionCoordinationError::ActionDispatchInFlight {
            action_id: first.action_id().clone()
        })
    );
    assert!(
        scope
            .expire(&store, &first, &first_lease, at(3))
            .await
            .is_err()
    );
    let dispatch = match first.delivery() {
        ActionDeliveryEvidence::DispatchArmed(id) => Some(id),
        _ => None,
    }
    .expect("owned arm must retain its dispatch identity");
    // Exact worker completion remains valid after submission authority expires.
    store
        .record_worker_result(
            &scope.tenant,
            &scope.session,
            first.action_id(),
            first.revision(),
            &scope.placement,
            dispatch,
            first.action_sequence(),
            BrowserResult::Succeeded(ResultDigest::new([1; 32])),
            None,
            at(3),
        )
        .await
        .unwrap();
    assert!(scope.arm(&store, &next, &next_lease, at(4)).await.is_ok());
}

#[tokio::test]
async fn legacy_unleased_actions_remain_discoverable_but_cannot_be_automatically_expired() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let old = store
        .claim_action(scope.claim("legacy", ActionKind::ReadOnly, None), at(0))
        .await
        .unwrap()
        .into_snapshot();
    assert_eq!(
        scope.expire(&store, &old, &lease(1), at(5)).await,
        Err(GatewayActionCoordinationError::SubmissionLeaseRequired)
    );
    let page = store
        .scan_pending_actions(GatewayActionRecoveryCursor::default(), 8)
        .await
        .unwrap();
    assert_eq!(page.actions(), &[old]);
    assert!(page.is_complete());
}

#[tokio::test]
async fn discovery_cursor_keeps_tail_when_prior_rows_are_terminalized() {
    let store = MemoryGatewayActionStore::default();
    let mut expected = BTreeSet::new();
    for _ in 0..5 {
        let scope = Scope::new();
        let snapshot = store
            .claim_action(
                scope.claim("scan", ActionKind::ReadOnly, Some(lease(2))),
                at(0),
            )
            .await
            .unwrap()
            .into_snapshot();
        expected.insert(snapshot.action_id().clone());
    }
    assert!(matches!(
        store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 0)
            .await,
        Err(GatewayActionCoordinationError::InvalidRecoveryScanLimit)
    ));
    assert!(matches!(
        store
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 257)
            .await,
        Err(GatewayActionCoordinationError::InvalidRecoveryScanLimit)
    ));
    let mut cursor = GatewayActionRecoveryCursor::default();
    let mut seen = BTreeSet::new();
    for _ in 0..4 {
        let page = store.scan_pending_actions(cursor, 2).await.unwrap();
        assert!(page.actions().len() <= 2);
        for snapshot in page.actions() {
            assert!(seen.insert(snapshot.action_id().clone()));
            store
                .expire_unattempted_action(
                    snapshot.tenant_id(),
                    snapshot.session_id(),
                    snapshot.action_id(),
                    snapshot.revision(),
                    snapshot.placement(),
                    snapshot.submission_lease().unwrap(),
                    at(3),
                )
                .await
                .unwrap();
        }
        cursor = page.next_cursor().clone();
        if page.is_complete() {
            break;
        }
    }
    assert_eq!(seen, expected);
    assert!(
        store
            .scan_pending_actions(cursor, 2)
            .await
            .unwrap()
            .is_complete()
    );
}

#[tokio::test]
async fn pending_session_cap_preserves_replays_and_releases_capacity_after_terminal() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let owner = lease(5);
    let mut first = None;
    for index in 0..MAX_PENDING_ACTIONS_PER_SESSION {
        let snapshot = store
            .claim_action(
                scope.claim(
                    &format!("cap-{index}"),
                    ActionKind::ReadOnly,
                    Some(owner.clone()),
                ),
                at(0),
            )
            .await
            .unwrap()
            .into_snapshot();
        if index == 0 {
            first = Some(snapshot);
        }
    }
    assert!(matches!(
        store
            .claim_action(
                scope.claim("overflow", ActionKind::ReadOnly, Some(owner.clone())),
                at(0)
            )
            .await,
        Err(GatewayActionCoordinationError::PendingActionCapacity)
    ));
    assert!(matches!(
        store
            .claim_action(
                scope.claim("cap-0", ActionKind::ReadOnly, Some(owner.clone())),
                at(1)
            )
            .await,
        Ok(GatewayActionClaimOutcome::Existing(_))
    ));
    scope
        .expire(&store, &first.unwrap(), &owner, at(5))
        .await
        .unwrap();
    store
        .claim_action(
            scope.claim("released", ActionKind::ReadOnly, Some(lease(9))),
            at(6),
        )
        .await
        .unwrap();
}

#[test]
fn blocking_actor_forwards_owned_arm_expiry_and_bounded_scan() {
    let store = Arc::new(MemoryGatewayActionStore::default());
    let actor =
        GatewayActionBlockingClient::spawn(store, CoordinationActorConfig::default()).unwrap();
    let scope = Scope::new();
    let owner = lease(3);
    let first = actor
        .claim_action(
            scope.claim("actor", ActionKind::ReadOnly, Some(owner.clone())),
            at(0),
        )
        .unwrap()
        .into_snapshot();
    assert_eq!(
        actor
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 1)
            .unwrap()
            .actions(),
        std::slice::from_ref(&first)
    );
    assert_eq!(
        actor.arm_dispatch_owned(
            &scope.tenant,
            &scope.session,
            first.action_id(),
            first.revision(),
            &scope.placement,
            DispatchId::new(),
            &lease(3),
            at(1)
        ),
        Err(GatewayActionCoordinationError::SubmissionLeaseMismatch)
    );
    let expired = actor
        .expire_unattempted_action(
            &scope.tenant,
            &scope.session,
            first.action_id(),
            first.revision(),
            &scope.placement,
            &owner,
            at(3),
        )
        .unwrap();
    assert_eq!(
        expired.terminal().unwrap().detail(),
        TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
    );
    assert!(
        actor
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 1)
            .unwrap()
            .actions()
            .is_empty()
    );
}

#[tokio::test]
async fn expired_or_invalid_submission_leases_never_allocate_a_new_identity() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    assert!(GatewayActionSubmissionLease::new(Uuid::nil(), 1, at(2), at(2)).is_err());
    assert!(GatewayActionSubmissionLease::new(Uuid::now_v7(), 0, at(2), at(2)).is_err());
    assert!(GatewayActionSubmissionLease::new(Uuid::now_v7(), 1, at(3), at(2)).is_err());
    assert!(matches!(
        store
            .claim_action(
                scope.claim("late", ActionKind::ReadOnly, Some(lease(2))),
                at(2)
            )
            .await,
        Err(GatewayActionCoordinationError::SubmissionLeaseExpired)
    ));
    let fresh = store
        .claim_action(
            scope.claim("valid", ActionKind::ReadOnly, Some(lease(3))),
            at(2),
        )
        .await
        .unwrap();
    assert_eq!(fresh.snapshot().action_sequence().get(), 1);
}

#[tokio::test]
async fn namespace_pending_cap_is_shared_across_sessions_and_terminal_release_is_exact() {
    // Keep this test focused on pending reservations: terminal payloads remain retained.
    let store = MemoryGatewayActionStore::default().with_retention_limits(
        GatewayActionRetentionLimits::new(MAX_PENDING_ACTIONS_PER_NAMESPACE + 2, 4096)
            .expect("retained capacity must exceed the independently tested pending cap"),
    );
    let owner = lease(5);
    let first_scope = Scope::new();
    let first = store
        .claim_action(
            first_scope.claim("first", ActionKind::ReadOnly, Some(owner.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    let mut admitted = 1;
    while admitted < MAX_PENDING_ACTIONS_PER_NAMESPACE {
        let scope = Scope::new();
        for index in 0..MAX_PENDING_ACTIONS_PER_SESSION {
            if admitted == MAX_PENDING_ACTIONS_PER_NAMESPACE {
                break;
            }
            store
                .claim_action(
                    scope.claim(
                        &format!("cap-{index}"),
                        ActionKind::ReadOnly,
                        Some(owner.clone()),
                    ),
                    at(0),
                )
                .await
                .unwrap();
            admitted += 1;
        }
    }
    let overflow = Scope::new();
    assert!(matches!(
        store
            .claim_action(
                overflow.claim("overflow", ActionKind::ReadOnly, Some(owner.clone())),
                at(0)
            )
            .await,
        Err(GatewayActionCoordinationError::PendingActionCapacity)
    ));
    assert!(matches!(
        store
            .claim_action(
                first_scope.claim("first", ActionKind::ReadOnly, Some(owner.clone())),
                at(1)
            )
            .await,
        Ok(GatewayActionClaimOutcome::Existing(_))
    ));
    first_scope
        .expire(&store, &first, &owner, at(5))
        .await
        .unwrap();
    store
        .claim_action(
            overflow.claim("released", ActionKind::ReadOnly, Some(lease(9))),
            at(6),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim_action(
                overflow.claim("still-full", ActionKind::ReadOnly, Some(lease(9))),
                at(6)
            )
            .await,
        Err(GatewayActionCoordinationError::PendingActionCapacity)
    ));
}

#[tokio::test]
async fn same_token_with_changed_generation_or_deadline_cannot_arm() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let owner = lease(5);
    let first = store
        .claim_action(
            scope.claim("exact-lease", ActionKind::ReadOnly, Some(owner.clone())),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    for forged in [
        GatewayActionSubmissionLease::new(*owner.token(), 2, at(5), at(5)).unwrap(),
        GatewayActionSubmissionLease::new(*owner.token(), 1, at(4), at(5)).unwrap(),
        GatewayActionSubmissionLease::new(*owner.token(), 1, at(5), at(6)).unwrap(),
    ] {
        assert_eq!(
            scope.arm(&store, &first, &forged, at(1)).await,
            Err(GatewayActionCoordinationError::SubmissionLeaseMismatch)
        );
    }
    assert!(matches!(
        store
            .arm_dispatch_owned(
                &scope.tenant,
                &scope.session,
                first.action_id(),
                1,
                &scope.placement,
                DispatchId::new(),
                &owner,
                at(1)
            )
            .await,
        Err(GatewayActionCoordinationError::StaleWrite(_))
    ));
    let wrong_placement =
        GatewayActionPlacement::new(scope.placement.directory_fence().clone(), 5).unwrap();
    assert_eq!(
        store
            .arm_dispatch_owned(
                &scope.tenant,
                &scope.session,
                first.action_id(),
                0,
                &wrong_placement,
                DispatchId::new(),
                &owner,
                at(1)
            )
            .await,
        Err(GatewayActionCoordinationError::PlacementMismatch)
    );
    assert_eq!(
        store
            .get_effective_action(&scope.tenant, &scope.session, first.action_id())
            .await
            .unwrap()
            .unwrap(),
        first
    );
}

#[tokio::test]
async fn legacy_read_only_arm_also_holds_the_cross_gateway_dispatch_lane() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let first = store
        .claim_action(
            scope.claim("first-legacy", ActionKind::ReadOnly, None),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    let second = store
        .claim_action(
            scope.claim("second-legacy", ActionKind::ReadOnly, None),
            at(0),
        )
        .await
        .unwrap()
        .into_snapshot();
    store
        .arm_dispatch(
            &scope.tenant,
            &scope.session,
            first.action_id(),
            first.revision(),
            &scope.placement,
            DispatchId::new(),
            at(1),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .arm_dispatch(
                &scope.tenant,
                &scope.session,
                second.action_id(),
                second.revision(),
                &scope.placement,
                DispatchId::new(),
                at(1)
            )
            .await,
        Err(GatewayActionCoordinationError::ActionDispatchInFlight {
            action_id: first.action_id().clone()
        })
    );
}
