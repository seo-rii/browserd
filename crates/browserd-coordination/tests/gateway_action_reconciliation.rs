#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use browserd_actions::{
    ActionKind, CanonicalRequestHash, DispatchId, OutcomeUnknownReason, ResolutionAnnotation,
    ResolutionKind, TerminalDetail, TransportLoss,
};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionClaimOutcome, GatewayActionCoordination,
    GatewayActionCoordinationError, GatewayActionPlacement, GatewayActionSnapshot,
    MemoryGatewayActionStore, SessionLossClaim, SessionLossOutcome,
};
use browserd_core::{ActionId, PrincipalId, SessionId, TenantId, WorkerId};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 1, 0, second)
        .single()
        .expect("test timestamp should be valid")
}

fn placement(worker_epoch: u64, directory_revision: u64) -> GatewayActionPlacement {
    GatewayActionPlacement::new(
        DirectoryFence::new(
            WorkerId::new("reconciliation-worker").expect("worker ID should be valid"),
            worker_epoch,
            17,
            1,
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
    idempotency_key: &str,
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

fn resolution() -> ResolutionAnnotation {
    ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        1_777_777_777_000,
        "post-read verification found no side effect",
    )
}

struct UnknownMutation {
    store: MemoryGatewayActionStore,
    tenant_id: TenantId,
    session_id: SessionId,
    placement: GatewayActionPlacement,
    action_id: ActionId,
    snapshot: GatewayActionSnapshot,
}

async fn unknown_mutation() -> UnknownMutation {
    let store = MemoryGatewayActionStore::default();
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(51, 83);
    let action_id = ActionId::new();
    let claimed = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "uncertain-mutation",
                1,
                ActionKind::Mutating,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("mutating action should be claimed");
    let dispatch_id = DispatchId::new();
    let armed = store
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
        .expect("dispatch should be armed");
    let exposed = store
        .mark_exposure_possible(
            &tenant_id,
            &session_id,
            &action_id,
            armed.revision(),
            &placement,
            &dispatch_id,
            at(3),
        )
        .await
        .expect("dispatch exposure should be recorded");
    let snapshot = store
        .record_transport_loss(
            &tenant_id,
            &session_id,
            &action_id,
            exposed.revision(),
            &placement,
            &dispatch_id,
            TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
            at(4),
        )
        .await
        .expect("ambiguous transport loss should become terminal");
    assert_eq!(
        snapshot.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::AmbiguousTransportLoss,
        ))
    );

    UnknownMutation {
        store,
        tenant_id,
        session_id,
        placement,
        action_id,
        snapshot,
    }
}

#[tokio::test]
async fn unresolved_mutation_blocks_only_new_mutations_until_fenced_resolution() {
    let fixture = unknown_mutation().await;

    let exact_retry = fixture
        .store
        .claim_action(
            claim(
                fixture.tenant_id.clone(),
                fixture.session_id.clone(),
                ActionId::new(),
                "uncertain-mutation",
                1,
                ActionKind::Mutating,
                fixture.placement.clone(),
            ),
            at(5),
        )
        .await
        .expect("exact idempotent retry should recover the uncertain action");
    assert!(matches!(
        exact_retry,
        GatewayActionClaimOutcome::Existing(_)
    ));
    assert_eq!(exact_retry.snapshot().action_id(), &fixture.action_id);
    assert_eq!(
        exact_retry.snapshot().terminal(),
        fixture.snapshot.terminal()
    );

    let blocked_action_id = ActionId::new();
    assert_eq!(
        fixture
            .store
            .claim_action(
                claim(
                    fixture.tenant_id.clone(),
                    fixture.session_id.clone(),
                    blocked_action_id,
                    "next-mutation",
                    2,
                    ActionKind::Mutating,
                    fixture.placement.clone(),
                ),
                at(5),
            )
            .await,
        Err(GatewayActionCoordinationError::ReconciliationRequired {
            action_id: fixture.action_id.clone(),
        })
    );

    let read_only = fixture
        .store
        .claim_action(
            claim(
                fixture.tenant_id.clone(),
                fixture.session_id.clone(),
                ActionId::new(),
                "reconciliation-read",
                3,
                ActionKind::ReadOnly,
                fixture.placement.clone(),
            ),
            at(5),
        )
        .await
        .expect("read-only verification should remain available");
    assert!(matches!(read_only, GatewayActionClaimOutcome::Created(_)));

    assert_eq!(
        fixture
            .store
            .resolve_unknown(
                &fixture.tenant_id,
                &fixture.session_id,
                &fixture.action_id,
                fixture.snapshot.revision(),
                &placement(51, 82),
                resolution(),
                at(6),
            )
            .await,
        Err(GatewayActionCoordinationError::PlacementMismatch)
    );
    assert!(matches!(
        fixture
            .store
            .resolve_unknown(
                &fixture.tenant_id,
                &fixture.session_id,
                &fixture.action_id,
                fixture.snapshot.revision() - 1,
                &fixture.placement,
                resolution(),
                at(6),
            )
            .await,
        Err(GatewayActionCoordinationError::StaleWrite(_))
    ));

    let annotation = resolution();
    let resolved = fixture
        .store
        .resolve_unknown(
            &fixture.tenant_id,
            &fixture.session_id,
            &fixture.action_id,
            fixture.snapshot.revision(),
            &fixture.placement,
            annotation.clone(),
            at(6),
        )
        .await
        .expect("current placement and revision should resolve the uncertainty");
    assert_eq!(resolved.resolution(), Some(&annotation));
    assert_eq!(resolved.terminal(), fixture.snapshot.terminal());
    assert_eq!(resolved.revision(), fixture.snapshot.revision() + 1);

    let next_mutation = fixture
        .store
        .claim_action(
            claim(
                fixture.tenant_id,
                fixture.session_id,
                ActionId::new(),
                "next-mutation",
                2,
                ActionKind::Mutating,
                fixture.placement,
            ),
            at(7),
        )
        .await
        .expect("resolution should reopen mutating execution");
    assert!(matches!(
        next_mutation,
        GatewayActionClaimOutcome::Created(_)
    ));
}

#[tokio::test]
async fn resolve_and_new_mutation_claim_have_one_linearization_order() {
    const ITERATIONS: usize = 64;

    for iteration in 0..ITERATIONS {
        let fixture = unknown_mutation().await;
        let annotation = resolution();
        let next_action_id = ActionId::new();
        let next_key = format!("racing-mutation-{iteration}");
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let resolve_store = fixture.store.clone();
        let resolve_tenant = fixture.tenant_id.clone();
        let resolve_session = fixture.session_id.clone();
        let resolve_action = fixture.action_id.clone();
        let resolve_placement = fixture.placement.clone();
        let resolve_annotation = annotation.clone();
        let resolve_barrier = Arc::clone(&barrier);
        let expected_revision = fixture.snapshot.revision();
        let resolve_task = tokio::spawn(async move {
            resolve_barrier.wait().await;
            resolve_store
                .resolve_unknown(
                    &resolve_tenant,
                    &resolve_session,
                    &resolve_action,
                    expected_revision,
                    &resolve_placement,
                    resolve_annotation,
                    at(5),
                )
                .await
        });

        let claim_store = fixture.store.clone();
        let claim_tenant = fixture.tenant_id.clone();
        let claim_session = fixture.session_id.clone();
        let claim_placement = fixture.placement.clone();
        let claim_action_id = next_action_id.clone();
        let claim_key = next_key.clone();
        let claim_barrier = Arc::clone(&barrier);
        let claim_task = tokio::spawn(async move {
            claim_barrier.wait().await;
            claim_store
                .claim_action(
                    claim(
                        claim_tenant,
                        claim_session,
                        claim_action_id,
                        &claim_key,
                        4,
                        ActionKind::Mutating,
                        claim_placement,
                    ),
                    at(5),
                )
                .await
        });

        barrier.wait().await;
        let resolved = resolve_task
            .await
            .expect("resolve task should join")
            .expect("resolve should linearize successfully");
        assert_eq!(resolved.resolution(), Some(&annotation));

        match claim_task.await.expect("claim task should join") {
            Ok(GatewayActionClaimOutcome::Created(created)) => {
                assert_eq!(created.action_id(), &next_action_id);
            }
            Err(GatewayActionCoordinationError::ReconciliationRequired { action_id }) => {
                assert_eq!(action_id, fixture.action_id);
                let retried = fixture
                    .store
                    .claim_action(
                        claim(
                            fixture.tenant_id.clone(),
                            fixture.session_id.clone(),
                            next_action_id.clone(),
                            &next_key,
                            4,
                            ActionKind::Mutating,
                            fixture.placement.clone(),
                        ),
                        at(6),
                    )
                    .await
                    .expect("claim should succeed after the concurrent resolution");
                assert!(matches!(retried, GatewayActionClaimOutcome::Created(_)));
                assert_eq!(retried.snapshot().action_id(), &next_action_id);
            }
            other => panic!("unexpected claim result in resolve race: {other:?}"),
        }

        let effective = fixture
            .store
            .get_effective_action(&fixture.tenant_id, &fixture.session_id, &fixture.action_id)
            .await
            .expect("resolved action lookup should succeed")
            .expect("resolved action should still exist");
        assert_eq!(effective.resolution(), Some(&annotation));
    }
}

#[tokio::test]
async fn only_one_mutating_action_owns_the_session_dispatch_lane() {
    let store = MemoryGatewayActionStore::default();
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(61, 93);
    let first_id = ActionId::new();
    let second_id = ActionId::new();
    let first = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                first_id.clone(),
                "first-lane-mutation",
                5,
                ActionKind::Mutating,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("first mutation should be claimed");
    let second = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                second_id.clone(),
                "second-lane-mutation",
                6,
                ActionKind::Mutating,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("second mutation may be durably claimed before dispatch");
    let first_dispatch = DispatchId::new();
    let first_armed = store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &first_id,
            first.snapshot().revision(),
            &placement,
            first_dispatch.clone(),
            at(2),
        )
        .await
        .expect("first mutation should own the dispatch lane");
    assert_eq!(
        store
            .arm_dispatch(
                &tenant_id,
                &session_id,
                &second_id,
                second.snapshot().revision(),
                &placement,
                DispatchId::new(),
                at(2),
            )
            .await,
        Err(GatewayActionCoordinationError::MutationInFlight {
            action_id: first_id.clone(),
        })
    );

    store
        .record_transport_loss(
            &tenant_id,
            &session_id,
            &first_id,
            first_armed.revision(),
            &placement,
            &first_dispatch,
            TransportLoss::ConfirmedNotWritten,
            at(3),
        )
        .await
        .expect("proven non-delivery should release the mutation lane");
    let second_dispatch = DispatchId::new();
    let second_armed = store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &second_id,
            second.snapshot().revision(),
            &placement,
            second_dispatch,
            at(4),
        )
        .await
        .expect("the next mutation should acquire the released lane");
    assert_eq!(second_armed.action_id(), &second_id);
}

#[tokio::test]
async fn worker_loss_unknown_can_be_resolved_without_reopening_the_lost_session() {
    let store = MemoryGatewayActionStore::default();
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(71, 103);
    let action_id = ActionId::new();
    let claimed = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "worker-loss-mutation",
                7,
                ActionKind::Mutating,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("mutation should be claimed before worker loss");
    let armed = store
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
        .expect("mutation should be dispatch-armed before worker loss");
    let loss = SessionLossClaim::new(
        tenant_id.clone(),
        session_id.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    assert_eq!(
        store
            .mark_session_lost(&loss, at(3))
            .await
            .expect("worker loss should fence the session"),
        SessionLossOutcome::Recorded
    );
    assert_eq!(
        store
            .materialize_session_loss(&loss, 10, at(4))
            .await
            .expect("worker loss should be materialized into the action"),
        1
    );

    let unknown = store
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("lost action lookup should succeed")
        .expect("lost action should remain durable");
    assert_eq!(unknown.revision(), armed.revision() + 1);
    assert_eq!(
        unknown.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost,
        ))
    );
    assert_eq!(unknown.resolution(), None);

    let annotation = resolution();
    let resolved = store
        .resolve_unknown(
            &tenant_id,
            &session_id,
            &action_id,
            unknown.revision(),
            &placement,
            annotation.clone(),
            at(5),
        )
        .await
        .expect("worker-loss uncertainty should accept an audit resolution");
    assert_eq!(resolved.resolution(), Some(&annotation));
    assert_eq!(resolved.revision(), unknown.revision() + 1);
    assert_eq!(resolved.terminal(), unknown.terminal());

    let exact_retry = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                ActionId::new(),
                "worker-loss-mutation",
                7,
                ActionKind::Mutating,
                placement.clone(),
            ),
            at(6),
        )
        .await
        .expect("exact retry should recover the resolved lost action");
    assert!(matches!(
        exact_retry,
        GatewayActionClaimOutcome::Existing(_)
    ));
    assert_eq!(exact_retry.snapshot().action_id(), &action_id);
    assert_eq!(exact_retry.snapshot().resolution(), Some(&annotation));
    assert_eq!(exact_retry.snapshot().terminal(), unknown.terminal());

    assert_eq!(
        store
            .claim_action(
                claim(
                    tenant_id,
                    session_id,
                    ActionId::new(),
                    "post-loss-mutation",
                    8,
                    ActionKind::Mutating,
                    placement,
                ),
                at(7),
            )
            .await,
        Err(GatewayActionCoordinationError::SessionLost)
    );
}
