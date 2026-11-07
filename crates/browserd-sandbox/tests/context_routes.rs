#![allow(clippy::expect_used)]
use browserd_core::{
    EgressFence, LaunchGeneration, LeaseId, OwnerFence, PlacementFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ContextEgressRequest, ContextRoutePhase, ContextRoutePolicy,
    DedicatedEgressSpec, EgressPolicyBinding, FilePreparedShardJournal, LaunchSpec,
    PreparedShardRecoveryLocators,
};
use std::path::PathBuf;
use std::time::Duration;

fn launch(tenant_dedicated: bool, live: u16, lifetime: u16) -> LaunchSpec {
    let fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("context-routes").expect("worker"),
                WorkerEpoch::new(7).expect("epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(3).expect("launch"),
        ),
        RouteGeneration::new(1).expect("route"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("incarnation"),
    );
    LaunchSpec::production(
        TenantId::new(),
        DedicatedEgressSpec::new(
            fence,
            EgressPolicyBinding::new("public", [7; 32]).expect("policy"),
            Duration::from_secs(10),
        )
        .expect("egress"),
        ChromiumBinaryDigest::new([8; 32]),
    )
    .with_context_route_policy(
        ContextRoutePolicy::new(
            PlacementFence::new(7, 9, 1),
            tenant_dedicated,
            live,
            lifetime,
        )
        .expect("route policy"),
    )
    .expect("shared launch")
}
fn sibling(spec: &LaunchSpec, tenant: TenantId, index: u64) -> ContextEgressRequest {
    ContextEgressRequest::new(
        tenant,
        PlacementFence::new(7, index, 1),
        DedicatedEgressSpec::new(
            EgressFence::new(
                spec.dedicated_egress().egress_fence().shard().clone(),
                RouteGeneration::new(index).expect("route"),
                SessionId::new(),
                SessionIncarnation::new(1).expect("incarnation"),
            ),
            spec.dedicated_egress().policy_binding().clone(),
            Duration::from_secs(10),
        )
        .expect("egress"),
    )
    .expect("request")
}
fn journal(path: &std::path::Path, spec: &LaunchSpec) -> FilePreparedShardJournal {
    let journal = FilePreparedShardJournal::open(path).expect("journal");
    journal
        .reserve(
            spec.dedicated_egress().egress_fence().shard().clone(),
            PreparedShardRecoveryLocators::new(
                "context-route-test",
                PathBuf::from("/sys/fs/cgroup/browserd/context-route-test"),
                PathBuf::from("/run/browserd/shards/context-route-test"),
            )
            .expect("locators")
            .with_egress_binding(41, spec.dedicated_egress().egress_fence().clone())
            .expect("epoch"),
        )
        .expect("reserve shard");
    journal
        .configure_context_routes(
            spec.dedicated_egress().egress_fence().shard(),
            spec.context_route_policy().expect("shared").clone(),
        )
        .expect("configure");
    journal
}
#[test]
fn shared_route_policy_is_opt_in_and_bounded_to_eight_live_five_hundred_lifetime() {
    let placement = PlacementFence::new(7, 9, 1);
    assert!(ContextRoutePolicy::new(placement, false, 8, 500).is_ok());
    for (live, lifetime) in [(0, 500), (9, 500), (8, 7), (8, 501)] {
        assert!(ContextRoutePolicy::new(placement, false, live, lifetime).is_err());
    }
    assert!(ContextRoutePolicy::new(PlacementFence::new(7, 0, 1), false, 8, 500).is_err());
    let spec = launch(false, 8, 500);
    assert!(
        sibling(&spec, TenantId::new(), 2)
            .validate_for(&spec)
            .is_ok()
    );
    let dedicated = launch(true, 8, 500);
    assert!(
        sibling(&dedicated, TenantId::new(), 2)
            .validate_for(&dedicated)
            .is_err()
    );
    assert!(
        sibling(&dedicated, dedicated.tenant_id().clone(), 2)
            .validate_for(&dedicated)
            .is_ok()
    );
    let other = launch(false, 8, 500);
    assert!(
        sibling(&spec, spec.tenant_id().clone(), 2)
            .validate_for(&other)
            .is_err()
    );
}
#[test]
fn route_intent_restart_and_cancel_before_attach_preserve_exact_immutable_identity() {
    let directory = tempfile::tempdir().expect("dir");
    let spec = launch(false, 2, 3);
    let first = ContextEgressRequest::initial(&spec).expect("initial");
    let next = sibling(&spec, TenantId::new(), 2);
    let store = journal(directory.path(), &spec);
    store
        .reserve_context_route(first, LeaseId::new(), 41, false)
        .expect("first");
    let reserved = store
        .reserve_context_route(next.clone(), LeaseId::new(), 41, false)
        .expect("intent");
    let retry = store
        .reserve_context_route(next.clone(), LeaseId::new(), 41, false)
        .expect("lost response retry");
    assert_eq!(reserved, retry);
    drop(store);
    let store = FilePreparedShardJournal::open(directory.path()).expect("restart");
    assert_eq!(
        store.records().expect("records")[0].context_routes()[1],
        reserved
    );
    store
        .set_context_route_phase(&next, ContextRoutePhase::Releasing, None)
        .expect("cancel durable");
    store
        .set_context_route_phase(&next, ContextRoutePhase::Released, None)
        .expect("drained");
    assert!(
        store
            .set_context_route_phase(&next, ContextRoutePhase::Active, None)
            .is_err()
    );
    let wrong = ContextEgressRequest::new(TenantId::new(), next.placement(), next.egress().clone())
        .expect("wrong tenant");
    assert!(
        store
            .reserve_context_route(wrong, LeaseId::new(), 41, false)
            .is_err()
    );
    drop(store);
    assert_eq!(
        FilePreparedShardJournal::open(directory.path())
            .expect("second restart")
            .records()
            .expect("records")[0]
            .context_routes()[1]
            .phase(),
        ContextRoutePhase::Released
    );
}
#[test]
fn route_capacity_reserves_live_intents_and_retains_cancelled_lifetime_slots() {
    let directory = tempfile::tempdir().expect("dir");
    let spec = launch(false, 1, 2);
    let first = ContextEgressRequest::initial(&spec).expect("initial");
    let next = sibling(&spec, TenantId::new(), 2);
    let store = journal(directory.path(), &spec);
    store
        .reserve_context_route(first.clone(), LeaseId::new(), 41, false)
        .expect("initial intent");
    assert!(
        store
            .reserve_context_route(next.clone(), LeaseId::new(), 41, false)
            .is_err()
    );
    store
        .set_context_route_phase(&first, ContextRoutePhase::Releasing, None)
        .expect("releasing");
    assert!(
        store
            .reserve_context_route(next.clone(), LeaseId::new(), 41, false)
            .is_err()
    );
    store
        .set_context_route_phase(&first, ContextRoutePhase::Released, None)
        .expect("released");
    store
        .reserve_context_route(next, LeaseId::new(), 41, true)
        .expect("cancel-before-attach tombstone");
    assert!(
        store
            .reserve_context_route(sibling(&spec, TenantId::new(), 3), LeaseId::new(), 41, true)
            .is_err()
    );
    assert_eq!(
        store.records().expect("records")[0].context_routes().len(),
        2
    );
}
