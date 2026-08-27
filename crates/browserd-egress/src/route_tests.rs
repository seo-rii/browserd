#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use crate::{
    CanonicalUrl, DnsResolution, EgressPolicy, MonotonicMillis, QuotaError, QuotaLimits,
    RouteBinding, RouteClaim, RouteEndpoint, RouteError, RouteRegistry, RouteRegistryLimits,
};
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};

static NEXT_ROUTE_GENERATION: AtomicU64 = AtomicU64::new(10_000);

fn shard_fence_with_launch(
    shard_id: ShardId,
    worker_epoch: u64,
    launch_generation: u64,
) -> ShardFence {
    let worker_id = WorkerId::new("worker-a").expect("worker ID should be valid");
    let worker_epoch = WorkerEpoch::new(worker_epoch).expect("worker epoch should be nonzero");
    let launch_generation =
        LaunchGeneration::new(launch_generation).expect("launch generation should be nonzero");
    ShardFence::new(
        OwnerFence::new(worker_id, worker_epoch),
        shard_id,
        launch_generation,
    )
}

fn shard_fence(shard_id: ShardId, worker_epoch: u64) -> ShardFence {
    shard_fence_with_launch(shard_id, worker_epoch, worker_epoch)
}

fn exact_fence(
    shard_id: ShardId,
    session_id: SessionId,
    launch_generation: u64,
    route_generation: u64,
    session_incarnation: u64,
) -> EgressFence {
    let route_generation =
        RouteGeneration::new(route_generation).expect("route generation should be nonzero");
    let session_incarnation = SessionIncarnation::new(session_incarnation)
        .expect("session incarnation should be nonzero");
    EgressFence::new(
        shard_fence_with_launch(shard_id, 7, launch_generation),
        route_generation,
        session_id,
        session_incarnation,
    )
}

#[test]
fn route_binding_exposes_its_authoritative_expiry() {
    let expires_at = MonotonicMillis::new(20_000);
    let binding = RouteBinding::new(
        TenantId::new(),
        SessionId::new(),
        ShardId::new(),
        7,
        EgressPolicy::public_web_default(),
        limits(),
        expires_at,
    );

    assert_eq!(binding.expires_at(), expires_at);
}

#[test]
fn every_full_fence_component_is_required_to_control_an_endpoint() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(1_101).expect("endpoint should be valid");
    let shard_id = ShardId::new();
    let session_id = SessionId::new();
    let owner_fence = exact_fence(shard_id.clone(), session_id.clone(), 1, 1, 1);
    let owner_claim = RouteClaim::new(endpoint, owner_fence.clone());
    registry
        .prepare_shard(owner_fence.shard())
        .expect("exact shard fence should prepare");
    registry
        .bind(
            &owner_claim,
            RouteBinding::new(
                TenantId::new(),
                session_id.clone(),
                shard_id.clone(),
                7,
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("owner should bind");

    let stale_claims = [
        RouteClaim::new(
            endpoint,
            exact_fence(shard_id.clone(), session_id.clone(), 2, 1, 1),
        ),
        RouteClaim::new(
            endpoint,
            exact_fence(shard_id.clone(), session_id.clone(), 1, 2, 1),
        ),
        RouteClaim::new(
            endpoint,
            exact_fence(shard_id.clone(), SessionId::new(), 1, 1, 1),
        ),
        RouteClaim::new(endpoint, exact_fence(shard_id, session_id, 1, 1, 2)),
    ];

    for stale_claim in stale_claims {
        assert_eq!(
            registry.binding(&stale_claim, MonotonicMillis::new(1_001)),
            Err(RouteError::RouteNotFound)
        );
        assert_eq!(
            registry.renew(
                &stale_claim,
                MonotonicMillis::new(1_001),
                MonotonicMillis::new(20_001),
            ),
            Err(RouteError::RouteNotFound)
        );
        assert_eq!(
            registry.revoke(&stale_claim),
            Err(RouteError::RouteNotFound)
        );
        assert!(matches!(
            registry.begin_ingress(&stale_claim, MonotonicMillis::new(1_001)),
            Err(RouteError::RouteNotFound)
        ));
    }
}

#[test]
fn identical_endpoint_metadata_does_not_alias_distinct_full_fences() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(1_102).expect("endpoint should be valid");
    let first_shard = ShardId::new();
    let second_shard = ShardId::new();
    let first_session = SessionId::new();
    let second_session = SessionId::new();
    let first_fence = exact_fence(first_shard.clone(), first_session.clone(), 1, 1, 1);
    let second_fence = exact_fence(second_shard.clone(), second_session.clone(), 1, 2, 1);
    let first_claim = RouteClaim::new(endpoint, first_fence.clone());
    let second_claim = RouteClaim::new(endpoint, second_fence.clone());
    registry
        .prepare_shard(first_fence.shard())
        .expect("first shard should prepare");
    registry
        .prepare_shard(second_fence.shard())
        .expect("second shard should prepare");

    let first_identity = registry
        .bind(
            &first_claim,
            RouteBinding::new(
                TenantId::new(),
                first_session,
                first_shard,
                7,
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("first full fence should bind");
    let second_identity = registry
        .bind(
            &second_claim,
            RouteBinding::new(
                TenantId::new(),
                second_session,
                second_shard,
                7,
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("second full fence should bind independently");

    assert_ne!(first_identity, second_identity);
    assert_eq!(
        registry.binding(&first_claim, MonotonicMillis::new(1_001)),
        Ok(first_identity)
    );
    assert_eq!(
        registry.binding(&second_claim, MonotonicMillis::new(1_001)),
        Ok(second_identity)
    );

    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let mut first_permit = registry
        .begin_connection(
            &first_claim,
            &url,
            public_resolution("example.com"),
            MonotonicMillis::new(1_002),
        )
        .expect("first fence should open independently");
    first_permit
        .record_egress_bytes(123, MonotonicMillis::new(1_003))
        .expect("first fence should account bytes");
    assert_eq!(
        registry
            .usage(&first_claim)
            .expect("first usage should exist")
            .total_egress_bytes,
        123
    );
    assert_eq!(
        registry
            .usage(&second_claim)
            .expect("second usage should exist")
            .total_egress_bytes,
        0
    );
}

fn limits() -> QuotaLimits {
    QuotaLimits {
        max_concurrent_connections: 2,
        max_connection_starts_per_window: 3,
        max_dns_queries_per_window: 4,
        max_egress_bytes_per_window: 1_024,
        max_total_egress_bytes: 2_048,
        max_response_bytes: Some(512),
        accounting_window: Duration::from_secs(60),
        idle_connection_timeout: Duration::from_secs(10),
    }
}

fn binding(claim: &RouteClaim, expires_at: u64) -> RouteBinding {
    binding_with_epoch(claim, claim.worker_epoch(), expires_at)
}

fn binding_with_epoch(claim: &RouteClaim, worker_epoch: u64, expires_at: u64) -> RouteBinding {
    RouteBinding::new(
        TenantId::new(),
        claim.fence().session_id().clone(),
        claim.source_shard().clone(),
        worker_epoch,
        EgressPolicy::public_web_default(),
        limits(),
        MonotonicMillis::new(expires_at),
    )
}

fn prepare_shard(registry: &RouteRegistry, shard_id: &ShardId, worker_epoch: u64) {
    assert_eq!(
        registry.prepare_shard(&shard_fence(shard_id.clone(), worker_epoch)),
        Ok(())
    );
}

fn public_resolution(host: &str) -> DnsResolution {
    DnsResolution::new(host, [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
}

fn claim(endpoint: RouteEndpoint, shard_id: ShardId, worker_epoch: u64) -> RouteClaim {
    let route_generation = NEXT_ROUTE_GENERATION.fetch_add(1, Ordering::Relaxed);
    claim_with_generation(endpoint, route_generation, shard_id, worker_epoch)
}

fn claim_with_generation(
    endpoint: RouteEndpoint,
    generation: u64,
    shard_id: ShardId,
    worker_epoch: u64,
) -> RouteClaim {
    let route_generation =
        RouteGeneration::new(generation).expect("route generation should be nonzero");
    RouteClaim::new(
        endpoint,
        EgressFence::new(
            shard_fence(shard_id, worker_epoch),
            route_generation,
            SessionId::new(),
            SessionIncarnation::new(1).expect("session incarnation should be nonzero"),
        ),
    )
}

fn claim_with_session(
    endpoint: RouteEndpoint,
    shard_id: ShardId,
    worker_epoch: u64,
    session_id: SessionId,
) -> RouteClaim {
    let route_generation = NEXT_ROUTE_GENERATION.fetch_add(1, Ordering::Relaxed);
    RouteClaim::new(
        endpoint,
        EgressFence::new(
            shard_fence(shard_id, worker_epoch),
            RouteGeneration::new(route_generation).expect("route generation should be nonzero"),
            session_id,
            SessionIncarnation::new(1).expect("session incarnation should be nonzero"),
        ),
    )
}

#[test]
fn route_control_requires_the_exact_full_fence() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(41);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let other_shard = ShardId::new();
    let generation = 9;
    let route_claim = claim_with_generation(endpoint, generation, shard.clone(), 7);
    let other_shard_claim = claim_with_generation(endpoint, generation, other_shard, 7);
    let other_epoch_claim = claim_with_generation(endpoint, generation, shard.clone(), 8);
    let route = binding(&route_claim, 20_000);
    let session_id = route.session_id().clone();
    prepare_shard(&registry, &shard, 7);

    assert!(
        registry
            .bind(&route_claim, route, MonotonicMillis::new(1_000))
            .is_ok()
    );
    assert_eq!(
        registry.binding(&other_shard_claim, MonotonicMillis::new(1_001)),
        Err(RouteError::RouteNotFound)
    );
    let inspected = registry.binding(&route_claim, MonotonicMillis::new(1_001));
    assert!(inspected.is_ok());
    if let Ok(inspected) = inspected {
        assert_eq!(inspected.session_id(), &session_id);
        assert_eq!(inspected.worker_epoch(), 7);
    }
    assert_eq!(
        registry.renew(
            &other_epoch_claim,
            MonotonicMillis::new(1_001),
            MonotonicMillis::new(20_001),
        ),
        Err(RouteError::RouteNotFound)
    );
}

#[test]
fn a_session_cannot_split_or_reset_quota_across_route_endpoints() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let first = RouteEndpoint::new(42).expect("endpoint should be valid");
    let second = RouteEndpoint::new(43).expect("endpoint should be valid");
    let shard = ShardId::new();
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let first_claim = claim_with_session(first, shard.clone(), 7, session_id.clone());
    let second_claim = claim_with_session(second, shard.clone(), 7, session_id.clone());
    prepare_shard(&registry, &shard, 7);
    registry
        .bind(
            &first_claim,
            RouteBinding::new(
                tenant_id.clone(),
                session_id.clone(),
                shard.clone(),
                7,
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("first session route should bind");

    assert!(matches!(
        registry.bind(
            &second_claim,
            RouteBinding::new(
                tenant_id.clone(),
                session_id.clone(),
                shard.clone(),
                7,
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_001),
        ),
        Err(RouteError::SessionAlreadyBound)
    ));
    registry
        .revoke(&first_claim)
        .expect("first route should revoke");
    assert!(matches!(
        registry.bind(
            &second_claim,
            RouteBinding::new(
                tenant_id,
                session_id,
                shard,
                7,
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::SessionAlreadyBound)
    ));
}

#[test]
fn expired_full_fences_stay_terminal_without_retiring_endpoint_metadata() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(7);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    assert!(
        registry
            .bind(
                &route_claim,
                binding(&route_claim, 2_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );

    assert_eq!(
        registry.binding(&route_claim, MonotonicMillis::new(2_000)),
        Err(RouteError::RouteExpired)
    );
    let rebound_shard = ShardId::new();
    let rebound_claim = claim(endpoint, rebound_shard.clone(), 7);
    assert_eq!(
        registry.bind(
            &route_claim,
            binding(&route_claim, 4_000),
            MonotonicMillis::new(2_001),
        ),
        Err(RouteError::EndpointRetired)
    );
    prepare_shard(&registry, &rebound_shard, 7);
    assert!(
        registry
            .bind(
                &rebound_claim,
                binding(&rebound_claim, 4_000),
                MonotonicMillis::new(2_001),
            )
            .is_ok()
    );
}

#[test]
fn lease_renewal_is_bounded_and_cannot_revive_an_expired_route() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(10);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    assert!(
        registry
            .bind(
                &route_claim,
                binding(&route_claim, 2_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );

    assert_eq!(
        registry.renew(
            &route_claim,
            MonotonicMillis::new(1_500),
            MonotonicMillis::new(31_501),
        ),
        Err(RouteError::InvalidLeaseExpiry)
    );
    assert!(
        registry
            .renew(
                &route_claim,
                MonotonicMillis::new(1_500),
                MonotonicMillis::new(10_000),
            )
            .is_ok()
    );
    assert_eq!(
        registry.renew(
            &route_claim,
            MonotonicMillis::new(10_000),
            MonotonicMillis::new(11_000),
        ),
        Err(RouteError::RouteExpired)
    );
}

#[test]
fn connection_permit_uses_inspected_sockaddr_and_accounts_bytes() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(12);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    assert!(
        registry
            .bind(
                &route_claim,
                binding(&route_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );
    let url = CanonicalUrl::parse("https://example.com/");
    assert!(url.is_ok());
    let Ok(url) = url else {
        return;
    };

    let permit = registry.begin_connection(
        &route_claim,
        &url,
        public_resolution("example.com"),
        MonotonicMillis::new(1_001),
    );
    assert!(permit.is_ok());
    let Ok(mut permit) = permit else {
        return;
    };
    assert_eq!(
        permit.plan().inspected_socket_addr().as_socket_addr(),
        SocketAddr::from(([93, 184, 216, 34], 443))
    );
    assert!(
        permit
            .record_egress_bytes(400, MonotonicMillis::new(1_002))
            .is_ok()
    );
    assert_eq!(
        permit.record_egress_bytes(113, MonotonicMillis::new(1_003)),
        Err(RouteError::Quota(QuotaError::ResponseBytes))
    );
    assert_eq!(
        registry
            .usage(&route_claim)
            .expect("usage should exist")
            .active_connections,
        1
    );
    drop(permit);
    let usage = registry.usage(&route_claim).expect("usage should exist");
    assert_eq!(usage.active_connections, 0);
    assert_eq!(usage.total_egress_bytes, 400);
}

#[test]
fn retired_routes_retain_final_quota_usage_for_audit() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(16).expect("endpoint should be valid");
    let shard = ShardId::new();
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    registry
        .bind(
            &route_claim,
            binding(&route_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("route should bind");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let mut permit = registry
        .begin_connection(
            &route_claim,
            &url,
            public_resolution("example.com"),
            MonotonicMillis::new(1_001),
        )
        .expect("connection should open");
    permit
        .record_egress_bytes(123, MonotonicMillis::new(1_002))
        .expect("usage should be recorded");

    registry.revoke(&route_claim).expect("route should revoke");

    let usage = registry.usage(&route_claim).expect("usage should exist");
    assert_eq!(usage.active_connections, 0);
    assert_eq!(usage.connection_starts_in_window, 1);
    assert_eq!(usage.dns_queries_in_window, 1);
    assert_eq!(usage.total_egress_bytes, 123);
    drop(permit);
}

#[test]
fn denied_dns_answers_count_queries_but_never_consume_connection_capacity() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(13);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    assert!(
        registry
            .bind(
                &route_claim,
                binding(&route_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );
    let url = CanonicalUrl::parse("http://localhost/");
    assert!(url.is_ok());
    let Ok(url) = url else {
        return;
    };

    assert!(
        registry
            .begin_connection(
                &route_claim,
                &url,
                DnsResolution::new("localhost", [IpAddr::V4(Ipv4Addr::LOCALHOST)]),
                MonotonicMillis::new(1_001),
            )
            .is_err()
    );
    let usage = registry.usage(&route_claim).expect("usage should exist");
    assert_eq!(usage.dns_queries_in_window, 1);
    assert_eq!(usage.connection_starts_in_window, 0);
    assert_eq!(usage.active_connections, 0);
}

#[test]
fn pre_dns_permit_fences_route_identity_and_reserves_dns_quota() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(14);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let other_shard = ShardId::new();
    let generation = 11;
    let route_claim = claim_with_generation(endpoint, generation, shard.clone(), 7);
    let other_shard_claim = claim_with_generation(endpoint, generation, other_shard, 7);
    prepare_shard(&registry, &shard, 7);
    assert!(
        registry
            .bind(
                &route_claim,
                binding(&route_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );
    let url = CanonicalUrl::parse("https://example.com/");
    assert!(url.is_ok());
    let Ok(url) = url else {
        return;
    };

    assert!(matches!(
        registry.authorize_dns(&other_shard_claim, &url, MonotonicMillis::new(1_001)),
        Err(RouteError::RouteNotFound)
    ));
    assert_eq!(
        registry
            .usage(&route_claim)
            .expect("usage should exist")
            .dns_queries_in_window,
        0
    );
    let permit = registry.authorize_dns(&route_claim, &url, MonotonicMillis::new(1_001));
    assert!(permit.is_ok());
    let usage = registry.usage(&route_claim).expect("usage should exist");
    assert_eq!(usage.dns_queries_in_window, 1);
    assert_eq!(usage.connection_starts_in_window, 0);
    let Ok(permit) = permit else {
        return;
    };
    let connection = permit.finish(
        public_resolution("example.com"),
        MonotonicMillis::new(1_002),
    );
    assert!(connection.is_ok());
    assert_eq!(
        registry
            .usage(&route_claim)
            .expect("usage should exist")
            .connection_starts_in_window,
        1
    );
}

#[test]
fn pending_ingress_reserves_connection_capacity_until_dropped() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(15).expect("endpoint should be valid");
    let shard = ShardId::new();
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    let mut quota_limits = limits();
    quota_limits.max_concurrent_connections = 1;
    registry
        .bind(
            &route_claim,
            RouteBinding::new(
                TenantId::new(),
                route_claim.fence().session_id().clone(),
                shard.clone(),
                7,
                EgressPolicy::public_web_default(),
                quota_limits,
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("route should bind");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");

    let first = registry
        .authorize_dns(&route_claim, &url, MonotonicMillis::new(1_001))
        .expect("first pre-DNS permit should reserve capacity");
    let usage = registry.usage(&route_claim).expect("usage should exist");
    assert_eq!(usage.active_connections, 0);
    assert_eq!(usage.connection_starts_in_window, 0);
    assert!(matches!(
        registry.begin_ingress(&route_claim, MonotonicMillis::new(1_002)),
        Err(RouteError::Quota(QuotaError::ConcurrentConnections))
    ));

    drop(first);
    assert!(
        registry
            .begin_ingress(&route_claim, MonotonicMillis::new(1_003))
            .is_ok()
    );
}

#[test]
fn revocation_fences_existing_permits_and_wins_races_with_new_connections() {
    for iteration in 1..=100 {
        let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
        let endpoint = RouteEndpoint::new(iteration);
        assert!(endpoint.is_ok());
        let Ok(endpoint) = endpoint else {
            continue;
        };
        let shard = ShardId::new();
        let route_claim = claim(endpoint, shard.clone(), 7);
        prepare_shard(&registry, &shard, 7);
        assert!(
            registry
                .bind(
                    &route_claim,
                    binding(&route_claim, 20_000),
                    MonotonicMillis::new(1_000),
                )
                .is_ok()
        );
        let url = CanonicalUrl::parse("https://example.com/");
        assert!(url.is_ok());
        let Ok(url) = url else {
            continue;
        };
        let barrier = Arc::new(Barrier::new(3));

        let connector = {
            let registry = Arc::clone(&registry);
            let route_claim = route_claim.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.begin_connection(
                    &route_claim,
                    &url,
                    public_resolution("example.com"),
                    MonotonicMillis::new(1_001),
                )
            })
        };
        let revoker = {
            let registry = Arc::clone(&registry);
            let route_claim = route_claim.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.revoke(&route_claim)
            })
        };
        barrier.wait();

        let permit = connector.join();
        let revoked = revoker.join();
        assert!(revoked.is_ok_and(|outcome| outcome.is_ok()));
        if let Ok(Ok(mut permit)) = permit {
            assert_eq!(
                permit.record_egress_bytes(1, MonotonicMillis::new(1_002)),
                Err(RouteError::RouteRevoked)
            );
        }
        assert_eq!(
            registry.binding(&route_claim, MonotonicMillis::new(1_002)),
            Err(RouteError::RouteRevoked)
        );
    }
}

#[test]
fn shard_revocation_is_atomic_idempotent_and_retires_every_bound_endpoint() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let other_shard = ShardId::new();
    let first = RouteEndpoint::new(101).expect("endpoint should be valid");
    let second = RouteEndpoint::new(102).expect("endpoint should be valid");
    let unrelated = RouteEndpoint::new(103).expect("endpoint should be valid");
    let first_claim = claim(first, shard.clone(), 7);
    let second_claim = claim(second, shard.clone(), 7);
    let unrelated_claim = claim(unrelated, other_shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    prepare_shard(&registry, &other_shard, 7);
    registry
        .bind(
            &first_claim,
            binding(&first_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("first route should bind");
    registry
        .bind(
            &second_claim,
            binding(&second_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("second route should bind");
    registry
        .bind(
            &unrelated_claim,
            binding(&unrelated_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("unrelated route should bind");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let first_permit = registry
        .authorize_dns(&first_claim, &url, MonotonicMillis::new(1_001))
        .expect("permit should be issued");
    let second_permit = registry
        .authorize_dns(&second_claim, &url, MonotonicMillis::new(1_001))
        .expect("permit should be issued");
    let first_cancellation = first_permit.cancellation_token();
    let second_cancellation = second_permit.cancellation_token();

    assert_eq!(registry.revoke_shard(first_claim.fence().shard()), Ok(2));
    assert!(first_cancellation.is_cancelled());
    assert!(second_cancellation.is_cancelled());
    assert_eq!(
        registry.binding(&first_claim, MonotonicMillis::new(1_002)),
        Err(RouteError::RouteRevoked)
    );
    assert_eq!(
        registry.binding(&second_claim, MonotonicMillis::new(1_002)),
        Err(RouteError::RouteRevoked)
    );
    assert!(
        registry
            .binding(&unrelated_claim, MonotonicMillis::new(1_002))
            .is_ok()
    );
    assert_eq!(registry.revoke_shard(first_claim.fence().shard()), Ok(0));
    let rebound_claim = claim(first, shard.clone(), 8);
    assert_eq!(
        registry.bind(
            &rebound_claim,
            binding(&rebound_claim, 20_000),
            MonotonicMillis::new(1_003),
        ),
        Err(RouteError::ShardFenceMismatch)
    );
}

#[test]
fn stale_shard_revocation_rejects_before_mutating_any_route() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let first = RouteEndpoint::new(111).expect("endpoint should be valid");
    let second = RouteEndpoint::new(112).expect("endpoint should be valid");
    let first_claim = claim(first, shard.clone(), 7);
    let second_claim = claim(second, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    for route_claim in [&first_claim, &second_claim] {
        registry
            .bind(
                route_claim,
                binding(route_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .expect("route should bind");
    }
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let permit = registry
        .authorize_dns(&first_claim, &url, MonotonicMillis::new(1_001))
        .expect("permit should be issued");
    let cancellation = permit.cancellation_token();

    assert_eq!(
        registry.revoke_shard(&shard_fence(shard.clone(), 6)),
        Err(RouteError::ShardFenceMismatch)
    );
    assert!(!cancellation.is_cancelled());
    for route_claim in [&first_claim, &second_claim] {
        assert!(
            registry
                .binding(route_claim, MonotonicMillis::new(1_002))
                .is_ok()
        );
    }
}

#[test]
fn concurrent_bind_and_shard_revoke_never_leave_an_old_epoch_route_active() {
    for iteration in 0..100 {
        let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
        let shard = ShardId::new();
        let existing = RouteEndpoint::new(1_000 + iteration * 2).expect("endpoint should be valid");
        let racing = RouteEndpoint::new(1_001 + iteration * 2).expect("endpoint should be valid");
        let existing_claim = claim(existing, shard.clone(), 7);
        let racing_claim = claim(racing, shard.clone(), 7);
        prepare_shard(&registry, &shard, 7);
        registry
            .bind(
                &existing_claim,
                binding(&existing_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .expect("existing route should bind");
        let barrier = Arc::new(Barrier::new(3));
        let binder = {
            let registry = Arc::clone(&registry);
            let racing_claim = racing_claim.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.bind(
                    &racing_claim,
                    binding(&racing_claim, 20_000),
                    MonotonicMillis::new(1_001),
                )
            })
        };
        let revoker = {
            let registry = Arc::clone(&registry);
            let shard = shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.revoke_shard(&shard_fence(shard, 7))
            })
        };
        barrier.wait();

        let bind_result = binder.join().expect("binder should not panic");
        let revoked = revoker
            .join()
            .expect("revoker should not panic")
            .expect("revocation should succeed");
        assert_eq!(revoked, usize::from(bind_result.is_ok()) + 1);
        assert_eq!(
            registry.binding(&existing_claim, MonotonicMillis::new(1_002)),
            Err(RouteError::RouteRevoked)
        );
        let rebound = registry.bind(
            &racing_claim,
            binding(&racing_claim, 20_000),
            MonotonicMillis::new(1_003),
        );
        assert!(matches!(
            rebound,
            Err(RouteError::EndpointRetired | RouteError::ShardRevoked)
        ));
    }
}

#[test]
fn concurrent_renew_and_shard_revoke_always_finish_revoked() {
    for iteration in 0..100 {
        let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
        let shard = ShardId::new();
        let endpoint = RouteEndpoint::new(2_000 + iteration).expect("endpoint should be valid");
        let route_claim = claim(endpoint, shard.clone(), 7);
        prepare_shard(&registry, &shard, 7);
        registry
            .bind(
                &route_claim,
                binding(&route_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .expect("route should bind");
        let barrier = Arc::new(Barrier::new(3));
        let renewer = {
            let registry = Arc::clone(&registry);
            let route_claim = route_claim.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.renew(
                    &route_claim,
                    MonotonicMillis::new(1_001),
                    MonotonicMillis::new(20_001),
                )
            })
        };
        let revoker = {
            let registry = Arc::clone(&registry);
            let shard = shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.revoke_shard(&shard_fence(shard, 7))
            })
        };
        barrier.wait();

        let renewal = renewer.join().expect("renewer should not panic");
        assert!(matches!(renewal, Ok(()) | Err(RouteError::RouteRevoked)));
        assert_eq!(revoker.join().expect("revoker should not panic"), Ok(1));
        assert_eq!(
            registry.binding(&route_claim, MonotonicMillis::new(1_002)),
            Err(RouteError::RouteRevoked)
        );
    }
}

#[test]
fn registry_limits_bound_route_tombstones_and_shard_index_state() {
    let limits = RouteRegistryLimits::new(2, 1);
    let registry = RouteRegistry::with_limits(Duration::from_secs(30), limits);
    let shard = ShardId::new();
    let first = RouteEndpoint::new(301).expect("endpoint should be valid");
    let second = RouteEndpoint::new(302).expect("endpoint should be valid");
    let third = RouteEndpoint::new(303).expect("endpoint should be valid");
    let first_claim = claim(first, shard.clone(), 7);
    let second_claim = claim(second, shard.clone(), 8);
    let third_claim = claim(third, shard.clone(), 9);
    let first_rebound_claim = claim(first, shard.clone(), 9);
    prepare_shard(&registry, &shard, 7);
    registry
        .bind(
            &first_claim,
            binding(&first_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("first route should bind");
    assert_eq!(registry.revoke_shard(first_claim.fence().shard()), Ok(1));
    assert_eq!(registry.release_shard(first_claim.fence().shard()), Ok(()));
    prepare_shard(&registry, &shard, 8);
    registry
        .bind(
            &second_claim,
            binding(&second_claim, 20_000),
            MonotonicMillis::new(1_001),
        )
        .expect("new shard epoch should bind");
    assert_eq!(registry.revoke_shard(second_claim.fence().shard()), Ok(1));
    assert_eq!(registry.release_shard(second_claim.fence().shard()), Ok(()));
    prepare_shard(&registry, &shard, 9);

    assert_eq!(
        registry.bind(
            &third_claim,
            binding(&third_claim, 20_000),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::RouteCapacityExceeded)
    );
    assert_eq!(
        registry.bind(
            &first_rebound_claim,
            binding(&first_rebound_claim, 20_000),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::RouteCapacityExceeded)
    );

    let first_shard = ShardId::new();
    let other_shard = ShardId::new();
    let shard_limited =
        RouteRegistry::with_limits(Duration::from_secs(30), RouteRegistryLimits::new(2, 1));
    prepare_shard(&shard_limited, &first_shard, 7);
    let limited_claim = claim(first, first_shard.clone(), 7);
    shard_limited
        .bind(
            &limited_claim,
            binding(&limited_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("first shard should bind");
    assert_eq!(
        shard_limited.prepare_shard(&shard_fence(other_shard, 7)),
        Err(RouteError::ShardCapacityExceeded)
    );
}

#[test]
fn zero_max_lease_rejects_shard_prepare_before_registry_state_is_mutated() {
    let registry = RouteRegistry::with_limits(Duration::ZERO, RouteRegistryLimits::new(1, 1));
    let first = ShardId::new();
    let second = ShardId::new();

    assert_eq!(
        registry.prepare_shard(&shard_fence(first, 7)),
        Err(RouteError::InvalidRegistryConfig)
    );
    assert_eq!(
        registry.prepare_shard(&shard_fence(second, 7)),
        Err(RouteError::InvalidRegistryConfig)
    );
}

#[test]
fn session_bind_requires_an_explicit_exact_epoch_shard_prepare() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(401).expect("endpoint should be valid");
    let exact_claim = claim(endpoint, shard.clone(), 7);
    let old_claim = claim(endpoint, shard.clone(), 6);
    let future_claim = claim(endpoint, shard.clone(), 8);

    assert_eq!(
        registry.bind(
            &exact_claim,
            binding(&exact_claim, 20_000),
            MonotonicMillis::new(1_000),
        ),
        Err(RouteError::ShardNotPrepared)
    );
    assert_eq!(registry.prepare_shard(exact_claim.fence().shard()), Ok(()));
    assert_eq!(registry.prepare_shard(exact_claim.fence().shard()), Ok(()));
    assert_eq!(
        registry.bind(
            &old_claim,
            binding(&old_claim, 20_000),
            MonotonicMillis::new(1_000),
        ),
        Err(RouteError::ShardFenceMismatch)
    );
    assert_eq!(
        registry.bind(
            &future_claim,
            binding(&future_claim, 20_000),
            MonotonicMillis::new(1_000),
        ),
        Err(RouteError::ShardFenceMismatch)
    );
    assert!(
        registry
            .bind(
                &exact_claim,
                binding(&exact_claim, 20_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );
}

#[test]
fn only_released_shards_can_advance_to_a_new_worker_epoch() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let old_endpoint = RouteEndpoint::new(411).expect("endpoint should be valid");
    let new_endpoint = RouteEndpoint::new(412).expect("endpoint should be valid");
    let old_claim = claim(old_endpoint, shard.clone(), 7);
    let new_claim = claim(new_endpoint, shard.clone(), 7);
    let next_epoch_claim = claim(new_endpoint, shard.clone(), 8);
    assert_eq!(registry.prepare_shard(old_claim.fence().shard()), Ok(()));
    assert_eq!(
        registry.prepare_shard(&shard_fence(shard.clone(), 6)),
        Err(RouteError::WorkerEpochMismatch {
            expected: 7,
            actual: 6,
        })
    );
    assert_eq!(
        registry.prepare_shard(next_epoch_claim.fence().shard()),
        Err(RouteError::ShardNotReleased)
    );
    assert_eq!(
        registry.release_shard(old_claim.fence().shard()),
        Err(RouteError::ShardNotRevoked)
    );
    registry
        .bind(
            &old_claim,
            binding(&old_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("prepared shard should accept a route");
    assert_eq!(registry.revoke_shard(old_claim.fence().shard()), Ok(1));
    assert_eq!(
        registry.bind(
            &new_claim,
            binding(&new_claim, 20_000),
            MonotonicMillis::new(1_001),
        ),
        Err(RouteError::ShardRevoked)
    );
    assert_eq!(
        registry.bind(
            &next_epoch_claim,
            binding(&next_epoch_claim, 20_000),
            MonotonicMillis::new(1_001),
        ),
        Err(RouteError::ShardFenceMismatch)
    );
    assert_eq!(registry.release_shard(old_claim.fence().shard()), Ok(()));
    assert_eq!(registry.release_shard(old_claim.fence().shard()), Ok(()));
    assert_eq!(
        registry.prepare_shard(old_claim.fence().shard()),
        Err(RouteError::ShardReleased)
    );
    assert_eq!(
        registry.bind(
            &next_epoch_claim,
            binding(&next_epoch_claim, 20_000),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::ShardFenceMismatch)
    );
    assert_eq!(
        registry.prepare_shard(next_epoch_claim.fence().shard()),
        Ok(())
    );
    assert!(
        registry
            .bind(
                &next_epoch_claim,
                binding(&next_epoch_claim, 20_000),
                MonotonicMillis::new(1_002),
            )
            .is_ok()
    );
}

#[test]
fn worker_epoch_high_watermark_fences_every_shard_in_the_registry() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let first = ShardId::new();
    let second = ShardId::new();
    let next_epoch = ShardId::new();
    let same_next_epoch = ShardId::new();

    assert_eq!(
        registry.prepare_shard(&shard_fence(first.clone(), 8)),
        Ok(())
    );
    assert_eq!(
        registry.prepare_shard(&shard_fence(second.clone(), 7)),
        Err(RouteError::WorkerEpochMismatch {
            expected: 8,
            actual: 7,
        })
    );
    assert_eq!(
        registry.prepare_shard(&shard_fence(second.clone(), 8)),
        Ok(())
    );
    assert_eq!(
        registry.prepare_shard(&shard_fence(next_epoch.clone(), 9)),
        Err(RouteError::ShardNotReleased)
    );

    assert_eq!(registry.revoke_shard(&shard_fence(first.clone(), 8)), Ok(0));
    assert_eq!(registry.release_shard(&shard_fence(first, 8)), Ok(()));
    assert_eq!(
        registry.prepare_shard(&shard_fence(next_epoch.clone(), 9)),
        Err(RouteError::ShardNotReleased)
    );

    assert_eq!(
        registry.revoke_shard(&shard_fence(second.clone(), 8)),
        Ok(0)
    );
    assert_eq!(registry.release_shard(&shard_fence(second, 8)), Ok(()));
    assert_eq!(registry.prepare_shard(&shard_fence(next_epoch, 9)), Ok(()));
    assert_eq!(
        registry.prepare_shard(&shard_fence(same_next_epoch, 9)),
        Ok(())
    );
    assert_eq!(
        registry.prepare_shard(&shard_fence(ShardId::new(), 8)),
        Err(RouteError::WorkerEpochMismatch {
            expected: 9,
            actual: 8,
        })
    );
}

#[test]
fn advancing_worker_epoch_reclaims_released_shard_capacity_without_reviving_it() {
    let registry =
        RouteRegistry::with_limits(Duration::from_secs(30), RouteRegistryLimits::new(2, 1));
    let released = ShardId::new();
    let replacement = ShardId::new();

    assert_eq!(
        registry.prepare_shard(&shard_fence(released.clone(), 7)),
        Ok(())
    );
    assert_eq!(
        registry.revoke_shard(&shard_fence(released.clone(), 7)),
        Ok(0)
    );
    assert_eq!(
        registry.release_shard(&shard_fence(released.clone(), 7)),
        Ok(())
    );

    assert_eq!(registry.prepare_shard(&shard_fence(replacement, 8)), Ok(()));
    assert_eq!(
        registry.prepare_shard(&shard_fence(released, 7)),
        Err(RouteError::WorkerEpochMismatch {
            expected: 8,
            actual: 7,
        })
    );
}

#[test]
fn release_waits_for_pre_dns_and_connection_permits_to_drain() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(421).expect("endpoint should be valid");
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    let mut quota_limits = limits();
    quota_limits.max_concurrent_connections = 3;
    registry
        .bind(
            &route_claim,
            RouteBinding::new(
                TenantId::new(),
                route_claim.fence().session_id().clone(),
                shard.clone(),
                7,
                EgressPolicy::public_web_default(),
                quota_limits,
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("route should bind");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let pre_dns = registry
        .authorize_dns(&route_claim, &url, MonotonicMillis::new(1_001))
        .expect("pre-DNS permit should open");
    let mut connection = registry
        .authorize_dns(&route_claim, &url, MonotonicMillis::new(1_001))
        .expect("second pre-DNS permit should open")
        .finish(
            public_resolution("example.com"),
            MonotonicMillis::new(1_002),
        )
        .expect("connection permit should open");
    let dropped_connection = registry
        .authorize_dns(&route_claim, &url, MonotonicMillis::new(1_003))
        .expect("third pre-DNS permit should open")
        .finish(
            public_resolution("example.com"),
            MonotonicMillis::new(1_004),
        )
        .expect("second connection permit should open");

    assert_eq!(registry.revoke_shard(route_claim.fence().shard()), Ok(1));
    assert_eq!(
        registry.release_shard(route_claim.fence().shard()),
        Err(RouteError::ShardNotDrained)
    );
    drop(pre_dns);
    assert_eq!(
        registry.release_shard(route_claim.fence().shard()),
        Err(RouteError::ShardNotDrained)
    );
    assert!(connection.close());
    assert_eq!(
        registry.release_shard(route_claim.fence().shard()),
        Err(RouteError::ShardNotDrained)
    );
    drop(dropped_connection);
    assert_eq!(registry.release_shard(route_claim.fence().shard()), Ok(()));
}

#[test]
fn a_cancelled_pre_dns_finish_drops_its_shard_drain_guard() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(422).expect("endpoint should be valid");
    let route_claim = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    registry
        .bind(
            &route_claim,
            binding(&route_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("route should bind");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let pre_dns = registry
        .authorize_dns(&route_claim, &url, MonotonicMillis::new(1_001))
        .expect("pre-DNS permit should open");

    assert_eq!(registry.revoke_shard(route_claim.fence().shard()), Ok(1));
    assert_eq!(
        registry.release_shard(route_claim.fence().shard()),
        Err(RouteError::ShardNotDrained)
    );
    assert!(matches!(
        pre_dns.finish(
            public_resolution("example.com"),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::RouteRevoked)
    ));
    assert_eq!(registry.release_shard(route_claim.fence().shard()), Ok(()));
}

#[test]
fn concurrent_revoke_release_and_prepare_preserve_global_epoch_order() {
    for _ in 0..100 {
        let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
        let old_shard = ShardId::new();
        let new_shard = ShardId::new();
        prepare_shard(&registry, &old_shard, 7);
        let barrier = Arc::new(Barrier::new(4));

        let revoker = {
            let registry = Arc::clone(&registry);
            let old_shard = old_shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.revoke_shard(&shard_fence(old_shard, 7))
            })
        };
        let releaser = {
            let registry = Arc::clone(&registry);
            let old_shard = old_shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.release_shard(&shard_fence(old_shard, 7))
            })
        };
        let preparer = {
            let registry = Arc::clone(&registry);
            let new_shard = new_shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.prepare_shard(&shard_fence(new_shard, 8))
            })
        };
        barrier.wait();

        assert_eq!(revoker.join().expect("revoker should not panic"), Ok(0));
        let release = releaser.join().expect("releaser should not panic");
        assert!(matches!(
            &release,
            Ok(()) | Err(RouteError::ShardNotRevoked)
        ));
        let prepare = preparer.join().expect("preparer should not panic");
        assert!(matches!(
            &prepare,
            Ok(()) | Err(RouteError::ShardNotReleased)
        ));
        if prepare.is_ok() {
            assert_eq!(release, Ok(()));
        }

        assert_eq!(registry.release_shard(&shard_fence(old_shard, 7)), Ok(()));
        assert_eq!(registry.prepare_shard(&shard_fence(new_shard, 8)), Ok(()));
    }
}

#[test]
fn exact_bind_retry_returns_the_original_route_without_resetting_usage() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(501).expect("endpoint should be valid");
    let claim = claim(endpoint, shard.clone(), 7);
    let route = binding(&claim, 20_000);
    prepare_shard(&registry, claim.source_shard(), claim.worker_epoch());

    let first = registry
        .bind(&claim, route.clone(), MonotonicMillis::new(1_000))
        .expect("first bind should commit");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let permit = registry
        .begin_connection(
            &claim,
            &url,
            public_resolution("example.com"),
            MonotonicMillis::new(1_001),
        )
        .expect("connection should open");
    let cancellation = permit.cancellation_token();
    drop(permit);
    let usage_before_retry = registry.usage(&claim).expect("usage should exist");

    let retried = registry
        .bind(&claim, route, MonotonicMillis::new(1_002))
        .expect("an exact response-loss retry should be idempotent");

    assert_eq!(retried, first);
    assert_eq!(registry.usage(&claim), Ok(usage_before_retry));
    assert_eq!(usage_before_retry.connection_starts_in_window, 1);
    assert_eq!(registry.revoke(&claim), Ok(()));
    assert!(cancellation.is_cancelled());
}

#[test]
fn route_generation_fences_conflicting_bind_and_control_requests() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(502).expect("endpoint should be valid");
    let owner = claim(endpoint, shard.clone(), 7);
    let stale = RouteClaim::new(
        endpoint,
        EgressFence::new(
            owner.fence().shard().clone(),
            RouteGeneration::new(NEXT_ROUTE_GENERATION.fetch_add(1, Ordering::Relaxed))
                .expect("route generation should be nonzero"),
            owner.fence().session_id().clone(),
            owner.fence().session_incarnation(),
        ),
    );
    prepare_shard(&registry, &shard, 7);
    let original = registry
        .bind(&owner, binding(&owner, 20_000), MonotonicMillis::new(1_000))
        .expect("owner should bind");
    let ingress = registry
        .begin_ingress(&owner, MonotonicMillis::new(1_001))
        .expect("owner ingress should open");
    let cancellation = ingress.cancellation_token();
    drop(ingress);

    assert_eq!(
        registry.bind(&stale, binding(&stale, 20_000), MonotonicMillis::new(1_001),),
        Err(RouteError::SessionAlreadyBound)
    );
    assert_eq!(
        registry.binding(&stale, MonotonicMillis::new(1_001)),
        Err(RouteError::RouteNotFound)
    );
    assert_eq!(
        registry.renew(
            &stale,
            MonotonicMillis::new(1_001),
            MonotonicMillis::new(21_000),
        ),
        Err(RouteError::RouteNotFound)
    );
    assert_eq!(registry.revoke(&stale), Err(RouteError::RouteNotFound));
    assert!(!cancellation.is_cancelled());
    assert_eq!(
        registry.binding(&owner, MonotonicMillis::new(1_001)),
        Ok(original.clone())
    );

    assert_eq!(
        registry.bind(&owner, binding(&owner, 20_000), MonotonicMillis::new(1_002),),
        Err(RouteError::BindingConflict)
    );
    assert_eq!(
        registry.binding(&owner, MonotonicMillis::new(1_002)),
        Ok(original)
    );
}

#[test]
fn exact_retired_revoke_is_idempotent_but_another_generation_fails_closed() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(503).expect("endpoint should be valid");
    let owner = claim(endpoint, shard.clone(), 7);
    let stale = claim(endpoint, shard.clone(), 7);
    prepare_shard(&registry, &shard, 7);
    registry
        .bind(&owner, binding(&owner, 20_000), MonotonicMillis::new(1_000))
        .expect("owner should bind");

    assert_eq!(registry.revoke(&owner), Ok(()));
    assert_eq!(registry.revoke(&owner), Ok(()));
    assert_eq!(registry.revoke(&stale), Err(RouteError::RouteNotFound));
}

#[test]
fn concurrent_exact_bind_retries_commit_one_route_identity() {
    let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(504).expect("endpoint should be valid");
    let claim = claim(endpoint, shard.clone(), 7);
    let route = binding(&claim, 20_000);
    prepare_shard(&registry, &shard, 7);
    let barrier = Arc::new(Barrier::new(3));

    let spawn_bind = || {
        let registry = Arc::clone(&registry);
        let claim = claim.clone();
        let route = route.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            registry.bind(&claim, route, MonotonicMillis::new(1_000))
        })
    };
    let first = spawn_bind();
    let second = spawn_bind();
    barrier.wait();

    let first = first
        .join()
        .expect("first bind thread should join")
        .expect("first exact bind should succeed");
    let second = second
        .join()
        .expect("second bind thread should join")
        .expect("second exact bind should succeed");
    assert_eq!(first, second);
    assert_eq!(first.claim(), &claim);
}

#[test]
fn concurrent_conflicting_generations_leave_one_exact_owner() {
    for iteration in 0..100 {
        let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
        let shard = ShardId::new();
        let endpoint = RouteEndpoint::new(600 + iteration).expect("endpoint should be valid");
        let session_id = SessionId::new();
        let first_claim = claim_with_session(endpoint, shard.clone(), 7, session_id.clone());
        let second_claim = claim_with_session(endpoint, shard.clone(), 7, session_id);
        let route = binding(&first_claim, 20_000);
        prepare_shard(&registry, &shard, 7);
        let barrier = Arc::new(Barrier::new(3));

        let spawn_bind = |route_claim: RouteClaim| {
            let registry = Arc::clone(&registry);
            let route = route.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.bind(&route_claim, route, MonotonicMillis::new(1_000))
            })
        };
        let first = spawn_bind(first_claim.clone());
        let second = spawn_bind(second_claim.clone());
        barrier.wait();

        let first = first.join().expect("first bind thread should join");
        let second = second.join().expect("second bind thread should join");
        assert!(matches!(
            (&first, &second),
            (Ok(_), Err(RouteError::SessionAlreadyBound))
                | (Err(RouteError::SessionAlreadyBound), Ok(_))
        ));
        let (winner, loser) = match (first, second) {
            (Ok(identity), Err(RouteError::SessionAlreadyBound)) => {
                assert_eq!(identity.claim(), &first_claim);
                (&first_claim, &second_claim)
            }
            (Err(RouteError::SessionAlreadyBound), Ok(identity)) => {
                assert_eq!(identity.claim(), &second_claim);
                (&second_claim, &first_claim)
            }
            _ => (&first_claim, &second_claim),
        };

        assert_eq!(registry.revoke(loser), Err(RouteError::RouteNotFound));
        assert!(
            registry
                .binding(winner, MonotonicMillis::new(1_001))
                .is_ok()
        );
    }
}

#[test]
fn exact_bind_replay_and_revoke_never_resurrect_a_route() {
    for iteration in 0..100 {
        let registry = Arc::new(RouteRegistry::new(Duration::from_secs(30)));
        let shard = ShardId::new();
        let endpoint = RouteEndpoint::new(800 + iteration).expect("endpoint should be valid");
        let route_claim = claim(endpoint, shard.clone(), 7);
        let route = binding(&route_claim, 20_000);
        prepare_shard(&registry, &shard, 7);
        registry
            .bind(&route_claim, route.clone(), MonotonicMillis::new(1_000))
            .expect("initial bind should commit");
        let barrier = Arc::new(Barrier::new(3));

        let replay = {
            let registry = Arc::clone(&registry);
            let route_claim = route_claim.clone();
            let route = route.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.bind(&route_claim, route, MonotonicMillis::new(1_001))
            })
        };
        let revoke = {
            let registry = Arc::clone(&registry);
            let route_claim = route_claim.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.revoke(&route_claim)
            })
        };
        barrier.wait();

        let replay = replay.join().expect("replay thread should join");
        assert!(matches!(replay, Ok(_) | Err(RouteError::EndpointRetired)));
        assert_eq!(revoke.join().expect("revoke thread should join"), Ok(()));
        assert_eq!(
            registry.binding(&route_claim, MonotonicMillis::new(1_002)),
            Err(RouteError::RouteRevoked)
        );
    }
}

#[test]
fn stale_pre_restart_claim_cannot_control_a_rebound_generation() {
    let endpoint = RouteEndpoint::new(1_001).expect("endpoint should be valid");
    let shard = ShardId::new();
    let stale_claim = claim(endpoint, shard.clone(), 7);
    let old_registry = RouteRegistry::new(Duration::from_secs(30));
    prepare_shard(&old_registry, &shard, 7);
    old_registry
        .bind(
            &stale_claim,
            binding(&stale_claim, 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("old generation should bind before restart");

    let restarted_registry = RouteRegistry::new(Duration::from_secs(30));
    let rebound_claim = claim(endpoint, shard.clone(), 7);
    let rebound_route = binding(&rebound_claim, 20_000);
    prepare_shard(&restarted_registry, &shard, 7);
    let rebound_identity = restarted_registry
        .bind(&rebound_claim, rebound_route, MonotonicMillis::new(1_000))
        .expect("new generation should bind after restart");

    assert_eq!(
        restarted_registry.binding(&stale_claim, MonotonicMillis::new(1_001)),
        Err(RouteError::RouteNotFound)
    );
    assert_eq!(
        restarted_registry.renew(
            &stale_claim,
            MonotonicMillis::new(1_001),
            MonotonicMillis::new(21_000),
        ),
        Err(RouteError::RouteNotFound)
    );
    assert_eq!(
        restarted_registry.revoke(&stale_claim),
        Err(RouteError::RouteNotFound)
    );
    assert_eq!(
        restarted_registry.binding(&rebound_claim, MonotonicMillis::new(1_001)),
        Ok(rebound_identity)
    );
}
