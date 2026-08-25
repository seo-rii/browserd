#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use browserd_core::{SessionId, ShardId, TenantId};
use browserd_egress::{
    CanonicalUrl, DnsResolution, EgressPolicy, MonotonicMillis, QuotaLimits, RouteBinding,
    RouteEndpoint, RouteError, RouteRegistry,
};

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

fn binding(shard_id: ShardId, expires_at: u64) -> RouteBinding {
    binding_with_epoch(shard_id, 7, expires_at)
}

fn binding_with_epoch(shard_id: ShardId, worker_epoch: u64, expires_at: u64) -> RouteBinding {
    RouteBinding::new(
        TenantId::new(),
        SessionId::new(),
        shard_id,
        worker_epoch,
        EgressPolicy::public_web_default(),
        limits(),
        MonotonicMillis::new(expires_at),
    )
}

fn public_resolution(host: &str) -> DnsResolution {
    DnsResolution::new(host, [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
}

#[test]
fn route_is_bound_to_an_exact_source_shard_and_worker_epoch() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(41);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    let other_shard = ShardId::new();
    let route = binding(shard.clone(), 20_000);
    let session_id = route.session_id().clone();

    assert!(
        registry
            .bind(endpoint, route, MonotonicMillis::new(1_000))
            .is_ok()
    );
    assert_eq!(
        registry.binding(endpoint, &other_shard, MonotonicMillis::new(1_001)),
        Err(RouteError::SourceShardMismatch)
    );
    let inspected = registry.binding(endpoint, &shard, MonotonicMillis::new(1_001));
    assert!(inspected.is_ok());
    if let Ok(inspected) = inspected {
        assert_eq!(inspected.session_id(), &session_id);
        assert_eq!(inspected.worker_epoch(), 7);
    }
    assert_eq!(
        registry.renew(
            endpoint,
            &shard,
            8,
            MonotonicMillis::new(1_001),
            MonotonicMillis::new(20_001),
        ),
        Err(RouteError::WorkerEpochMismatch {
            expected: 7,
            actual: 8,
        })
    );
}

#[test]
fn expired_routes_fail_closed_and_endpoints_are_never_rebound() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(7);
    assert!(endpoint.is_ok());
    let Ok(endpoint) = endpoint else {
        return;
    };
    let shard = ShardId::new();
    assert!(
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 2_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );

    assert_eq!(
        registry.binding(endpoint, &shard, MonotonicMillis::new(2_000)),
        Err(RouteError::RouteExpired)
    );
    assert_eq!(
        registry.bind(
            endpoint,
            binding(ShardId::new(), 4_000),
            MonotonicMillis::new(2_001),
        ),
        Err(RouteError::EndpointRetired)
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
    assert!(
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 2_000),
                MonotonicMillis::new(1_000),
            )
            .is_ok()
    );

    assert_eq!(
        registry.renew(
            endpoint,
            &shard,
            7,
            MonotonicMillis::new(1_500),
            MonotonicMillis::new(31_501),
        ),
        Err(RouteError::InvalidLeaseExpiry)
    );
    assert!(
        registry
            .renew(
                endpoint,
                &shard,
                7,
                MonotonicMillis::new(1_500),
                MonotonicMillis::new(10_000),
            )
            .is_ok()
    );
    assert_eq!(
        registry.renew(
            endpoint,
            &shard,
            7,
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
    assert!(
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 20_000),
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
        endpoint,
        &shard,
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
        Err(RouteError::Quota(
            browserd_egress::QuotaError::ResponseBytes
        ))
    );
    assert_eq!(registry.usage(endpoint).active_connections, 1);
    drop(permit);
    assert_eq!(registry.usage(endpoint).active_connections, 0);
    assert_eq!(registry.usage(endpoint).total_egress_bytes, 400);
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
    assert!(
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 20_000),
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
                endpoint,
                &shard,
                &url,
                DnsResolution::new("localhost", [IpAddr::V4(Ipv4Addr::LOCALHOST)]),
                MonotonicMillis::new(1_001),
            )
            .is_err()
    );
    let usage = registry.usage(endpoint);
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
    assert!(
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 20_000),
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
        registry.authorize_dns(endpoint, &other_shard, &url, MonotonicMillis::new(1_001)),
        Err(RouteError::SourceShardMismatch)
    ));
    assert_eq!(registry.usage(endpoint).dns_queries_in_window, 0);
    let permit = registry.authorize_dns(endpoint, &shard, &url, MonotonicMillis::new(1_001));
    assert!(permit.is_ok());
    assert_eq!(registry.usage(endpoint).dns_queries_in_window, 1);
    assert_eq!(registry.usage(endpoint).connection_starts_in_window, 0);
    let Ok(permit) = permit else {
        return;
    };
    let connection = permit.finish(
        public_resolution("example.com"),
        MonotonicMillis::new(1_002),
    );
    assert!(connection.is_ok());
    assert_eq!(registry.usage(endpoint).connection_starts_in_window, 1);
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
        assert!(
            registry
                .bind(
                    endpoint,
                    binding(shard.clone(), 20_000),
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
            let shard = shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.begin_connection(
                    endpoint,
                    &shard,
                    &url,
                    public_resolution("example.com"),
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
                registry.revoke(endpoint, &shard, 7)
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
            registry.binding(endpoint, &shard, MonotonicMillis::new(1_002)),
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
    registry
        .bind(
            first,
            binding(shard.clone(), 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("first route should bind");
    registry
        .bind(
            second,
            binding(shard.clone(), 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("second route should bind");
    registry
        .bind(
            unrelated,
            binding(other_shard.clone(), 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("unrelated route should bind");
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let first_permit = registry
        .authorize_dns(first, &shard, &url, MonotonicMillis::new(1_001))
        .expect("permit should be issued");
    let second_permit = registry
        .authorize_dns(second, &shard, &url, MonotonicMillis::new(1_001))
        .expect("permit should be issued");
    let first_cancellation = first_permit.cancellation_token();
    let second_cancellation = second_permit.cancellation_token();

    assert_eq!(registry.revoke_shard(&shard, 7), Ok(2));
    assert!(first_cancellation.is_cancelled());
    assert!(second_cancellation.is_cancelled());
    assert_eq!(
        registry.binding(first, &shard, MonotonicMillis::new(1_002)),
        Err(RouteError::RouteRevoked)
    );
    assert_eq!(
        registry.binding(second, &shard, MonotonicMillis::new(1_002)),
        Err(RouteError::RouteRevoked)
    );
    assert!(
        registry
            .binding(unrelated, &other_shard, MonotonicMillis::new(1_002))
            .is_ok()
    );
    assert_eq!(registry.revoke_shard(&shard, 7), Ok(0));
    assert_eq!(
        registry.bind(
            first,
            binding_with_epoch(shard.clone(), 8, 20_000),
            MonotonicMillis::new(1_003),
        ),
        Err(RouteError::EndpointRetired)
    );
}

#[test]
fn stale_shard_revocation_rejects_before_mutating_any_route() {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let first = RouteEndpoint::new(111).expect("endpoint should be valid");
    let second = RouteEndpoint::new(112).expect("endpoint should be valid");
    for endpoint in [first, second] {
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 20_000),
                MonotonicMillis::new(1_000),
            )
            .expect("route should bind");
    }
    let url = CanonicalUrl::parse("https://example.com/").expect("URL should be valid");
    let permit = registry
        .authorize_dns(first, &shard, &url, MonotonicMillis::new(1_001))
        .expect("permit should be issued");
    let cancellation = permit.cancellation_token();

    assert_eq!(
        registry.revoke_shard(&shard, 6),
        Err(RouteError::WorkerEpochMismatch {
            expected: 7,
            actual: 6,
        })
    );
    assert!(!cancellation.is_cancelled());
    for endpoint in [first, second] {
        assert!(
            registry
                .binding(endpoint, &shard, MonotonicMillis::new(1_002))
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
        registry
            .bind(
                existing,
                binding(shard.clone(), 20_000),
                MonotonicMillis::new(1_000),
            )
            .expect("existing route should bind");
        let barrier = Arc::new(Barrier::new(3));
        let binder = {
            let registry = Arc::clone(&registry);
            let shard = shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.bind(racing, binding(shard, 20_000), MonotonicMillis::new(1_001))
            })
        };
        let revoker = {
            let registry = Arc::clone(&registry);
            let shard = shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.revoke_shard(&shard, 7)
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
            registry.binding(existing, &shard, MonotonicMillis::new(1_002)),
            Err(RouteError::RouteRevoked)
        );
        let rebound = registry.bind(
            racing,
            binding(shard.clone(), 20_000),
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
        registry
            .bind(
                endpoint,
                binding(shard.clone(), 20_000),
                MonotonicMillis::new(1_000),
            )
            .expect("route should bind");
        let barrier = Arc::new(Barrier::new(3));
        let renewer = {
            let registry = Arc::clone(&registry);
            let shard = shard.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.renew(
                    endpoint,
                    &shard,
                    7,
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
                registry.revoke_shard(&shard, 7)
            })
        };
        barrier.wait();

        let renewal = renewer.join().expect("renewer should not panic");
        assert!(matches!(renewal, Ok(()) | Err(RouteError::RouteRevoked)));
        assert_eq!(revoker.join().expect("revoker should not panic"), Ok(1));
        assert_eq!(
            registry.binding(endpoint, &shard, MonotonicMillis::new(1_002)),
            Err(RouteError::RouteRevoked)
        );
    }
}

#[test]
fn registry_limits_bound_route_tombstones_and_shard_index_state() {
    let limits = browserd_egress::RouteRegistryLimits::new(2, 1);
    let registry = RouteRegistry::with_limits(Duration::from_secs(30), limits);
    let shard = ShardId::new();
    let first = RouteEndpoint::new(301).expect("endpoint should be valid");
    let second = RouteEndpoint::new(302).expect("endpoint should be valid");
    let third = RouteEndpoint::new(303).expect("endpoint should be valid");
    registry
        .bind(
            first,
            binding(shard.clone(), 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("first route should bind");
    assert_eq!(registry.revoke_shard(&shard, 7), Ok(1));
    registry
        .bind(
            second,
            binding_with_epoch(shard.clone(), 8, 20_000),
            MonotonicMillis::new(1_001),
        )
        .expect("new shard epoch should bind");
    assert_eq!(registry.revoke_shard(&shard, 8), Ok(1));

    assert_eq!(
        registry.bind(
            third,
            binding_with_epoch(shard.clone(), 9, 20_000),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::RouteCapacityExceeded)
    );
    assert_eq!(
        registry.bind(
            first,
            binding_with_epoch(shard, 9, 20_000),
            MonotonicMillis::new(1_002),
        ),
        Err(RouteError::EndpointRetired)
    );

    let other_shard = ShardId::new();
    let shard_limited = RouteRegistry::with_limits(
        Duration::from_secs(30),
        browserd_egress::RouteRegistryLimits::new(2, 1),
    );
    shard_limited
        .bind(
            first,
            binding(ShardId::new(), 20_000),
            MonotonicMillis::new(1_000),
        )
        .expect("first shard should bind");
    assert_eq!(
        shard_limited.bind(
            second,
            binding(other_shard, 20_000),
            MonotonicMillis::new(1_000),
        ),
        Err(RouteError::ShardCapacityExceeded)
    );
}
