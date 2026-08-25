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
    RouteBinding::new(
        TenantId::new(),
        SessionId::new(),
        shard_id,
        7,
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
