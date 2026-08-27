#![allow(clippy::expect_used)]

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::unistd::{dup, pipe, write};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    EgressPolicy, MonotonicMillis, QuotaLimits, RouteBinding, RouteClaim, RouteEndpoint,
    RouteError, RouteIngressError, RouteIngressListener, RouteRegistry,
};

fn bound_route(endpoint_value: u64) -> (RouteRegistry, RouteClaim, ShardFence) {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let shard = ShardId::new();
    let endpoint = RouteEndpoint::new(endpoint_value).expect("endpoint should be nonzero");
    let session_id = SessionId::new();
    let shard_fence = ShardFence::new(
        OwnerFence::new(
            WorkerId::new("worker-a").expect("worker ID should be valid"),
            WorkerEpoch::new(7).expect("worker epoch should be nonzero"),
        ),
        shard.clone(),
        LaunchGeneration::new(1).expect("launch generation should be nonzero"),
    );
    let claim = RouteClaim::new(
        endpoint,
        EgressFence::new(
            shard_fence.clone(),
            RouteGeneration::new(1).expect("route generation should be nonzero"),
            session_id.clone(),
            SessionIncarnation::new(1).expect("session incarnation should be nonzero"),
        ),
    );
    registry
        .prepare_shard(&shard_fence)
        .expect("shard should prepare");
    registry
        .bind(
            &claim,
            RouteBinding::new(
                TenantId::new(),
                session_id,
                shard.clone(),
                7,
                EgressPolicy::public_web_default(),
                QuotaLimits {
                    max_concurrent_connections: 2,
                    max_connection_starts_per_window: 4,
                    max_dns_queries_per_window: 4,
                    max_egress_bytes_per_window: 1_024,
                    max_total_egress_bytes: 2_048,
                    max_response_bytes: Some(512),
                    accounting_window: Duration::from_secs(60),
                    idle_connection_timeout: Duration::from_secs(10),
                },
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("route should bind");
    (registry, claim, shard_fence)
}

#[tokio::test]
async fn owned_pipe_descriptor_is_rejected_and_closed() {
    let (registry, claim, _) = bound_route(506);
    let (read, pipe_writer) = pipe().expect("pipe should open");
    fcntl(&read, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .expect("pipe descriptor should gain CLOEXEC");
    let result = RouteIngressListener::from_owned_fd(read, claim, registry);

    assert!(matches!(
        result,
        Err(RouteIngressError::InvalidDescriptor(_))
    ));
    assert_eq!(
        write(&pipe_writer, b"ownership probe"),
        Err(nix::errno::Errno::EPIPE)
    );
    drop(pipe_writer);
}

#[tokio::test]
async fn connected_tcp_descriptor_is_rejected_and_closed() {
    let (registry, claim, _) = bound_route(507);
    let server = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("blocking listener should bind");
    let server_addr = server
        .local_addr()
        .expect("listener should have a local address");
    let connected =
        std::net::TcpStream::connect(server_addr).expect("blocking client should connect");
    let (mut peer, _) = server.accept().expect("server should accept client");
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("peer read timeout should configure");
    let owned: OwnedFd = connected.into();

    let result = RouteIngressListener::from_owned_fd(owned, claim, registry);

    assert!(matches!(result, Err(RouteIngressError::NotListeningSocket)));
    let mut byte = [0_u8; 1];
    assert!(matches!(peer.read(&mut byte), Ok(0)));
    drop(peer);
    drop(server);
}

#[tokio::test]
async fn descriptor_without_cloexec_is_rejected_and_closed() {
    let (registry, claim, _) = bound_route(508);
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("blocking listener should bind");
    let without_cloexec = dup(&listener).expect("listener descriptor should duplicate");
    let descriptor_flags = FdFlag::from_bits_retain(
        fcntl(&without_cloexec, FcntlArg::F_GETFD).expect("descriptor flags should be readable"),
    );
    assert!(!descriptor_flags.contains(FdFlag::FD_CLOEXEC));
    let local_addr = listener
        .local_addr()
        .expect("listener should have a local address");
    drop(listener);

    let result = RouteIngressListener::from_owned_fd(without_cloexec, claim, registry);

    assert!(matches!(result, Err(RouteIngressError::MissingCloseOnExec)));
    assert!(std::net::TcpListener::bind(local_addr).is_ok());
}

#[tokio::test]
async fn blocking_owned_tcp_listener_becomes_nonblocking_and_accepts() {
    let (registry, claim, _) = bound_route(509);
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("blocking listener should bind");
    listener
        .set_nonblocking(false)
        .expect("listener should be blocking before transfer");
    let local_addr = listener
        .local_addr()
        .expect("listener should have a local address");
    let owned: OwnedFd = listener.into();
    let observer = dup(&owned).expect("listener descriptor should duplicate for flag checks");
    let descriptor_flags = FdFlag::from_bits_retain(
        fcntl(&owned, FcntlArg::F_GETFD).expect("descriptor flags should be readable"),
    );
    assert!(descriptor_flags.contains(FdFlag::FD_CLOEXEC));
    let blocking_flags = OFlag::from_bits_retain(
        fcntl(&observer, FcntlArg::F_GETFL).expect("status flags should be readable"),
    );
    assert!(!blocking_flags.contains(OFlag::O_NONBLOCK));

    let route_listener =
        RouteIngressListener::from_owned_fd(owned, claim.clone(), registry.clone())
            .expect("valid listener capability should be accepted");

    let nonblocking_flags = OFlag::from_bits_retain(
        fcntl(&observer, FcntlArg::F_GETFL).expect("status flags should remain readable"),
    );
    assert!(nonblocking_flags.contains(OFlag::O_NONBLOCK));
    assert_eq!(route_listener.local_addr(), local_addr);
    drop(observer);
    assert!(std::net::TcpListener::bind(local_addr).is_err());
    drop(route_listener);
    let rebound = std::net::TcpListener::bind(local_addr)
        .expect("dropping the capability should close its owned listener");
    let rebound_owned: OwnedFd = rebound.into();
    let route_listener = RouteIngressListener::from_owned_fd(rebound_owned, claim, registry)
        .expect("rebound listener capability should be accepted");
    let client = TcpStream::connect(local_addr)
        .await
        .expect("client should connect");
    let accepted = route_listener
        .accept(|| MonotonicMillis::new(1_001))
        .await
        .expect("transferred listener should accept exact route ingress");
    drop(accepted);
    drop(client);
    drop(route_listener);
}

#[tokio::test]
async fn listener_rejects_non_loopback_local_addresses() {
    let (registry, claim, _) = bound_route(501);
    let raw = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await
        .expect("unspecified listener should bind for validation");
    let local_addr = raw
        .local_addr()
        .expect("listener should have a local address");

    let result = RouteIngressListener::new(raw, claim, registry);

    assert!(matches!(
        result,
        Err(RouteIngressError::InvalidLocalAddress(address)) if address == local_addr
    ));
}

#[tokio::test]
async fn listener_accepts_a_connection_for_its_exact_claim() {
    let (registry, claim, _) = bound_route(502);
    let raw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let local_addr = raw
        .local_addr()
        .expect("listener should have a local address");
    let listener = RouteIngressListener::new(raw, claim, registry)
        .expect("loopback listener should be accepted");
    assert_eq!(listener.local_addr(), local_addr);
    assert!(listener.local_addr().ip().is_loopback());
    assert_ne!(listener.local_addr().port(), 0);
    let client = TcpStream::connect(local_addr)
        .await
        .expect("client should connect");

    let accepted = listener.accept(|| MonotonicMillis::new(1_001)).await;

    assert!(accepted.is_ok());
    drop(accepted);
    drop(client);
}

#[tokio::test]
async fn accept_reads_the_clock_once_after_the_socket_is_accepted() {
    let (registry, claim, _) = bound_route(505);
    let raw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let local_addr = raw
        .local_addr()
        .expect("listener should have a local address");
    let listener = RouteIngressListener::new(raw, claim, registry)
        .expect("loopback listener should be accepted");
    let clock_calls = AtomicUsize::new(0);
    let accepted_at = MonotonicMillis::new(1_234);
    let mut accepting = Box::pin(listener.accept(|| {
        clock_calls.fetch_add(1, Ordering::SeqCst);
        accepted_at
    }));

    assert!(
        tokio::time::timeout(Duration::from_millis(10), accepting.as_mut())
            .await
            .is_err()
    );
    assert_eq!(clock_calls.load(Ordering::SeqCst), 0);
    let client = TcpStream::connect(local_addr)
        .await
        .expect("client should connect");
    let accepted = accepting.await.expect("exact route should accept ingress");
    assert_eq!(clock_calls.load(Ordering::SeqCst), 1);
    let (_, _, observed_at) = accepted.into_parts();
    assert_eq!(observed_at, accepted_at);
    drop(client);
}

#[tokio::test]
async fn an_accepted_connection_blocks_shard_release_before_a_serve_task_exists() {
    let (registry, claim, shard) = bound_route(503);
    let raw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let local_addr = raw
        .local_addr()
        .expect("listener should have a local address");
    let listener = RouteIngressListener::new(raw, claim, registry.clone())
        .expect("loopback listener should be accepted");
    let client = TcpStream::connect(local_addr)
        .await
        .expect("client should connect");
    let accepted = listener
        .accept(|| MonotonicMillis::new(1_001))
        .await
        .expect("exact route should accept ingress");

    assert_eq!(registry.revoke_shard(&shard), Ok(1));
    assert_eq!(
        registry.release_shard(&shard),
        Err(RouteError::ShardNotDrained)
    );
    drop(accepted);
    assert_eq!(registry.release_shard(&shard), Ok(()));
    drop(client);
}

#[tokio::test]
async fn wrong_generation_and_revoked_routes_fail_closed_after_accept() {
    let (registry, claim, _) = bound_route(504);
    let wrong_claim = RouteClaim::new(
        claim.endpoint(),
        EgressFence::new(
            claim.fence().shard().clone(),
            RouteGeneration::new(2).expect("route generation should be nonzero"),
            claim.fence().session_id().clone(),
            claim.fence().session_incarnation(),
        ),
    );
    let wrong_raw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let wrong_addr = wrong_raw
        .local_addr()
        .expect("listener should have a local address");
    let wrong_listener = RouteIngressListener::new(wrong_raw, wrong_claim, registry.clone())
        .expect("loopback listener should be accepted");
    let wrong_client = TcpStream::connect(wrong_addr)
        .await
        .expect("client should connect");

    assert!(matches!(
        wrong_listener.accept(|| MonotonicMillis::new(1_001)).await,
        Err(RouteIngressError::Route(RouteError::RouteNotFound))
    ));
    drop(wrong_client);

    let revoked_raw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let revoked_addr = revoked_raw
        .local_addr()
        .expect("listener should have a local address");
    let revoked_listener = RouteIngressListener::new(revoked_raw, claim.clone(), registry.clone())
        .expect("loopback listener should be accepted");
    registry.revoke(&claim).expect("route should revoke");
    let revoked_client = TcpStream::connect(revoked_addr)
        .await
        .expect("client should connect");

    assert!(matches!(
        revoked_listener
            .accept(|| MonotonicMillis::new(1_002))
            .await,
        Err(RouteIngressError::Route(RouteError::RouteRevoked))
    ));
    drop(revoked_client);
}

#[tokio::test]
async fn accept_racing_revoke_never_releases_a_shard_with_a_live_guard() {
    for endpoint_value in 600..632 {
        let (registry, claim, shard) = bound_route(endpoint_value);
        let raw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");
        let local_addr = raw
            .local_addr()
            .expect("listener should have a local address");
        let listener = RouteIngressListener::new(raw, claim, registry.clone())
            .expect("loopback listener should be accepted");
        let revoke_registry = registry.clone();
        let revoke_shard = shard.clone();
        let revoke = async move {
            tokio::task::yield_now().await;
            revoke_registry.revoke_shard(&revoke_shard)
        };

        let (accepted, client, revoked) = tokio::join!(
            listener.accept(|| MonotonicMillis::new(1_001)),
            TcpStream::connect(local_addr),
            revoke,
        );

        assert!(client.is_ok());
        assert_eq!(revoked, Ok(1));
        match accepted {
            Ok(accepted) => {
                assert_eq!(
                    registry.release_shard(&shard),
                    Err(RouteError::ShardNotDrained)
                );
                drop(accepted);
                assert_eq!(registry.release_shard(&shard), Ok(()));
            }
            Err(error) => {
                assert!(matches!(
                    error,
                    RouteIngressError::Route(RouteError::RouteRevoked)
                ));
                assert_eq!(registry.release_shard(&shard), Ok(()));
            }
        }
    }
}
