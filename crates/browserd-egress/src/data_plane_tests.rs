#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::{
    BoxedEgressIo, Connector, DataPlane, DataPlaneError, DataPlaneLimits, DnsResolution,
    EgressPolicy, InspectedSocketAddr, MonotonicMillis, QuotaLimits, Resolver, RouteBinding,
    RouteClaim, RouteEndpoint, RouteError, RouteIngressListener, RouteRegistry,
    VerifiedRouteSource,
};
use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;

#[derive(Clone)]
struct FakeResolver {
    calls: Arc<Mutex<Vec<String>>>,
    gate: Option<Arc<Notify>>,
}

#[async_trait]
impl Resolver for FakeResolver {
    async fn resolve(&self, host: &str) -> Result<DnsResolution, DataPlaneError> {
        self.calls
            .lock()
            .expect("resolver lock should work")
            .push(host.to_owned());
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        Ok(DnsResolution::new(
            host,
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        ))
    }
}

#[derive(Clone)]
struct FakeConnector {
    targets: Arc<Mutex<Vec<SocketAddr>>>,
    upstream: Arc<Mutex<Option<DuplexStream>>>,
}

#[derive(Clone)]
struct GatedConnector {
    started: Arc<Notify>,
    gate: Arc<Notify>,
}

struct StagedWriteIo {
    writes_remaining: usize,
    write_completed: Arc<Notify>,
    write_blocked: Arc<Notify>,
}

struct BlockingRelayClientIo {
    request: Vec<u8>,
    request_offset: usize,
    writes_before_blocking: usize,
    completed_writes: Arc<Mutex<Vec<Vec<u8>>>>,
    blocked: Arc<Notify>,
}

struct StalledHeaderIo {
    read_polled: Arc<Notify>,
}

impl AsyncRead for StalledHeaderIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.read_polled.notify_one();
        Poll::Pending
    }
}

impl AsyncWrite for StalledHeaderIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for BlockingRelayClientIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.request_offset == self.request.len() {
            return Poll::Pending;
        }
        let remaining = &self.request[self.request_offset..];
        let read = remaining.len().min(buffer.remaining());
        buffer.put_slice(&remaining[..read]);
        self.request_offset += read;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BlockingRelayClientIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.writes_before_blocking == 0 {
            self.blocked.notify_one();
            return Poll::Pending;
        }
        self.writes_before_blocking -= 1;
        self.completed_writes
            .lock()
            .expect("completed-writes lock should work")
            .push(buffer.to_vec());
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct HangingShutdownIo {
    shutdown_started: Arc<Notify>,
}

impl AsyncRead for HangingShutdownIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for HangingShutdownIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.shutdown_started.notify_one();
        Poll::Pending
    }
}

#[derive(Clone)]
struct HangingShutdownConnector {
    upstream: Arc<Mutex<Option<HangingShutdownIo>>>,
}

#[async_trait]
impl Connector for HangingShutdownConnector {
    async fn connect(&self, _target: InspectedSocketAddr) -> Result<BoxedEgressIo, DataPlaneError> {
        self.upstream
            .lock()
            .expect("upstream lock should work")
            .take()
            .map(|stream| Box::new(stream) as BoxedEgressIo)
            .ok_or_else(|| DataPlaneError::Connect("missing hanging upstream".into()))
    }
}

impl AsyncRead for StagedWriteIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for StagedWriteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.writes_remaining == 0 {
            self.write_blocked.notify_one();
            return Poll::Pending;
        }
        self.writes_remaining -= 1;
        self.write_completed.notify_one();
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct StagedConnector {
    upstream: Arc<Mutex<Option<StagedWriteIo>>>,
}

#[async_trait]
impl Connector for StagedConnector {
    async fn connect(&self, _target: InspectedSocketAddr) -> Result<BoxedEgressIo, DataPlaneError> {
        self.upstream
            .lock()
            .expect("upstream lock should work")
            .take()
            .map(|stream| Box::new(stream) as BoxedEgressIo)
            .ok_or_else(|| DataPlaneError::Connect("missing staged upstream".into()))
    }
}

#[async_trait]
impl Connector for GatedConnector {
    async fn connect(&self, _target: InspectedSocketAddr) -> Result<BoxedEgressIo, DataPlaneError> {
        self.started.notify_one();
        self.gate.notified().await;
        Err(DataPlaneError::Connect("gate unexpectedly opened".into()))
    }
}

#[async_trait]
impl Connector for FakeConnector {
    async fn connect(&self, target: InspectedSocketAddr) -> Result<BoxedEgressIo, DataPlaneError> {
        self.targets
            .lock()
            .expect("target lock should work")
            .push(target.as_socket_addr());
        self.upstream
            .lock()
            .expect("upstream lock should work")
            .take()
            .map(|stream| Box::new(stream) as BoxedEgressIo)
            .ok_or_else(|| DataPlaneError::Connect("missing fake upstream".into()))
    }
}

fn limits() -> QuotaLimits {
    QuotaLimits {
        max_concurrent_connections: 4,
        max_connection_starts_per_window: 8,
        max_dns_queries_per_window: 8,
        max_egress_bytes_per_window: 4_096,
        max_total_egress_bytes: 8_192,
        max_response_bytes: Some(2_048),
        accounting_window: Duration::from_secs(60),
        idle_connection_timeout: Duration::from_secs(2),
    }
}

fn setup() -> (RouteRegistry, RouteClaim) {
    setup_with_limits(limits())
}

fn setup_with_limits(quota_limits: QuotaLimits) -> (RouteRegistry, RouteClaim) {
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let endpoint = RouteEndpoint::new(71).expect("endpoint should be valid");
    let shard = ShardId::new();
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
            shard_fence,
            RouteGeneration::new(1).expect("route generation should be nonzero"),
            session_id.clone(),
            SessionIncarnation::new(1).expect("session incarnation should be nonzero"),
        ),
    );
    registry
        .prepare_shard(claim.fence().shard())
        .expect("shard should be prepared");
    registry
        .bind(
            &claim,
            RouteBinding::new(
                TenantId::new(),
                session_id,
                shard.clone(),
                claim.worker_epoch(),
                EgressPolicy::public_web_default(),
                quota_limits,
                MonotonicMillis::new(20_000),
            ),
            MonotonicMillis::new(1_000),
        )
        .expect("route should bind");
    (registry, claim)
}

fn data_limits() -> DataPlaneLimits {
    DataPlaneLimits {
        header_timeout: Duration::from_secs(1),
        dns_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(2),
        write_timeout: Duration::from_secs(1),
        max_request_body_bytes: 1_024,
        ..DataPlaneLimits::default()
    }
}

fn safety_cache(
    snapshot: browserd_core::SafetySwitchSnapshot,
    ttl: Duration,
) -> Arc<browserd_core::RuntimeSafetyCache> {
    let cache = Arc::new(browserd_core::RuntimeSafetyCache::new());
    cache
        .install(*TenantId::new().as_uuid(), snapshot, ttl)
        .expect("initial authority");
    cache
}

fn update_safety(
    cache: &browserd_core::RuntimeSafetyCache,
    mutation: browserd_core::SafetySwitchMutation,
) {
    let namespace = cache.generation().expect("fresh namespace").namespace_id();
    let snapshot = cache
        .with_fresh_snapshot(|snapshot| snapshot.apply(&mutation))
        .expect("fresh")
        .expect("mutation");
    cache
        .install(namespace, snapshot, Duration::from_secs(5))
        .expect("new authority revision");
}

#[test]
fn runtime_denied_unselected_dns_candidate_rejects_the_entire_actual_route_plan() {
    let snapshot = browserd_core::SafetySwitchSnapshot::default()
        .apply(&browserd_core::SafetySwitchMutation::SetDeniedIp {
            ip: "::ffff:1.1.1.1".parse().expect("mapped public IP"),
            denied: true,
        })
        .expect("canonical IP deny");
    let cache = safety_cache(snapshot, Duration::from_secs(5));
    let (registry, claim) = setup();
    let registry = registry.with_runtime_safety(cache);
    let url = crate::CanonicalUrl::parse("https://example.com/").expect("URL");
    let pre_dns = registry
        .authorize_dns(&claim, &url, MonotonicMillis::new(1001))
        .expect("host admitted");
    assert!(matches!(
        pre_dns.finish(
            DnsResolution::new(
                "example.com",
                [
                    "93.184.216.34".parse().expect("selected IP"),
                    "1.1.1.1".parse().expect("later denied IP"),
                ]
            ),
            MonotonicMillis::new(1002)
        ),
        Err(RouteError::Plan(crate::PlanError::EmergencyIpDenied))
    ));
    let usage = registry.usage(&claim).expect("usage");
    assert_eq!(usage.active_connections, 0);
    assert_eq!(usage.connection_starts_in_window, 0);
}

#[tokio::test]
async fn runtime_domain_and_subdomain_denial_prevents_autonomous_dns() {
    for host in ["example.com", "assets.example.com"] {
        let snapshot = browserd_core::SafetySwitchSnapshot::default()
            .apply(&browserd_core::SafetySwitchMutation::SetDeniedDomain {
                domain: "EXAMPLE.COM.".into(),
                denied: true,
            })
            .expect("domain deny");
        let cache = safety_cache(snapshot, Duration::from_secs(5));
        let (registry, claim) = setup();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let service = DataPlane::new(
            registry.with_runtime_safety(cache),
            FakeResolver {
                calls: calls.clone(),
                gate: None,
            },
            FakeConnector {
                targets: targets.clone(),
                upstream: Arc::new(Mutex::new(None)),
            },
            data_limits(),
        )
        .expect("service");
        let (mut client, server) = tokio::io::duplex(2048);
        client
            .write_all(
                format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes(),
            )
            .await
            .expect("request");
        assert!(matches!(
            service
                .serve_verified_connection(
                    VerifiedRouteSource::new(claim),
                    server,
                    MonotonicMillis::new(1001)
                )
                .await,
            Err(DataPlaneError::Route(RouteError::Plan(
                crate::PlanError::EmergencyDomainDenied
            )))
        ));
        assert!(calls.lock().expect("calls").is_empty());
        assert!(targets.lock().expect("targets").is_empty());
    }
}

#[tokio::test]
async fn runtime_revision_cancels_blocked_dns_and_connect_before_more_effects() {
    for block_dns in [true, false] {
        let cache = safety_cache(
            browserd_core::SafetySwitchSnapshot::default(),
            Duration::from_secs(5),
        );
        let (registry, claim) = setup();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connect_started = Arc::new(Notify::new());
        let service = DataPlane::new(
            registry.with_runtime_safety(cache.clone()),
            FakeResolver {
                calls: calls.clone(),
                gate: block_dns.then(|| Arc::new(Notify::new())),
            },
            GatedConnector {
                started: connect_started.clone(),
                gate: Arc::new(Notify::new()),
            },
            data_limits(),
        )
        .expect("service");
        let (mut client, server) = tokio::io::duplex(2048);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .expect("request");
        let serve = tokio::spawn(async move {
            service
                .serve_verified_connection(
                    VerifiedRouteSource::new(claim),
                    server,
                    MonotonicMillis::new(1001),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            if block_dns {
                while calls.lock().expect("calls").is_empty() {
                    tokio::task::yield_now().await;
                }
            } else {
                connect_started.notified().await;
            }
        })
        .await
        .expect("entered gated effect");
        update_safety(
            &cache,
            browserd_core::SafetySwitchMutation::SetDeniedIp {
                ip: "93.184.216.34".parse().expect("ip"),
                denied: true,
            },
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), serve)
                .await
                .expect("cancels promptly")
                .expect("join"),
            Err(DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable))
        ));
        if block_dns {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), connect_started.notified())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn runtime_freshness_deadline_closes_header_stall_without_observer_polls() {
    let cache = safety_cache(
        browserd_core::SafetySwitchSnapshot::default(),
        Duration::from_millis(100),
    );
    let (registry, claim) = setup();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let service = DataPlane::new(
        registry.with_runtime_safety(cache),
        FakeResolver {
            calls: calls.clone(),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(None)),
        },
        data_limits(),
    )
    .expect("service");
    let (_client, server) = tokio::io::duplex(2048);
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            service.serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1001)
            )
        )
        .await
        .expect("freshness timer"),
        Err(DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable))
    ));
    assert!(calls.lock().expect("calls").is_empty());
}

#[tokio::test]
async fn runtime_same_version_refresh_preserves_long_connect_then_new_deny_closes_it() {
    let cache = safety_cache(
        browserd_core::SafetySwitchSnapshot::default(),
        Duration::from_millis(500),
    );
    let (registry, claim) = setup();
    let (proxy, mut origin) = tokio::io::duplex(4096);
    let service = DataPlane::new(
        registry.with_runtime_safety(cache.clone()),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy))),
        },
        data_limits(),
    )
    .expect("service");
    let (mut client, server) = tokio::io::duplex(4096);
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1001),
            )
            .await
    });
    let mut response = [0; 39];
    client.read_exact(&mut response).await.expect("established");
    let generation = cache.generation().expect("initial generation");
    let snapshot = cache
        .with_fresh_snapshot(Clone::clone)
        .expect("exact snapshot");
    cache
        .install(generation.namespace_id(), snapshot, Duration::from_secs(2))
        .expect("exact polling refresh");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !serve.is_finished(),
        "old captured expiry must rearm from exact refresh"
    );
    client.write_all(b"alive").await.expect("healthy flow");
    let mut bytes = [0; 5];
    tokio::time::timeout(Duration::from_secs(1), origin.read_exact(&mut bytes))
        .await
        .expect("still routed")
        .expect("origin read");
    assert_eq!(&bytes, b"alive");
    update_safety(
        &cache,
        browserd_core::SafetySwitchMutation::SetDeniedDomain {
            domain: "example.com".into(),
            denied: true,
        },
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), serve)
            .await
            .expect("existing tunnel closes")
            .expect("join"),
        Err(DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable))
    ));
    assert_eq!(origin.read(&mut bytes).await.expect("origin closed"), 0);
}

#[tokio::test]
async fn delayed_accepted_handler_uses_current_shared_registry_time() {
    use crate::{
        AcceptedIngressHandler, AcceptedRouteIngress, AttachmentManager, BindingDigest,
        DaemonEpoch, IngressHandlerError,
    };
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct QueueConnector(Arc<Mutex<VecDeque<DuplexStream>>>);
    #[async_trait]
    impl Connector for QueueConnector {
        async fn connect(
            &self,
            _target: InspectedSocketAddr,
        ) -> Result<BoxedEgressIo, DataPlaneError> {
            self.0
                .lock()
                .expect("queue lock")
                .pop_front()
                .map(|stream| Box::new(stream) as BoxedEgressIo)
                .ok_or_else(|| DataPlaneError::Connect("missing test origin".into()))
        }
    }
    struct DelayedHandler {
        service: DataPlane<FakeResolver, QueueConnector>,
        accepted: AtomicUsize,
        first_accepted: Notify,
        release_first: Notify,
        completed: Notify,
        results: Mutex<Vec<Result<(), DataPlaneError>>>,
    }
    #[async_trait]
    impl AcceptedIngressHandler for DelayedHandler {
        async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
            if self.accepted.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_accepted.notify_one();
                self.release_first.notified().await;
            }
            let result = self.service.serve_accepted_connection(ingress).await;
            self.results.lock().expect("results lock").push(result);
            self.completed.notify_one();
            Ok(())
        }
    }
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let (first_upstream, mut first_origin) = tokio::io::duplex(4_096);
    let (second_upstream, mut second_origin) = tokio::io::duplex(4_096);
    let handler = Arc::new(DelayedHandler {
        service: DataPlane::new(
            registry.clone(),
            FakeResolver {
                calls: Arc::new(Mutex::new(Vec::new())),
                gate: None,
            },
            QueueConnector(Arc::new(Mutex::new(VecDeque::from([
                first_upstream,
                second_upstream,
            ])))),
            data_limits(),
        )
        .expect("limits"),
        accepted: AtomicUsize::new(0),
        first_accepted: Notify::new(),
        release_first: Notify::new(),
        completed: Notify::new(),
        results: Mutex::new(Vec::new()),
    });
    let manager = AttachmentManager::with_registry(
        DaemonEpoch::new(7).expect("epoch"),
        registry,
        handler.clone(),
    );
    let (_, fixture_claim) = setup();
    let route_fence = fixture_claim.fence().clone();
    let prepared = manager
        .prepare(route_fence.clone(), BindingDigest::new([7; 32]))
        .expect("prepare");
    let raw = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
    let address = raw.local_addr().expect("address");
    let active = manager
        .install(
            &prepared,
            RouteBinding::new(
                TenantId::new(),
                route_fence.session_id().clone(),
                route_fence.shard().shard_id().clone(),
                route_fence.shard().owner().worker_epoch().get(),
                EgressPolicy::public_web_default(),
                limits(),
                MonotonicMillis::new(manager.now().value() + 10_000),
            ),
            raw.into(),
        )
        .await
        .expect("install");
    let origin_task = tokio::spawn(async move {
        for origin in [&mut first_origin, &mut second_origin] {
            let mut request = Vec::new();
            origin
                .read_to_end(&mut request)
                .await
                .expect("forwarded request EOF");
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .expect("response");
            origin.shutdown().await.expect("origin EOF");
        }
    });
    let mut first = tokio::net::TcpStream::connect(address)
        .await
        .expect("first");
    first
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("first request");
    handler.first_accepted.notified().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut second = tokio::net::TcpStream::connect(address)
        .await
        .expect("second");
    second
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("second request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), second.read_to_end(&mut response))
        .await
        .expect("second completes")
        .expect("second response");
    handler.completed.notified().await;
    assert!(handler.results.lock().expect("results")[0].is_ok());
    handler.release_first.notify_one();
    tokio::time::timeout(Duration::from_secs(1), handler.completed.notified())
        .await
        .expect("delayed first completes");
    assert!(
        handler.results.lock().expect("results")[1].is_ok(),
        "older acceptance must not move shared quota time backwards"
    );
    response.clear();
    first
        .read_to_end(&mut response)
        .await
        .expect("first response");
    assert!(response.ends_with(b"OK"));
    origin_task.await.expect("origin task joins");
    manager.revoke(&active).await.expect("exact cleanup");
}

#[tokio::test]
async fn accepted_listener_capability_is_the_public_data_plane_entrypoint() {
    let (registry, claim) = setup();
    let raw = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("loopback listener should bind");
    let address = raw.local_addr().expect("listener should have an address");
    let listener = RouteIngressListener::new(raw, claim, registry.clone())
        .expect("listener should be attributed");
    let mut client = tokio::net::TcpStream::connect(address)
        .await
        .expect("client should connect");
    client
        .write_all(b"not-http\r\n\r\n")
        .await
        .expect("invalid request should write");
    let accepted = listener
        .accept(|| MonotonicMillis::new(1_001))
        .await
        .expect("attributed ingress should accept");
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(None)),
        },
        data_limits(),
    )
    .expect("limits should be valid");

    let result = service.serve_accepted_connection(accepted).await;

    assert!(matches!(result, Err(DataPlaneError::Request(_))));
}

#[tokio::test]
async fn wrong_source_route_cannot_trigger_dns_even_with_proxy_credentials() {
    let (registry, claim) = setup();
    let resolver_calls = Arc::new(Mutex::new(Vec::new()));
    let connector_targets = Arc::new(Mutex::new(Vec::new()));
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: resolver_calls.clone(),
            gate: None,
        },
        FakeConnector {
            targets: connector_targets.clone(),
            upstream: Arc::new(Mutex::new(None)),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dHJ1c3QtbWU=\r\n\r\n",
        )
        .await
        .expect("request should write");

    let result = service
        .serve_verified_connection(
            VerifiedRouteSource::new(RouteClaim::new(
                claim.endpoint(),
                EgressFence::new(
                    ShardFence::new(
                        claim.fence().shard().owner().clone(),
                        ShardId::new(),
                        claim.fence().shard().launch_generation(),
                    ),
                    claim.fence().route_generation(),
                    claim.fence().session_id().clone(),
                    claim.fence().session_incarnation(),
                ),
            )),
            server,
            MonotonicMillis::new(1_001),
        )
        .await;
    assert!(matches!(result, Err(DataPlaneError::Route(_))));
    assert!(
        resolver_calls
            .lock()
            .expect("resolver lock should work")
            .is_empty()
    );
    assert!(
        connector_targets
            .lock()
            .expect("target lock should work")
            .is_empty()
    );
}

#[tokio::test]
async fn resolves_once_and_connects_only_the_inspected_socket_address() {
    let (registry, claim) = setup();
    let resolver_calls = Arc::new(Mutex::new(Vec::new()));
    let connector_targets = Arc::new(Mutex::new(Vec::new()));
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: resolver_calls.clone(),
            gate: None,
        },
        FakeConnector {
            targets: connector_targets.clone(),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let origin_task = tokio::spawn(async move {
        let mut request = vec![0; 1_024];
        let read = origin.read(&mut request).await.expect("origin should read");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /path HTTP/1.1"));
        origin
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .expect("origin response should write");
        read
    });
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("request should write");
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("response should read");
    assert!(serve.await.expect("serve task should join").is_ok());
    let request_bytes = origin_task.await.expect("origin task should join");

    assert_eq!(
        resolver_calls
            .lock()
            .expect("resolver lock should work")
            .as_slice(),
        ["example.com"]
    );
    assert_eq!(
        connector_targets
            .lock()
            .expect("target lock should work")
            .as_slice(),
        [SocketAddr::from(([93, 184, 216, 34], 80))]
    );
    assert!(response.ends_with(b"\r\n\r\nOK"));
    assert_eq!(
        registry
            .usage(&claim)
            .expect("usage should exist")
            .total_egress_bytes,
        u64::try_from(response.len().saturating_add(request_bytes))
            .expect("network usage should fit u64")
    );
}

#[tokio::test]
async fn revoke_cancels_blocked_dns_before_connect() {
    let (registry, claim) = setup();
    let resolver_calls = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Notify::new());
    let connector_targets = Arc::new(Mutex::new(Vec::new()));
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: resolver_calls.clone(),
            gate: Some(gate),
        },
        FakeConnector {
            targets: connector_targets.clone(),
            upstream: Arc::new(Mutex::new(None)),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request should write");
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    while resolver_calls
        .lock()
        .expect("resolver lock should work")
        .is_empty()
    {
        tokio::task::yield_now().await;
    }
    registry.revoke(&claim).expect("revoke should work");
    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("serve should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
    assert!(
        connector_targets
            .lock()
            .expect("target lock should work")
            .is_empty()
    );
}

#[tokio::test]
async fn shard_release_waits_for_a_header_stalled_connection_to_cancel() {
    let (registry, claim) = setup();
    let read_polled = Arc::new(Notify::new());
    let mut configured = data_limits();
    configured.header_timeout = Duration::from_secs(30);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        GatedConnector {
            started: Arc::new(Notify::new()),
            gate: Arc::new(Notify::new()),
        },
        configured,
    )
    .expect("limits should be valid");
    let serving_claim = claim.clone();
    let header_started = read_polled.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                StalledHeaderIo {
                    read_polled: header_started,
                },
                MonotonicMillis::new(1_001),
            )
            .await
    });
    read_polled.notified().await;

    assert_eq!(registry.revoke_shard(claim.fence().shard()), Ok(1));
    assert_eq!(
        registry.release_shard(claim.fence().shard()),
        Err(RouteError::ShardNotDrained)
    );
    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("header read should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
    assert_eq!(registry.release_shard(claim.fence().shard()), Ok(()));
}

#[tokio::test]
async fn revoke_cancels_blocked_connect() {
    let (registry, claim) = setup();
    let started = Arc::new(Notify::new());
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        GatedConnector {
            started: started.clone(),
            gate: Arc::new(Notify::new()),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request should write");
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    started.notified().await;
    registry.revoke(&claim).expect("revoke should work");

    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("connect should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
}

#[tokio::test]
async fn shard_revoke_cancels_a_blocked_initial_upstream_write() {
    let (registry, claim) = setup();
    let write_blocked = Arc::new(Notify::new());
    let mut configured = data_limits();
    configured.write_timeout = Duration::from_secs(30);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        StagedConnector {
            upstream: Arc::new(Mutex::new(Some(StagedWriteIo {
                writes_remaining: 0,
                write_completed: Arc::new(Notify::new()),
                write_blocked: write_blocked.clone(),
            }))),
        },
        configured,
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("request should write");
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    write_blocked.notified().await;

    assert_eq!(registry.revoke_shard(claim.fence().shard()), Ok(1));
    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("initial write should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
    assert_eq!(registry.release_shard(claim.fence().shard()), Ok(()));
}

#[tokio::test]
async fn shard_revoke_cancels_a_blocked_request_body_read() {
    let (registry, claim) = setup();
    let write_completed = Arc::new(Notify::new());
    let mut configured = data_limits();
    configured.read_timeout = Duration::from_secs(30);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        StagedConnector {
            upstream: Arc::new(Mutex::new(Some(StagedWriteIo {
                writes_remaining: 1,
                write_completed: write_completed.clone(),
                write_blocked: Arc::new(Notify::new()),
            }))),
        },
        configured,
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(
            b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
        )
        .await
        .expect("request head should write");
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    write_completed.notified().await;

    assert_eq!(registry.revoke_shard(claim.fence().shard()), Ok(1));
    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("request body read should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
    assert_eq!(registry.release_shard(claim.fence().shard()), Ok(()));
}

#[tokio::test]
async fn shard_revoke_cancels_a_blocked_request_body_write() {
    let (registry, claim) = setup();
    let write_completed = Arc::new(Notify::new());
    let write_blocked = Arc::new(Notify::new());
    let mut configured = data_limits();
    configured.write_timeout = Duration::from_secs(30);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        StagedConnector {
            upstream: Arc::new(Mutex::new(Some(StagedWriteIo {
                writes_remaining: 1,
                write_completed: write_completed.clone(),
                write_blocked: write_blocked.clone(),
            }))),
        },
        configured,
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(
            b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
        )
        .await
        .expect("request head should write");
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    write_completed.notified().await;
    client
        .write_all(b"body")
        .await
        .expect("request body should write");
    write_blocked.notified().await;

    assert_eq!(registry.revoke_shard(claim.fence().shard()), Ok(1));
    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("request body write should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
    assert_eq!(registry.release_shard(claim.fence().shard()), Ok(()));
}

#[tokio::test]
async fn shard_revoke_cancels_a_blocked_relay_write_before_more_bytes_flush() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let blocked = Arc::new(Notify::new());
    let completed_writes = Arc::new(Mutex::new(Vec::new()));
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let writes = completed_writes.clone();
    let client_blocked = blocked.clone();
    let serving_claim = claim.clone();
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(serving_claim),
                BlockingRelayClientIo {
                    request: b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
                        .to_vec(),
                    request_offset: 0,
                    writes_before_blocking: 1,
                    completed_writes: writes,
                    blocked: client_blocked,
                },
                MonotonicMillis::new(1_001),
            )
            .await
    });
    origin
        .write_all(b"must-not-flush-after-revoke")
        .await
        .expect("origin bytes should write");
    blocked.notified().await;

    assert_eq!(registry.revoke_shard(claim.fence().shard()), Ok(1));
    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("blocked relay write should cancel promptly")
        .expect("serve task should join");
    assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
    assert_eq!(
        completed_writes
            .lock()
            .expect("completed-writes lock should work")
            .as_slice(),
        [b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec()]
    );
    assert_eq!(registry.release_shard(claim.fence().shard()), Ok(()));
}

#[tokio::test]
async fn tunnel_duplex_backpressure_keeps_both_directions_progressing() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(64);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits");
    let (mut client, server) = tokio::io::duplex(64);
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request");
    let mut established = [0_u8; 39];
    client
        .read_exact(&mut established)
        .await
        .expect("CONNECT reply");
    let peers = async {
        let client_side = async {
            client
                .write_all(&[b'c'; 512])
                .await
                .expect("client sends before reading");
            client.shutdown().await.expect("client write EOF");
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("client reads origin EOF");
            assert_eq!(response, vec![b'o'; 512]);
        };
        let origin_side = async {
            origin
                .write_all(&[b'o'; 512])
                .await
                .expect("origin sends before reading");
            origin.shutdown().await.expect("origin write EOF");
            let mut request = Vec::new();
            origin
                .read_to_end(&mut request)
                .await
                .expect("origin reads client EOF");
            assert_eq!(request, vec![b'c'; 512]);
        };
        tokio::join!(client_side, origin_side);
    };
    tokio::time::timeout(Duration::from_millis(250), peers)
        .await
        .expect("both bounded buffers must make progress");
    assert!(serve.await.expect("serve joins").is_ok());
}

#[tokio::test]
async fn tunnel_client_write_eof_preserves_the_origin_response() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits");
    let (mut client, server) = tokio::io::duplex(4_096);
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request");
    let mut established = [0_u8; 39];
    client
        .read_exact(&mut established)
        .await
        .expect("CONNECT reply");
    client.write_all(b"request").await.expect("request payload");
    client.shutdown().await.expect("client write EOF");
    let mut received = Vec::new();
    origin
        .read_to_end(&mut received)
        .await
        .expect("origin sees client EOF");
    assert_eq!(received, b"request");
    origin
        .write_all(b"response after request EOF")
        .await
        .expect("origin response remains writable");
    origin.shutdown().await.expect("origin EOF");
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.expect("response");
    assert_eq!(response, b"response after request EOF");
    assert!(serve.await.expect("serve joins").is_ok());
}

#[tokio::test]
async fn tunnel_half_close_is_bounded_by_the_write_timeout() {
    let (registry, claim) = setup();
    let shutdown_started = Arc::new(Notify::new());
    let mut configured = data_limits();
    configured.write_timeout = Duration::from_millis(20);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        HangingShutdownConnector {
            upstream: Arc::new(Mutex::new(Some(HangingShutdownIo {
                shutdown_started: shutdown_started.clone(),
            }))),
        },
        configured,
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(2_048);
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request should write");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    let mut established = vec![0_u8; 39];
    client
        .read_exact(&mut established)
        .await
        .expect("CONNECT response should arrive");
    client.shutdown().await.expect("client should half-close");
    shutdown_started.notified().await;

    let result = tokio::time::timeout(Duration::from_secs(1), serve)
        .await
        .expect("half-close timeout should be bounded")
        .expect("serve task should join");
    assert!(matches!(
        result,
        Err(DataPlaneError::Timeout("upstream shutdown"))
    ));
}

#[tokio::test]
async fn forward_http_does_not_tunnel_a_time_split_second_request() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let first_request_received = Arc::new(Notify::new());
    let origin_started = first_request_received.clone();
    let origin_task = tokio::spawn(async move {
        let mut request = vec![0_u8; 1_024];
        let read = origin.read(&mut request).await.expect("origin should read");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /first HTTP/1.1"));
        origin_started.notify_one();
        origin
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            .await
            .expect("origin response should write");
        let mut extra = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_millis(250), origin.read_to_end(&mut extra)).await;
        extra
    });
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(b"GET http://example.com/first HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("first request should write");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    first_request_received.notified().await;
    let mut response = vec![0_u8; 64];
    client
        .read_exact(&mut response)
        .await
        .expect("first response should arrive");
    let _ = client
        .write_all(b"GET http://metadata.invalid/latest HTTP/1.1\r\nHost: metadata.invalid\r\n\r\n")
        .await;

    let unexpected_upstream_bytes = origin_task.await.expect("origin task should join");
    assert!(
        unexpected_upstream_bytes.is_empty(),
        "a second request bypassed route authorization: {}",
        String::from_utf8_lossy(&unexpected_upstream_bytes)
    );
    assert!(serve.await.expect("serve task should join").is_ok());
}

#[tokio::test]
async fn websocket_rejection_does_not_enable_a_raw_tunnel() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let origin_task = tokio::spawn(async move {
        let mut request = vec![0_u8; 1_024];
        let read = origin.read(&mut request).await.expect("origin should read");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /socket HTTP/1.1"));
        origin
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\nConnection: close\r\n\r\nNO",
            )
            .await
            .expect("rejection response should write");
        let mut extra = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_millis(250), origin.read_to_end(&mut extra)).await;
        extra
    });
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(
            b"GET ws://example.com/socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .expect("upgrade request should write");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    let mut response = vec![0_u8; 66];
    client
        .read_exact(&mut response)
        .await
        .expect("rejection response should arrive");
    let _ = client.write_all(b"must-not-tunnel").await;

    let unexpected_upstream_bytes = origin_task.await.expect("origin task should join");
    assert!(
        unexpected_upstream_bytes.is_empty(),
        "a rejected upgrade opened a tunnel: {}",
        String::from_utf8_lossy(&unexpected_upstream_bytes)
    );
    assert!(serve.await.expect("serve task should join").is_ok());
}

#[tokio::test]
async fn websocket_response_header_uses_one_absolute_timeout() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let mut configured = data_limits();
    configured.header_timeout = Duration::from_millis(15);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        configured,
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(
            b"GET ws://example.com/socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .expect("upgrade request should write");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    let mut request = vec![0_u8; 1_024];
    let read = origin.read(&mut request).await.expect("origin should read");
    assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /socket HTTP/1.1"));
    let dripper = tokio::spawn(async move {
        for byte in b"HTTP/1.1 101 Switching Protocols\r\n" {
            if origin.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let result = tokio::time::timeout(Duration::from_millis(250), serve)
        .await
        .expect("absolute upstream header timeout should fire")
        .expect("serve task should join");
    assert!(matches!(
        result,
        Err(DataPlaneError::Timeout("upstream response header"))
    ));
    dripper.abort();
}

#[tokio::test]
async fn revoke_or_expiry_immediately_closes_live_connect_tunnel() {
    for expire in [false, true] {
        let (registry, claim) = setup();
        let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
        let service = DataPlane::new(
            registry.clone(),
            FakeResolver {
                calls: Arc::new(Mutex::new(Vec::new())),
                gate: None,
            },
            FakeConnector {
                targets: Arc::new(Mutex::new(Vec::new())),
                upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
            },
            data_limits(),
        )
        .expect("limits should be valid");
        let (mut client, server) = tokio::io::duplex(4_096);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .expect("request should write");
        let serving_claim = claim.clone();
        let serve = tokio::spawn(async move {
            service
                .serve_verified_connection(
                    VerifiedRouteSource::new(serving_claim),
                    server,
                    MonotonicMillis::new(1_001),
                )
                .await
        });
        let mut established = vec![0; 39];
        client
            .read_exact(&mut established)
            .await
            .expect("CONNECT response should arrive");
        assert_eq!(&established, b"HTTP/1.1 200 Connection Established\r\n\r\n");

        if expire {
            assert_eq!(registry.expire_routes(MonotonicMillis::new(20_000)), 1);
        } else {
            registry.revoke(&claim).expect("revoke should work");
        }
        let result = tokio::time::timeout(Duration::from_secs(1), serve)
            .await
            .expect("live tunnel should close promptly")
            .expect("serve task should join");
        assert!(matches!(result, Err(DataPlaneError::RouteRevoked)));
        let mut byte = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), origin.read(&mut byte))
                .await
                .expect("origin should observe close")
                .expect("origin read should work"),
            0
        );
    }
}

#[tokio::test]
async fn forward_http_requires_the_exact_declared_content_length() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(
            b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nab",
        )
        .await
        .expect("partial request should write");
    client.shutdown().await.expect("client write should close");

    let result = service
        .serve_verified_connection(
            VerifiedRouteSource::new(claim),
            server,
            MonotonicMillis::new(1_001),
        )
        .await;
    assert!(matches!(result, Err(DataPlaneError::UnexpectedEof)));
    let mut discarded = Vec::new();
    origin
        .read_to_end(&mut discarded)
        .await
        .expect("origin should observe proxy close");
}

#[tokio::test]
async fn websocket_upgrade_uses_the_same_bidirectional_bounded_tunnel() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let origin_task = tokio::spawn(async move {
        let mut request = vec![0; 1_024];
        let read = origin.read(&mut request).await.expect("origin should read");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("GET /socket HTTP/1.1"));
        assert!(request.contains("Connection: Upgrade"));
        origin
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nS",
            )
            .await
            .expect("upgrade response should write");
        let mut client_frame = [0_u8; 1];
        origin
            .read_exact(&mut client_frame)
            .await
            .expect("client frame should tunnel");
        assert_eq!(client_frame, *b"C");
    });
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(
            b"GET ws://example.com/socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .expect("upgrade request should write");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    let mut response = vec![0_u8; 78];
    client
        .read_exact(&mut response)
        .await
        .expect("upgrade response and first frame should arrive");
    assert!(response.ends_with(b"\r\n\r\nS"));
    client
        .write_all(b"C")
        .await
        .expect("client frame should write");
    client
        .shutdown()
        .await
        .expect("client tunnel direction completes");
    origin_task.await.expect("origin task should join");
    assert!(serve.await.expect("serve task should join").is_ok());
}

#[tokio::test]
async fn request_body_quota_is_checked_before_bytes_are_forwarded() {
    let expected_head = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 4\r\n\r\n";
    let head_bytes = u64::try_from(expected_head.len()).expect("request head should fit u64");
    let mut quota = limits();
    quota.max_egress_bytes_per_window = head_bytes;
    quota.max_total_egress_bytes = head_bytes;
    let (registry, claim) = setup_with_limits(quota);
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let origin_task = tokio::spawn(async move {
        let mut received = Vec::new();
        origin
            .read_to_end(&mut received)
            .await
            .expect("origin should observe proxy close");
        received
    });
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(
            b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody",
        )
        .await
        .expect("request should write");

    let result = service
        .serve_verified_connection(
            VerifiedRouteSource::new(claim.clone()),
            server,
            MonotonicMillis::new(1_001),
        )
        .await;

    assert!(matches!(result, Err(DataPlaneError::Route(_))));
    assert_eq!(
        origin_task.await.expect("origin task should join"),
        expected_head
    );
    assert_eq!(
        registry
            .usage(&claim)
            .expect("usage should exist")
            .total_egress_bytes,
        head_bytes
    );
}

#[tokio::test]
async fn response_quota_is_checked_before_bytes_are_forwarded() {
    let mut quota = limits();
    quota.max_response_bytes = Some(32);
    let (registry, claim) = setup_with_limits(quota);
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let service = DataPlane::new(
        registry.clone(),
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        data_limits(),
    )
    .expect("limits should be valid");
    let origin_task = tokio::spawn(async move {
        let mut request = vec![0; 1_024];
        let read = origin.read(&mut request).await.expect("origin should read");
        origin
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n0123456789012345678901234567890123456789012345678901234567890123")
            .await
            .expect("oversized response should write");
        read
    });
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("request should write");
    let result = service
        .serve_verified_connection(
            VerifiedRouteSource::new(claim.clone()),
            server,
            MonotonicMillis::new(1_001),
        )
        .await;
    assert!(matches!(result, Err(DataPlaneError::Route(_))));
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("client should observe close");
    assert!(response.is_empty());
    let request_bytes = origin_task.await.expect("origin task should join");
    assert_eq!(
        registry
            .usage(&claim)
            .expect("usage should exist")
            .total_egress_bytes,
        u64::try_from(request_bytes).expect("request usage should fit u64")
    );
}

#[tokio::test]
async fn incomplete_header_is_bounded_by_the_header_timeout() {
    let (registry, claim) = setup();
    let mut configured = data_limits();
    configured.header_timeout = Duration::from_millis(20);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(None)),
        },
        configured,
    )
    .expect("limits should be valid");
    let (_client, server) = tokio::io::duplex(128);

    assert!(matches!(
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await,
        Err(DataPlaneError::Timeout("header"))
    ));
}

#[tokio::test]
async fn tunnel_idle_timeout_resets_on_traffic_in_either_direction() {
    let (registry, claim) = setup();
    let (proxy_upstream, mut origin) = tokio::io::duplex(4_096);
    let mut configured = data_limits();
    configured.idle_timeout = Duration::from_millis(40);
    let service = DataPlane::new(
        registry,
        FakeResolver {
            calls: Arc::new(Mutex::new(Vec::new())),
            gate: None,
        },
        FakeConnector {
            targets: Arc::new(Mutex::new(Vec::new())),
            upstream: Arc::new(Mutex::new(Some(proxy_upstream))),
        },
        configured,
    )
    .expect("limits should be valid");
    let origin_task = tokio::spawn(async move {
        for byte in *b"ABCD" {
            tokio::time::sleep(Duration::from_millis(20)).await;
            origin
                .write_all(&[byte])
                .await
                .expect("stream byte should write");
        }
    });
    let (mut client, server) = tokio::io::duplex(4_096);
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .expect("request should write");
    let serve = tokio::spawn(async move {
        service
            .serve_verified_connection(
                VerifiedRouteSource::new(claim),
                server,
                MonotonicMillis::new(1_001),
            )
            .await
    });
    let mut established = vec![0; 39];
    client
        .read_exact(&mut established)
        .await
        .expect("CONNECT response should arrive");
    let mut streamed = [0_u8; 4];
    client
        .read_exact(&mut streamed)
        .await
        .expect("one-way traffic should keep the tunnel alive");
    assert_eq!(&streamed, b"ABCD");
    client
        .shutdown()
        .await
        .expect("client tunnel direction completes");
    origin_task.await.expect("origin task should join");
    assert!(serve.await.expect("serve task should join").is_ok());
}
