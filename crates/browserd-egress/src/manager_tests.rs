#![allow(clippy::expect_used, clippy::panic)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::socket::{Shutdown, shutdown};
use nix::unistd::dup;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Notify;

use crate::{
    AcceptedIngressHandler, AcceptedRouteIngress, ActiveAttachmentReceipt, AttachmentError,
    AttachmentManager, AttachmentManagerError, AttachmentState, AttachmentStatus, BindingDigest,
    DaemonEpoch, DataPlane, EgressPolicy, IngressHandlerError, MonotonicMillis, QuotaLimits,
    RouteBinding, TcpConnector, TokioResolver,
};

#[derive(Debug, Default)]
struct DropHandler {
    accepted: AtomicUsize,
    notify: Notify,
}

#[async_trait]
impl AcceptedIngressHandler for DropHandler {
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
        self.accepted.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
        drop(ingress);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct HoldingHandler {
    started: Notify,
    release: Notify,
}

#[async_trait]
impl AcceptedIngressHandler for HoldingHandler {
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
        self.started.notify_one();
        self.release.notified().await;
        drop(ingress);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct FailingHandler {
    attempts: AtomicUsize,
    attempted: Notify,
}

#[async_trait]
impl AcceptedIngressHandler for FailingHandler {
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.attempted.notify_one();
        drop(ingress);
        Err(io::Error::other("injected handler failure").into())
    }
}

#[derive(Debug, Default)]
struct PanickingHandler;

#[async_trait]
impl AcceptedIngressHandler for PanickingHandler {
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
        drop(ingress);
        panic!("injected handler panic")
    }
}

fn daemon_epoch() -> DaemonEpoch {
    DaemonEpoch::new(17).expect("non-zero daemon epoch")
}

fn fence(seed: u64) -> EgressFence {
    let worker_epoch = WorkerEpoch::new(seed).expect("non-zero worker epoch");
    let launch_generation = LaunchGeneration::new(seed).expect("non-zero launch generation");
    let route_generation = RouteGeneration::new(seed).expect("non-zero route generation");
    let session_incarnation = SessionIncarnation::new(seed).expect("non-zero session incarnation");
    EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new(format!("manager-worker-{seed}")).expect("valid worker identifier"),
                worker_epoch,
            ),
            ShardId::new(),
            launch_generation,
        ),
        route_generation,
        SessionId::new(),
        session_incarnation,
    )
}

fn digest(seed: u8) -> BindingDigest {
    BindingDigest::new([seed; 32])
}

fn limits() -> QuotaLimits {
    QuotaLimits {
        max_concurrent_connections: 4,
        max_connection_starts_per_window: 8,
        max_dns_queries_per_window: 8,
        max_egress_bytes_per_window: 16_384,
        max_total_egress_bytes: 32_768,
        max_response_bytes: Some(8_192),
        accounting_window: Duration::from_secs(60),
        idle_connection_timeout: Duration::from_secs(10),
    }
}

fn binding(
    manager: &AttachmentManager,
    route_fence: &EgressFence,
    lease: Duration,
) -> RouteBinding {
    let now = manager.now();
    let lease_millis = u64::try_from(lease.as_millis()).expect("test lease fits u64");
    RouteBinding::new(
        TenantId::new(),
        route_fence.session_id().clone(),
        route_fence.shard().shard_id().clone(),
        route_fence.shard().owner().worker_epoch().get(),
        EgressPolicy::public_web_default(),
        limits(),
        MonotonicMillis::new(now.value() + lease_millis),
    )
}

fn listener() -> (SocketAddr, OwnedFd) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test listener");
    let address = listener.local_addr().expect("read listener address");
    (address, listener.into())
}

fn duplicate(descriptor: &OwnedFd) -> OwnedFd {
    let duplicate = dup(descriptor.as_fd()).expect("duplicate listener");
    fcntl(&duplicate, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .expect("set close-on-exec on duplicate");
    duplicate
}

async fn install(
    manager: &AttachmentManager,
    route_fence: EgressFence,
    digest: BindingDigest,
    descriptor: OwnedFd,
    lease: Duration,
) -> ActiveAttachmentReceipt {
    let prepared = manager
        .prepare(route_fence.clone(), digest)
        .expect("prepare attachment");
    manager
        .install(&prepared, binding(manager, &route_fence, lease), descriptor)
        .await
        .expect("install attachment")
}

async fn wait_for_state(
    manager: &AttachmentManager,
    route_fence: &EgressFence,
    expected: AttachmentState,
) -> AttachmentStatus {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = manager
                .status(daemon_epoch(), route_fence)
                .expect("query attachment status");
            if status.state() == expected {
                return status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("attachment reaches expected state")
}

#[tokio::test]
async fn install_derives_proxy_address_and_expiry_from_owned_capability_and_binding() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(1);
    let (address, descriptor) = listener();
    let route_binding = binding(&manager, &route_fence, Duration::from_secs(10));
    let expected_expiry = route_binding.expires_at();
    let prepared = manager
        .prepare(route_fence.clone(), digest(1))
        .expect("prepare attachment");

    let active = manager
        .install(&prepared, route_binding, descriptor)
        .await
        .expect("install attachment");

    assert_eq!(active.proxy_address(), address);
    assert_eq!(active.expires_at().daemon_millis(), expected_expiry.value());
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read active status"),
        AttachmentStatus::Active(active.clone())
    );
    assert_eq!(
        manager.revoke(&active).await.expect("revoke").fence(),
        &route_fence
    );
}

#[tokio::test]
async fn invalid_install_metadata_closes_and_releases_the_reserved_attachment() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(11);
    let prepared = manager
        .prepare(route_fence.clone(), digest(11))
        .expect("prepare attachment");
    let (address, descriptor) = listener();
    let invalid_binding = RouteBinding::new(
        TenantId::new(),
        route_fence.session_id().clone(),
        route_fence.shard().shard_id().clone(),
        route_fence.shard().owner().worker_epoch().get(),
        EgressPolicy::public_web_default(),
        limits(),
        MonotonicMillis::new(0),
    );

    assert!(matches!(
        manager
            .install(&prepared, invalid_binding, descriptor)
            .await,
        Err(AttachmentManagerError::Attachment(
            AttachmentError::InvalidExpiry
        ))
    ));
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read terminal status")
            .state(),
        AttachmentState::Released
    );
    StdTcpListener::bind(address).expect("invalid install descriptor is closed");
}

#[tokio::test]
async fn concurrent_dup_descriptor_install_is_exact_but_distinct_listener_conflicts_and_closes() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(2);
    let prepared = manager
        .prepare(route_fence.clone(), digest(2))
        .expect("prepare attachment");
    let route_binding = binding(&manager, &route_fence, Duration::from_secs(10));
    let (installed_address, descriptor) = listener();
    let duplicate_descriptor = duplicate(&descriptor);
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let first = {
        let manager = manager.clone();
        let prepared = prepared.clone();
        let binding = route_binding.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            manager.install(&prepared, binding, descriptor).await
        })
    };
    let second = {
        let manager = manager.clone();
        let prepared = prepared.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            manager
                .install(&prepared, route_binding, duplicate_descriptor)
                .await
        })
    };
    barrier.wait().await;
    let first = first
        .await
        .expect("first task joins")
        .expect("first installs");
    let second = second
        .await
        .expect("second task joins")
        .expect("exact retry installs");
    assert_eq!(first, second);

    let (conflict_address, conflict_descriptor) = listener();
    assert!(matches!(
        manager
            .install(
                &prepared,
                binding(&manager, &route_fence, Duration::from_secs(10)),
                conflict_descriptor
            )
            .await,
        Err(AttachmentManagerError::DescriptorConflict)
    ));
    StdTcpListener::bind(conflict_address).expect("conflicting descriptor is closed on failure");
    manager.revoke(&first).await.expect("revoke attachment");
    StdTcpListener::bind(installed_address)
        .expect("exact retry drops its duplicate descriptor before revoke completes");
}

#[tokio::test]
async fn cancellation_is_terminal_before_a_late_descriptor_install() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(3);
    let prepared = manager
        .prepare(route_fence.clone(), digest(3))
        .expect("prepare attachment");
    let released = manager.cancel(&prepared).await.expect("cancel preparation");
    let (address, descriptor) = listener();

    assert!(matches!(
        manager
            .install(
                &prepared,
                binding(&manager, &route_fence, Duration::from_secs(10)),
                descriptor,
            )
            .await,
        Err(AttachmentManagerError::InstallCancelled)
    ));
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read released status"),
        AttachmentStatus::Released(released)
    );
    StdTcpListener::bind(address).expect("late descriptor is closed");
}

#[tokio::test]
async fn revoke_closes_listener_and_waits_for_accepted_handler_guard_to_drain() {
    let handler = Arc::new(HoldingHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler.clone());
    let route_fence = fence(4);
    let (address, descriptor) = listener();
    let active = install(
        &manager,
        route_fence.clone(),
        digest(4),
        descriptor,
        Duration::from_secs(10),
    )
    .await;
    let mut client = TcpStream::connect(address)
        .await
        .expect("connect to ingress");
    client.write_all(b"x").await.expect("write a byte");
    handler.started.notified().await;

    let revoke = {
        let manager = manager.clone();
        let active = active.clone();
        tokio::spawn(async move { manager.revoke(&active).await })
    };
    tokio::task::yield_now().await;
    assert!(
        !revoke.is_finished(),
        "revoke must wait for the accepted guard"
    );
    handler.release.notify_waiters();
    let released = revoke
        .await
        .expect("revoke task joins")
        .expect("revoke succeeds");
    assert_eq!(released.fence(), &route_fence);
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read released status"),
        AttachmentStatus::Released(released)
    );
    drop(client);
    StdTcpListener::bind(address).expect("listener is closed after drain");
}

#[tokio::test]
async fn authoritative_binding_expiry_revokes_and_releases_the_listener() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(5);
    let (address, descriptor) = listener();
    let _active = install(
        &manager,
        route_fence.clone(),
        digest(5),
        descriptor,
        Duration::from_millis(250),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(275)).await;
    let status = wait_for_state(&manager, &route_fence, AttachmentState::Released).await;
    assert!(matches!(status, AttachmentStatus::Released(_)));
    StdTcpListener::bind(address).expect("expired listener is closed");
}

#[tokio::test]
async fn renewal_extends_the_route_and_listener_beyond_the_original_expiry() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(2), handler);
    let route_fence = fence(13);
    let (address, descriptor) = listener();
    let active = install(
        &manager,
        route_fence.clone(),
        digest(13),
        descriptor,
        Duration::from_millis(200),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(75)).await;
    let renewed_expiry = MonotonicMillis::new(manager.now().value() + 350);
    manager
        .renew(&active, renewed_expiry)
        .expect("active listener lease should renew");

    tokio::time::sleep(Duration::from_millis(175)).await;
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read renewed status")
            .state(),
        AttachmentState::Active
    );
    let client = TcpStream::connect(address)
        .await
        .expect("renewed listener should accept beyond its original expiry");
    drop(client);

    let status = wait_for_state(&manager, &route_fence, AttachmentState::Released).await;
    assert!(matches!(status, AttachmentStatus::Released(_)));
    StdTcpListener::bind(address).expect("renewed listener closes at the extended expiry");
}

#[tokio::test]
async fn renewal_is_idempotent_and_cannot_shorten_the_committed_deadline() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(14);
    let (_address, descriptor) = listener();
    let active = install(
        &manager,
        route_fence.clone(),
        digest(14),
        descriptor,
        Duration::from_secs(10),
    )
    .await;
    let renewed_expiry = MonotonicMillis::new(manager.now().value() + 15_000);

    assert!(manager.renew(&active, renewed_expiry).is_ok());
    assert!(manager.renew(&active, renewed_expiry).is_ok());
    assert!(matches!(
        manager.renew(
            &active,
            MonotonicMillis::new(renewed_expiry.value() - 1_000)
        ),
        Err(AttachmentManagerError::Route(
            crate::RouteError::InvalidLeaseExpiry
        ))
    ));
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read active status")
            .state(),
        AttachmentState::Active
    );
    manager.revoke(&active).await.expect("revoke attachment");
}

#[tokio::test]
async fn concurrent_renew_and_revoke_never_resurrect_the_listener() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let route_fence = fence(15);
    let (address, descriptor) = listener();
    let active = install(
        &manager,
        route_fence.clone(),
        digest(15),
        descriptor,
        Duration::from_secs(10),
    )
    .await;
    let renewed_expiry = MonotonicMillis::new(manager.now().value() + 15_000);
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let renew = {
        let manager = manager.clone();
        let active = active.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            manager.renew(&active, renewed_expiry)
        })
    };
    let revoke = {
        let manager = manager.clone();
        let active = active.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            manager.revoke(&active).await
        })
    };
    barrier.wait().await;

    let _renew_result = renew.await.expect("renew task should join");
    let released = revoke
        .await
        .expect("revoke task should join")
        .expect("revoke should remain authoritative");
    assert_eq!(released.fence(), &route_fence);
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read terminal status")
            .state(),
        AttachmentState::Released
    );
    StdTcpListener::bind(address).expect("revoked listener must remain closed after renewal race");
}

#[tokio::test]
async fn normal_per_connection_handler_errors_do_not_revoke_the_listener() {
    let handler = Arc::new(FailingHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler.clone());
    let route_fence = fence(6);
    let (address, descriptor) = listener();
    let active = install(
        &manager,
        route_fence.clone(),
        digest(6),
        descriptor,
        Duration::from_secs(10),
    )
    .await;
    let first_client = TcpStream::connect(address)
        .await
        .expect("connect to ingress");
    handler.attempted.notified().await;
    assert_eq!(
        manager
            .status(daemon_epoch(), &route_fence)
            .expect("read status")
            .state(),
        AttachmentState::Active
    );
    let second_client = TcpStream::connect(address)
        .await
        .expect("listener still accepts after a per-connection error");
    tokio::time::timeout(Duration::from_secs(2), async {
        while handler.attempts.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second handler attempt is observed");
    drop((first_client, second_client));
    manager.revoke(&active).await.expect("revoke attachment");
}

#[tokio::test]
async fn handler_task_panic_makes_the_attachment_fail_closed_and_terminal() {
    let manager = AttachmentManager::new(
        daemon_epoch(),
        Duration::from_secs(30),
        Arc::new(PanickingHandler),
    );
    let route_fence = fence(12);
    let (address, descriptor) = listener();
    let _active = install(
        &manager,
        route_fence.clone(),
        digest(12),
        descriptor,
        Duration::from_secs(10),
    )
    .await;
    let _client = TcpStream::connect(address)
        .await
        .expect("connect to ingress");

    let status = wait_for_state(&manager, &route_fence, AttachmentState::Released).await;
    assert!(matches!(status, AttachmentStatus::Released(_)));
    StdTcpListener::bind(address).expect("panicked actor closes listener");
}

#[tokio::test]
async fn unexpected_accept_loop_failure_is_fail_closed_and_terminal() {
    let manager = AttachmentManager::new(
        daemon_epoch(),
        Duration::from_secs(30),
        Arc::new(DropHandler::default()),
    );
    let route_fence = fence(10);
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test listener");
    let address = listener.local_addr().expect("read listener address");
    let descriptor = duplicate(&OwnedFd::from(
        listener.try_clone().expect("clone listener"),
    ));
    let _active = install(
        &manager,
        route_fence.clone(),
        digest(10),
        descriptor,
        Duration::from_secs(10),
    )
    .await;

    shutdown(listener.as_raw_fd(), Shutdown::Both).expect("break the shared listening socket");
    let status = wait_for_state(&manager, &route_fence, AttachmentState::Released).await;
    assert!(matches!(status, AttachmentStatus::Released(_)));
    drop(listener);
    StdTcpListener::bind(address).expect("failed accept actor closes its listener");
}

#[test]
fn production_data_plane_is_directly_usable_as_the_ingress_handler() {
    fn assert_handler<T: AcceptedIngressHandler>() {}

    assert_handler::<DataPlane<TokioResolver, TcpConnector>>();
}

#[tokio::test]
async fn shutdown_revokes_and_joins_every_active_listener_actor() {
    let handler = Arc::new(DropHandler::default());
    let manager = AttachmentManager::new(daemon_epoch(), Duration::from_secs(30), handler);
    let first_fence = fence(7);
    let second_fence = fence(8);
    let (first_address, first_descriptor) = listener();
    let (second_address, second_descriptor) = listener();
    let _first = install(
        &manager,
        first_fence.clone(),
        digest(7),
        first_descriptor,
        Duration::from_secs(10),
    )
    .await;
    let _second = install(
        &manager,
        second_fence.clone(),
        digest(8),
        second_descriptor,
        Duration::from_secs(10),
    )
    .await;

    manager.shutdown().await.expect("shutdown succeeds");
    assert_eq!(
        manager
            .status(daemon_epoch(), &first_fence)
            .expect("first status")
            .state(),
        AttachmentState::Released
    );
    assert_eq!(
        manager
            .status(daemon_epoch(), &second_fence)
            .expect("second status")
            .state(),
        AttachmentState::Released
    );
    StdTcpListener::bind(first_address).expect("first listener joined");
    StdTcpListener::bind(second_address).expect("second listener joined");
    assert!(matches!(
        manager.prepare(fence(9), digest(9)),
        Err(AttachmentManagerError::ShuttingDown)
    ));
}
