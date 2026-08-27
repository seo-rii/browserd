#![allow(clippy::expect_used)]

use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, LeaseId, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_egress::{
    AcceptedIngressHandler, AcceptedRouteIngress, AttachmentState, BindingDigest, DaemonEpoch,
    IngressHandlerError, QuotaLimits,
};
use browserd_egress_control::{
    ClientInstallError, EpochProbeRequest, InstallRequest, ServerCommitError, receive_listener,
    send_epoch_probe, send_listener,
};
use nix::sys::stat::fstat;
use nix::unistd::Uid;
use tokio::net::{TcpStream, UnixStream};

use super::{DaemonControlError, DaemonLimits, EgressDaemon, PreparedRouteRequest};

static LISTENER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug)]
struct DropHandler;

#[async_trait]
impl AcceptedIngressHandler for DropHandler {
    async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
        drop(ingress);
        Ok(())
    }
}

fn epoch() -> DaemonEpoch {
    DaemonEpoch::new(41).expect("daemon epoch is nonzero")
}

fn fence(seed: u64) -> EgressFence {
    EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new(format!("daemon-worker-{seed}")).expect("worker ID is valid"),
                WorkerEpoch::new(seed).expect("worker epoch is nonzero"),
            ),
            ShardId::new(),
            LaunchGeneration::new(seed).expect("launch generation is nonzero"),
        ),
        RouteGeneration::new(seed).expect("route generation is nonzero"),
        SessionId::new(),
        SessionIncarnation::new(seed).expect("session incarnation is nonzero"),
    )
}

fn quotas() -> QuotaLimits {
    QuotaLimits {
        max_concurrent_connections: 8,
        max_connection_starts_per_window: 32,
        max_dns_queries_per_window: 32,
        max_egress_bytes_per_window: 1024 * 1024,
        max_total_egress_bytes: 8 * 1024 * 1024,
        max_response_bytes: Some(1024 * 1024),
        accounting_window: Duration::from_secs(60),
        idle_connection_timeout: Duration::from_secs(15),
    }
}

fn daemon(max_plans: usize) -> EgressDaemon {
    let limits = DaemonLimits::new(Duration::from_secs(30), max_plans, quotas())
        .expect("daemon limits are valid");
    EgressDaemon::with_handler(epoch(), limits, Arc::new(DropHandler))
        .expect("daemon must initialize")
}

fn prepare(
    daemon: &EgressDaemon,
    route_fence: EgressFence,
    digest: [u8; 32],
) -> super::PreparedRouteResponse {
    daemon
        .prepare(
            PreparedRouteRequest::new(
                epoch().get(),
                TenantId::new(),
                route_fence,
                digest,
                "public-web",
                Duration::from_secs(10),
            )
            .expect("prepare request is valid"),
        )
        .expect("route must prepare")
}

fn listener() -> (std::net::SocketAddr, OwnedFd) {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener must bind");
    let address = listener.local_addr().expect("listener address must exist");
    (address, OwnedFd::from(listener))
}

fn install_request(prepared: &super::PreparedRouteResponse) -> InstallRequest {
    InstallRequest::new(
        LeaseId::new(),
        prepared.daemon_epoch(),
        prepared.egress_fence().clone(),
        *prepared.binding_digest(),
        prepared.prepare_revision(),
    )
    .expect("install request is valid")
}

#[tokio::test]
async fn unix_control_probe_returns_the_nonce_bound_current_daemon_epoch() {
    let daemon = Arc::new(daemon(8));
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must open");
    let server = tokio::spawn({
        let daemon = Arc::clone(&daemon);
        async move {
            daemon
                .handle_control_stream(server_stream, Uid::current().as_raw())
                .await
        }
    });
    let request = EpochProbeRequest::new(LeaseId::new());
    let response = send_epoch_probe(client_stream, request.clone())
        .await
        .expect("authenticated epoch proof should succeed");

    assert_eq!(response.protocol_version(), request.protocol_version());
    assert_eq!(response.nonce(), request.nonce());
    assert_eq!(response.current_daemon_epoch(), epoch().get());
    assert_eq!(
        server
            .await
            .expect("server task must join")
            .expect("control request should succeed"),
        None
    );
}

#[tokio::test]
async fn prepare_install_status_and_revoke_are_one_full_fence_transaction() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let daemon = Arc::new(daemon(8));
    let route_fence = fence(1);
    let prepared = prepare(&daemon, route_fence.clone(), [7; 32]);
    let (expected_address, listener) = listener();
    let listener_inode = fstat(&listener)
        .expect("listener identity must be readable")
        .st_ino;
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must open");
    let server = tokio::spawn({
        let daemon = Arc::clone(&daemon);
        async move {
            daemon
                .handle_control_stream(server_stream, Uid::current().as_raw())
                .await
        }
    });

    let active = send_listener(client_stream, install_request(&prepared), listener)
        .await
        .expect("client must receive active receipt");
    assert_eq!(active.proxy_address(), expected_address);
    assert_eq!(
        server
            .await
            .expect("server task must join")
            .expect("install succeeds"),
        Some(active.clone())
    );

    let status = daemon
        .status(epoch().get(), &route_fence)
        .expect("status must resolve");
    assert_eq!(status.state(), AttachmentState::Active);
    assert_eq!(status.active(), Some(&active));
    let client = TcpStream::connect(expected_address)
        .await
        .expect("active listener must accept inside its namespace");

    let released = daemon
        .revoke(epoch().get(), &route_fence)
        .await
        .expect("revoke must drain and release");
    assert_eq!(released.state(), AttachmentState::Released);
    drop(client);
    let listener_descriptor = format!("socket:[{listener_inode}]");
    let open_listener_copies = std::fs::read_dir("/proc/self/fd")
        .expect("process descriptor directory must be readable")
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|target| target.to_string_lossy() == listener_descriptor)
        .count();
    assert_eq!(
        open_listener_copies, 0,
        "released attachment must close every listener capability copy"
    );
}

#[tokio::test]
async fn semantic_metadata_mismatch_is_rejected_before_fd_offer() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let daemon = Arc::new(daemon(8));
    let route_fence = fence(2);
    let prepared = prepare(&daemon, route_fence.clone(), [8; 32]);
    let (_address, listener) = listener();
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must open");
    let mut request = install_request(&prepared);
    request = InstallRequest::new(
        request.transfer_id().clone(),
        request.daemon_epoch(),
        request.egress_fence().clone(),
        [9; 32],
        request.prepare_revision(),
    )
    .expect("mismatching request remains syntactically valid");
    let server = tokio::spawn({
        let daemon = Arc::clone(&daemon);
        async move {
            daemon
                .install_stream(server_stream, Uid::current().as_raw())
                .await
        }
    });

    let client_error = send_listener(client_stream, request, listener)
        .await
        .expect_err("client must fail before observing commit");
    assert!(matches!(client_error, ClientInstallError::BeforeCommit(_)));
    assert!(matches!(
        server.await.expect("server task must join"),
        Err(DaemonControlError::InstallMetadataMismatch)
    ));
    assert_eq!(
        daemon
            .status(epoch().get(), &route_fence)
            .expect("prepared status remains")
            .state(),
        AttachmentState::Prepared
    );
}

#[tokio::test]
async fn failed_commit_announcement_revokes_the_domain_install() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let daemon = daemon(8);
    let route_fence = fence(3);
    let prepared = prepare(&daemon, route_fence.clone(), [10; 32]);
    let (address, listener) = listener();
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must open");
    let client = tokio::spawn(send_listener(
        client_stream,
        install_request(&prepared),
        listener,
    ));
    let pending = receive_listener(server_stream, Uid::current().as_raw())
        .await
        .expect("listener handoff must reach domain commit boundary");
    client.abort();
    let _ = client.await;

    let error = daemon
        .install_pending(pending)
        .await
        .expect_err("commit announcement must fail");
    assert!(matches!(
        error,
        DaemonControlError::Commit(ServerCommitError::BeforeAnnouncement(_))
    ));
    assert_eq!(
        daemon
            .status(epoch().get(), &route_fence)
            .expect("terminal status must reconcile")
            .state(),
        AttachmentState::Released
    );
    assert!(TcpStream::connect(address).await.is_err());
}

#[test]
fn daemon_epoch_plan_binding_and_capacity_fail_closed() {
    let daemon = daemon(1);
    let first_fence = fence(4);
    let first = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        first_fence.clone(),
        [11; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("request is valid");
    let prepared = daemon
        .prepare(first.clone())
        .expect("first prepare succeeds");
    assert_eq!(
        daemon.prepare(first).expect("exact retry succeeds"),
        prepared
    );

    let wrong_epoch = PreparedRouteRequest::new(
        epoch().get() + 1,
        TenantId::new(),
        fence(5),
        [12; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("request is syntactically valid");
    assert!(matches!(
        daemon.prepare(wrong_epoch),
        Err(DaemonControlError::DaemonEpochMismatch { .. })
    ));

    let second = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        fence(6),
        [13; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("request is valid");
    assert!(matches!(
        daemon.prepare(second),
        Err(DaemonControlError::PlanCapacityExceeded)
    ));

    let conflicting = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        first_fence,
        [14; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("request is valid");
    assert!(matches!(
        daemon.prepare(conflicting),
        Err(DaemonControlError::PlanConflict)
    ));
    assert_eq!(
        prepared.binding_digest(),
        BindingDigest::new([11; 32]).as_bytes()
    );
}
