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

use super::{
    DaemonControlError, DaemonLimits, EgressDaemon, PreparedRouteRequest, RenewRouteRequest,
};

// A concurrently spawned test child can retain CLOEXEC socket capabilities
// between fork and exec. Keep process spawning outside listener lifecycle tests
// so TCP refusal and control EOF describe this process's completed cleanup.
pub(crate) static LISTENER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

fn listener_copy_count(inode: u64) -> usize {
    let descriptor = format!("socket:[{inode}]");
    std::fs::read_dir("/proc/self/fd")
        .expect("process descriptor directory must be readable")
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter(|target| target.to_string_lossy() == descriptor)
        .count()
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

async fn install_active_route(
    daemon: &Arc<EgressDaemon>,
    seed: u64,
    binding_digest: [u8; 32],
) -> (
    EgressFence,
    std::net::SocketAddr,
    browserd_egress_control::ActiveInstallResponse,
) {
    let route_fence = fence(seed);
    let prepared = prepare(daemon, route_fence.clone(), binding_digest);
    let (address, listener) = listener();
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must open");
    let server = tokio::spawn({
        let daemon = Arc::clone(daemon);
        async move {
            daemon
                .handle_control_stream(server_stream, Uid::current().as_raw())
                .await
        }
    });
    let active = send_listener(client_stream, install_request(&prepared), listener)
        .await
        .expect("client must receive active receipt");
    assert_eq!(
        server
            .await
            .expect("server task must join")
            .expect("install succeeds"),
        Some(active.clone())
    );
    (route_fence, address, active)
}

#[tokio::test]
async fn revoking_plan_keeps_its_active_budget_until_accepted_guards_drain() {
    struct HeldIngress {
        accepted: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait]
    impl AcceptedIngressHandler for HeldIngress {
        async fn handle(&self, ingress: AcceptedRouteIngress) -> Result<(), IngressHandlerError> {
            self.accepted.notify_one();
            self.release.notified().await;
            drop(ingress);
            Ok(())
        }
    }
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let handler = Arc::new(HeldIngress {
        accepted: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let limits = DaemonLimits::new(Duration::from_secs(30), 1, quotas())
        .expect("limits")
        .with_plan_history_capacity(2)
        .expect("history");
    let daemon =
        Arc::new(EgressDaemon::with_handler(epoch(), limits, handler.clone()).expect("daemon"));
    let (first_fence, address, _) = install_active_route(&daemon, 81, [81; 32]).await;
    let client = TcpStream::connect(address)
        .await
        .expect("accepted connection");
    handler.accepted.notified().await;
    let revoke = tokio::spawn({
        let daemon = daemon.clone();
        let first_fence = first_fence.clone();
        async move { daemon.revoke(epoch().get(), &first_fence).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while daemon
            .status(epoch().get(), &first_fence)
            .expect("status")
            .state()
            == AttachmentState::Active
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revocation begins");
    let next_request = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        fence(82),
        [82; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("next request");
    assert!(
        matches!(
            daemon.prepare(next_request.clone()),
            Err(DaemonControlError::PlanCapacityExceeded)
        ),
        "revocation intent alone cannot recover an undrained slot"
    );
    handler.release.notify_one();
    drop(client);
    assert_eq!(
        revoke
            .await
            .expect("revoke joins")
            .expect("drain completes")
            .state(),
        AttachmentState::Released
    );
    let next = daemon
        .prepare(next_request)
        .expect("actual drain recovers the slot");
    daemon
        .revoke(epoch().get(), next.egress_fence())
        .await
        .expect("cancel next");
    daemon.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn bounded_terminal_history_keeps_exact_receipts_and_rejects_reactivation() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let limits = DaemonLimits::new(Duration::from_secs(30), 1, quotas())
        .expect("limits")
        .with_plan_history_capacity(2)
        .expect("independent history bound");
    let daemon = Arc::new(
        EgressDaemon::with_handler(epoch(), limits, Arc::new(DropHandler)).expect("daemon"),
    );
    let first_fence = fence(71);
    let first_request = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        first_fence.clone(),
        [71; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("first request");
    let first_prepared = daemon
        .prepare(first_request.clone())
        .expect("first prepare");
    let (first_address, descriptor) = listener();
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair");
    let server = tokio::spawn({
        let daemon = daemon.clone();
        async move {
            daemon
                .handle_control_stream(server_stream, Uid::current().as_raw())
                .await
        }
    });
    let active = send_listener(client_stream, install_request(&first_prepared), descriptor)
        .await
        .expect("actual install");
    assert_eq!(
        server.await.expect("server join").expect("server install"),
        Some(active.clone())
    );
    assert_eq!(
        daemon
            .revoke(epoch().get(), &first_fence)
            .await
            .expect("first cleanup")
            .state(),
        AttachmentState::Released
    );
    let second = prepare(&daemon, fence(72), [72; 32]);
    assert_eq!(
        daemon
            .revoke(epoch().get(), second.egress_fence())
            .await
            .expect("second cleanup")
            .state(),
        AttachmentState::Released
    );
    let third_request = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        fence(73),
        [73; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("third request");
    assert!(matches!(
        daemon.prepare(third_request),
        Err(DaemonControlError::PlanHistoryCapacityExceeded)
    ));
    assert_eq!(
        daemon
            .prepare(first_request)
            .expect("exact immutable retry remains available"),
        first_prepared
    );
    assert_eq!(
        daemon
            .status(epoch().get(), &first_fence)
            .expect("first history")
            .state(),
        AttachmentState::Released
    );
    assert_eq!(
        daemon
            .status(epoch().get(), second.egress_fence())
            .expect("second history")
            .state(),
        AttachmentState::Released
    );
    let (stale_address, stale_descriptor) = listener();
    let (client_stream, server_stream) = UnixStream::pair().expect("old ticket pair");
    let server = tokio::spawn({
        let daemon = daemon.clone();
        async move {
            daemon
                .handle_control_stream(server_stream, Uid::current().as_raw())
                .await
        }
    });
    assert!(
        send_listener(
            client_stream,
            install_request(&first_prepared),
            stale_descriptor
        )
        .await
        .is_err(),
        "retained old prepare cannot reactivate a terminal route"
    );
    assert!(server.await.expect("old ticket server joins").is_err());
    assert!(TcpStream::connect(stale_address).await.is_err());
    assert!(TcpStream::connect(first_address).await.is_err());
    assert!(
        daemon
            .renew(
                RenewRouteRequest::new(
                    1,
                    epoch().get(),
                    first_fence.clone(),
                    active.attachment_id(),
                    active.activation_revision(),
                    Duration::from_secs(10)
                )
                .expect("old renewal")
            )
            .is_err()
    );
    assert_eq!(
        daemon
            .revoke(epoch().get(), &first_fence)
            .await
            .expect("terminal revoke retry")
            .state(),
        AttachmentState::Released
    );
    let wrong_epoch = PreparedRouteRequest::new(
        epoch().get() + 1,
        TenantId::new(),
        first_fence,
        [71; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("wrong incarnation");
    assert!(matches!(
        daemon.prepare(wrong_epoch),
        Err(DaemonControlError::DaemonEpochMismatch { .. })
    ));
    daemon
        .shutdown()
        .await
        .expect("history remains fail closed through drain");
}

#[test]
fn history_capacity_cannot_be_smaller_than_active_capacity() {
    assert!(matches!(
        DaemonLimits::new(Duration::from_secs(30), 2, quotas())
            .expect("limits")
            .with_plan_history_capacity(1),
        Err(DaemonControlError::InvalidLimits)
    ));
}

#[tokio::test]
async fn released_plan_recovers_active_capacity_without_reviving_its_authority() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let daemon = Arc::new(daemon(1));
    let (first_fence, first_address, first_active) =
        install_active_route(&daemon, 61, [61; 32]).await;
    let next_request = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        fence(62),
        [62; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("next request");
    assert!(matches!(
        daemon.prepare(next_request.clone()),
        Err(DaemonControlError::PlanCapacityExceeded)
    ));
    assert_eq!(
        daemon
            .revoke(epoch().get(), &first_fence)
            .await
            .expect("drain first")
            .state(),
        AttachmentState::Released
    );
    let next = daemon
        .prepare(next_request)
        .expect("released plan recovers the active slot");
    assert_eq!(
        daemon
            .status(epoch().get(), &first_fence)
            .expect("old receipt remains tracked")
            .state(),
        AttachmentState::Released
    );
    assert!(
        daemon
            .renew(
                RenewRouteRequest::new(
                    1,
                    epoch().get(),
                    first_fence.clone(),
                    first_active.attachment_id(),
                    first_active.activation_revision(),
                    Duration::from_secs(10)
                )
                .expect("old renewal")
            )
            .is_err()
    );
    assert!(
        TcpStream::connect(first_address).await.is_err(),
        "old listener stays closed"
    );
    assert_eq!(
        daemon
            .revoke(epoch().get(), next.egress_fence())
            .await
            .expect("cancel second")
            .state(),
        AttachmentState::Released
    );
    daemon.shutdown().await.expect("shutdown");
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
    assert_eq!(
        listener_copy_count(listener_inode),
        0,
        "released attachment must close every listener capability copy"
    );
}

#[tokio::test]
async fn active_route_renewal_is_exactly_replayable_and_updates_status() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let daemon = Arc::new(daemon(8));
    let (route_fence, address, active) = install_active_route(&daemon, 8, [18; 32]).await;
    let renewal = RenewRouteRequest::new(
        1,
        epoch().get(),
        route_fence.clone(),
        active.attachment_id(),
        active.activation_revision(),
        Duration::from_secs(20),
    )
    .expect("renewal request should be valid");

    let renewed = daemon
        .renew(renewal.clone())
        .expect("active route should renew");
    assert!(renewed.expires_at_millis() > active.expires_at_millis());
    assert_eq!(
        daemon
            .renew(renewal)
            .expect("exact renewal replay should return its committed receipt"),
        renewed
    );
    let status = daemon
        .status(epoch().get(), &route_fence)
        .expect("renewed status should resolve");
    assert_eq!(status.state(), AttachmentState::Active);
    assert_eq!(
        status
            .active()
            .expect("active status should retain its receipt")
            .expires_at_millis(),
        renewed.expires_at_millis()
    );
    let client = TcpStream::connect(address)
        .await
        .expect("renewed listener should remain active");
    drop(client);
    daemon
        .revoke(epoch().get(), &route_fence)
        .await
        .expect("renewed route should revoke");
}

#[tokio::test]
async fn superseded_or_conflicting_renewal_ids_cannot_change_the_latest_deadline() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    let daemon = Arc::new(daemon(8));
    let (route_fence, _address, active) = install_active_route(&daemon, 9, [19; 32]).await;
    let first = RenewRouteRequest::new(
        1,
        epoch().get(),
        route_fence.clone(),
        active.attachment_id(),
        active.activation_revision(),
        Duration::from_secs(15),
    )
    .expect("first renewal should be valid");
    let second = RenewRouteRequest::new(
        2,
        epoch().get(),
        route_fence.clone(),
        active.attachment_id(),
        active.activation_revision(),
        Duration::from_secs(20),
    )
    .expect("second renewal should be valid");

    daemon
        .renew(first.clone())
        .expect("first renewal should commit");
    let latest = daemon
        .renew(second.clone())
        .expect("later renewal should commit");
    assert!(matches!(
        daemon.renew(first),
        Err(DaemonControlError::RenewalConflict)
    ));
    let conflicting = RenewRouteRequest::new(
        second.renewal_sequence(),
        epoch().get(),
        route_fence.clone(),
        active.attachment_id(),
        active.activation_revision(),
        Duration::from_secs(25),
    )
    .expect("conflicting replay remains structurally valid");
    assert!(matches!(
        daemon.renew(conflicting),
        Err(DaemonControlError::RenewalConflict)
    ));
    assert_eq!(
        daemon
            .status(epoch().get(), &route_fence)
            .expect("latest status should resolve")
            .active()
            .expect("route should remain active")
            .expires_at_millis(),
        latest.expires_at_millis()
    );
    daemon
        .revoke(epoch().get(), &route_fence)
        .await
        .expect("route should revoke after renewal conflicts");
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
    assert_failed_commit_rolls_back(3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_commit_on_other_runtime_threads_closes_every_listener_copy() {
    let _listener_test = LISTENER_TEST_LOCK.lock().await;
    for seed in 100..116 {
        assert_failed_commit_rolls_back(seed).await;
    }
}

async fn assert_failed_commit_rolls_back(seed: u64) {
    let daemon = daemon(8);
    let route_fence = fence(seed);
    let prepared = prepare(&daemon, route_fence.clone(), [10; 32]);
    let (address, listener) = listener();
    let listener_inode = fstat(&listener)
        .expect("listener identity must be readable")
        .st_ino;
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
    assert!(
        matches!(
            error,
            DaemonControlError::Commit(ServerCommitError::BeforeAnnouncement(_))
        ),
        "unexpected commit failure: {error:?}"
    );
    assert_eq!(
        daemon
            .status(epoch().get(), &route_fence)
            .expect("terminal status must reconcile")
            .state(),
        AttachmentState::Released
    );
    assert_eq!(
        listener_copy_count(listener_inode),
        0,
        "rollback must close domain and protocol listener copies before returning Released"
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

#[test]
fn shared_prepare_is_explicit_and_mode_policy_and_route_identity_remain_immutable() {
    let daemon = daemon(8);
    let first = fence(5);
    let second = EgressFence::new(
        first.shard().clone(),
        RouteGeneration::new(6).expect("route"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("incarnation"),
    );
    let first_request = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        first.clone(),
        [7; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("request")
    .with_shared_context();
    let receipt = daemon
        .prepare(first_request.clone())
        .expect("shared primary");
    assert_eq!(daemon.prepare(first_request).expect("exact retry"), receipt);
    let second_request = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        second,
        [7; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("request");
    assert!(
        daemon.prepare(second_request.clone()).is_err(),
        "legacy path cannot share a shard"
    );
    assert!(daemon.prepare(second_request.with_shared_context()).is_ok());
    let changed = PreparedRouteRequest::new(
        epoch().get(),
        TenantId::new(),
        first,
        [8; 32],
        "public-web",
        Duration::from_secs(10),
    )
    .expect("different policy")
    .with_shared_context();
    assert!(matches!(
        daemon.prepare(changed),
        Err(DaemonControlError::PlanConflict)
    ));
}
