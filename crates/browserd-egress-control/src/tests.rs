#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::IoSlice;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream as StdUnixStream;

use browserd_core::{
    EgressFence, LaunchGeneration, LeaseId, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, WorkerEpoch, WorkerId,
};
use browserd_local_ipc::{HandoffError, Sender};
use nix::sys::socket::{MsgFlags, sendmsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;

use crate::{
    ActiveInstallResponse, ClientInstallError, InstallRequest, MAX_CONTROL_FRAME_BYTES,
    PendingInstall, ReceiveInstallError, ResponseMismatch, ServerCommitError, WireValidationError,
    read_json_frame, receive_listener, send_listener, write_json_frame,
};

const HANDOFF_FRAME_BYTES: usize = 33;
const DESCRIPTOR_OFFER: u8 = 0x52;

fn fence() -> EgressFence {
    EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                WorkerId::new("worker-a").expect("valid worker ID"),
                WorkerEpoch::new(7).expect("nonzero worker epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(11).expect("nonzero launch generation"),
        ),
        RouteGeneration::new(13).expect("nonzero route generation"),
        SessionId::new(),
        SessionIncarnation::new(17).expect("nonzero session incarnation"),
    )
}

fn request() -> InstallRequest {
    InstallRequest::new(LeaseId::new(), 19, fence(), [23; 32], 29).expect("request must be valid")
}

fn active(request: &InstallRequest) -> ActiveInstallResponse {
    ActiveInstallResponse::new(
        request.transfer_id().clone(),
        request.daemon_epoch(),
        request.egress_fence().clone(),
        31,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41_337),
        37,
        41,
    )
    .expect("active response must be valid")
}

fn capability() -> (OwnedFd, StdUnixStream) {
    let (capability, observer) = StdUnixStream::pair().expect("capability pair must be created");
    (capability.into(), observer)
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

async fn assert_capability_closed(observer: StdUnixStream) {
    observer
        .set_nonblocking(true)
        .expect("observer must become nonblocking");
    let observer = UnixStream::from_std(observer).expect("observer must become async");
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), observer.readable())
        .await
        .expect("all capability copies must close");
    read.expect("observer readiness must succeed");
    assert_eq!(
        observer.try_read(&mut byte).expect("EOF must be readable"),
        0
    );
}

#[tokio::test]
async fn installs_exactly_one_listener_and_returns_correlated_active_response() {
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must be created");
    let request = request();
    let expected = active(&request);
    let (listener, observer) = capability();
    let expected_for_server = expected.clone();
    let server = tokio::spawn(async move {
        let mut pending = receive_listener(server_stream, current_uid())
            .await
            .expect("install request must be received");
        assert_eq!(pending.request(), &request);
        let installed_listener = pending
            .take_listener()
            .expect("domain listener clone must be transferable exactly once");
        assert!(pending.take_listener().is_none());
        let response = pending
            .commit(expected_for_server)
            .await
            .expect("install must commit");
        drop(installed_listener);
        response
    });

    let received = send_listener(client_stream, expected_request(&expected), listener)
        .await
        .expect("client must observe the active response");
    assert_eq!(received, expected);
    assert_eq!(server.await.expect("server task must finish"), received);

    assert_capability_closed(observer).await;
}

fn expected_request(response: &ActiveInstallResponse) -> InstallRequest {
    InstallRequest::new(
        response.transfer_id().clone(),
        response.daemon_epoch(),
        response.egress_fence().clone(),
        [23; 32],
        29,
    )
    .expect("request must be valid")
}

#[test]
fn request_rejects_zero_epoch_revision_and_binding_digest() {
    assert_eq!(
        InstallRequest::new(LeaseId::new(), 0, fence(), [1; 32], 1),
        Err(WireValidationError::ZeroDaemonEpoch)
    );
    assert_eq!(
        InstallRequest::new(LeaseId::new(), 1, fence(), [1; 32], 0),
        Err(WireValidationError::ZeroPrepareRevision)
    );
    assert_eq!(
        InstallRequest::new(LeaseId::new(), 1, fence(), [0; 32], 1),
        Err(WireValidationError::ZeroBindingDigest)
    );
}

#[test]
fn active_response_rejects_invalid_domain_values() {
    let request = request();
    let valid_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 31_337);
    let build = |epoch, attachment, address, expiry, revision| {
        ActiveInstallResponse::new(
            request.transfer_id().clone(),
            epoch,
            request.egress_fence().clone(),
            attachment,
            address,
            expiry,
            revision,
        )
    };
    assert_eq!(
        build(0, 1, valid_address, 1, 1),
        Err(WireValidationError::ZeroDaemonEpoch)
    );
    assert_eq!(
        build(1, 0, valid_address, 1, 1),
        Err(WireValidationError::ZeroAttachmentId)
    );
    assert_eq!(
        build(
            1,
            1,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 31_337),
            1,
            1,
        ),
        Err(WireValidationError::InvalidProxyAddress(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            31_337
        )))
    );
    assert_eq!(
        build(
            1,
            1,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            1,
            1,
        ),
        Err(WireValidationError::InvalidProxyAddress(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0
        )))
    );
    assert_eq!(
        build(1, 1, valid_address, 0, 1),
        Err(WireValidationError::ZeroExpiry)
    );
    assert_eq!(
        build(1, 1, valid_address, 1, 0),
        Err(WireValidationError::ZeroActivationRevision)
    );
}

#[tokio::test]
async fn wrong_peer_uid_is_rejected_before_receiver_ready_and_no_fd_is_sent() {
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must be created");
    let request = request();
    let (listener, observer) = capability();
    let wrong_uid = current_uid().wrapping_add(1);
    assert_ne!(wrong_uid, current_uid());
    let server = tokio::spawn(receive_listener(server_stream, wrong_uid));

    let client_error = send_listener(client_stream, request, listener)
        .await
        .expect_err("client must fail before commit");
    assert!(!client_error.commit_was_observed());
    let server_error = server
        .await
        .expect("server task must finish")
        .expect_err("wrong UID must be rejected");
    assert!(matches!(
        server_error,
        ReceiveInstallError::PeerUidMismatch { .. }
    ));
    assert_capability_closed(observer).await;
}

#[tokio::test]
async fn malformed_unknown_and_oversized_metadata_are_rejected_before_ready() {
    let (mut malformed_peer, malformed_server) =
        UnixStream::pair().expect("control pair must be created");
    malformed_peer
        .write_all(&3_u32.to_be_bytes())
        .await
        .expect("length must be sent");
    malformed_peer
        .write_all(b"not")
        .await
        .expect("payload must be sent");
    assert!(matches!(
        receive_listener(malformed_server, current_uid()).await,
        Err(ReceiveInstallError::Metadata(_))
    ));

    let request = request();
    let mut unknown = serde_json::to_value(&request).expect("request must serialize");
    unknown
        .as_object_mut()
        .expect("request must be an object")
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    let unknown = serde_json::to_vec(&unknown).expect("request must serialize");
    let (mut unknown_peer, unknown_server) =
        UnixStream::pair().expect("control pair must be created");
    unknown_peer
        .write_all(
            &u32::try_from(unknown.len())
                .expect("test frame length must fit")
                .to_be_bytes(),
        )
        .await
        .expect("length must be sent");
    unknown_peer
        .write_all(&unknown)
        .await
        .expect("payload must be sent");
    assert!(matches!(
        receive_listener(unknown_server, current_uid()).await,
        Err(ReceiveInstallError::Metadata(_))
    ));

    let (mut oversized_peer, oversized_server) =
        UnixStream::pair().expect("control pair must be created");
    oversized_peer
        .write_all(
            &u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
                .expect("test frame length must fit")
                .to_be_bytes(),
        )
        .await
        .expect("length must be sent");
    assert!(matches!(
        receive_listener(oversized_server, current_uid()).await,
        Err(ReceiveInstallError::Metadata(_))
    ));
}

#[tokio::test]
async fn zero_descriptor_offer_is_rejected() {
    let (mut peer, server_stream) = UnixStream::pair().expect("control pair must be created");
    let request = request();
    let server = tokio::spawn(receive_listener(server_stream, current_uid()));
    write_json_frame(&mut peer, &request)
        .await
        .expect("metadata must be sent");
    let mut ready = [0_u8; HANDOFF_FRAME_BYTES];
    peer.read_exact(&mut ready)
        .await
        .expect("receiver ready must arrive");

    let nonce = LeaseId::new();
    let mut offer = [0_u8; HANDOFF_FRAME_BYTES];
    offer[0] = DESCRIPTOR_OFFER;
    offer[1..17].copy_from_slice(request.transfer_id().as_bytes());
    offer[17..].copy_from_slice(nonce.as_bytes());
    let sent = peer
        .async_io(Interest::WRITABLE, || {
            let buffers = [IoSlice::new(&offer)];
            sendmsg::<()>(
                peer.as_raw_fd(),
                &buffers,
                &[],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(std::io::Error::from)
        })
        .await
        .expect("empty ancillary offer must be sent");
    assert_eq!(sent, HANDOFF_FRAME_BYTES);

    let error = server
        .await
        .expect("server task must finish")
        .expect_err("zero descriptors must fail closed");
    assert!(matches!(
        error,
        ReceiveInstallError::Handoff(HandoffError::RightsMessageCount { received: 0 })
    ));
}

#[tokio::test]
async fn excess_descriptor_offer_is_rejected() {
    let (mut peer, server_stream) = UnixStream::pair().expect("control pair must be created");
    let request = request();
    let server = tokio::spawn(receive_listener(server_stream, current_uid()));
    write_json_frame(&mut peer, &request)
        .await
        .expect("metadata must be sent");
    let (first, first_observer) = capability();
    let (second, second_observer) = capability();
    let sender = Sender::new(peer, request.transfer_id().clone(), vec![first, second])
        .expect("two-descriptor malicious sender must be constructible");
    let ready = sender.await_ready().await.expect("ready must arrive");
    let offered = ready.offer().await.expect("offer must be sent");

    let error = server
        .await
        .expect("server task must finish")
        .expect_err("excess descriptors must fail closed");
    assert!(matches!(
        error,
        ReceiveInstallError::Handoff(HandoffError::DescriptorCountMismatch {
            expected: 1,
            received: 2
        })
    ));
    offered
        .await_accepted()
        .await
        .expect_err("rejected offer must close the sender protocol state");
    assert_capability_closed(first_observer).await;
    assert_capability_closed(second_observer).await;
}

#[tokio::test]
async fn dropping_pending_install_closes_receiver_clones_and_client_fails_precommit() {
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must be created");
    let request = request();
    let (listener, observer) = capability();
    let client = tokio::spawn(send_listener(client_stream, request, listener));
    let pending = receive_listener(server_stream, current_uid())
        .await
        .expect("pending install must arrive");
    assert!(!client.is_finished());
    drop(pending);

    let error = client
        .await
        .expect("client task must finish")
        .expect_err("cancelled install must fail");
    assert!(!error.commit_was_observed());
    assert_capability_closed(observer).await;
}

#[tokio::test]
async fn response_loss_after_commit_requires_status_reconciliation() {
    let (client_stream, server_stream) = UnixStream::pair().expect("control pair must be created");
    let request = request();
    let (listener, observer) = capability();
    let client = tokio::spawn(send_listener(client_stream, request, listener));
    let pending = receive_listener(server_stream, current_uid())
        .await
        .expect("pending install must arrive");
    let PendingInstall {
        request: _,
        listener,
        receiver,
    } = pending;
    let committed = receiver.commit().await.expect("commit must be announced");
    let receipted = committed
        .await_receipt()
        .await
        .expect("client must receipt commit");
    let complete = receipted.complete().await.expect("handoff must complete");
    let (stream, protocol_descriptors) = complete.into_parts();
    drop(protocol_descriptors);
    drop(listener);
    drop(stream);

    let error = client
        .await
        .expect("client task must finish")
        .expect_err("missing active response must fail");
    assert!(matches!(
        error,
        ClientInstallError::CommittedButUnconfirmed(_)
    ));
    assert!(error.commit_was_observed());
    assert!(error.requires_status_reconciliation());
    assert_capability_closed(observer).await;
}

#[tokio::test]
async fn server_rejects_wrong_transfer_fence_and_epoch_before_commit() {
    let mismatches = [
        ResponseMismatch::TransferId,
        ResponseMismatch::EgressFence,
        ResponseMismatch::DaemonEpoch,
    ];
    for mismatch in mismatches {
        let (client_stream, server_stream) =
            UnixStream::pair().expect("control pair must be created");
        let request = request();
        let (listener, observer) = capability();
        let client = tokio::spawn(send_listener(client_stream, request.clone(), listener));
        let pending = receive_listener(server_stream, current_uid())
            .await
            .expect("pending install must arrive");
        let valid = active(&request);
        let response = match mismatch {
            ResponseMismatch::TransferId => ActiveInstallResponse::new(
                LeaseId::new(),
                valid.daemon_epoch(),
                valid.egress_fence().clone(),
                valid.attachment_id(),
                valid.proxy_address(),
                valid.expires_at_millis(),
                valid.activation_revision(),
            ),
            ResponseMismatch::EgressFence => ActiveInstallResponse::new(
                valid.transfer_id().clone(),
                valid.daemon_epoch(),
                fence(),
                valid.attachment_id(),
                valid.proxy_address(),
                valid.expires_at_millis(),
                valid.activation_revision(),
            ),
            ResponseMismatch::DaemonEpoch => ActiveInstallResponse::new(
                valid.transfer_id().clone(),
                valid.daemon_epoch() + 1,
                valid.egress_fence().clone(),
                valid.attachment_id(),
                valid.proxy_address(),
                valid.expires_at_millis(),
                valid.activation_revision(),
            ),
        }
        .expect("mismatched response remains structurally valid");
        let error = pending
            .commit(response)
            .await
            .expect_err("mismatch must be rejected");
        assert!(matches!(
            error,
            ServerCommitError::ResponseMismatch(actual) if actual == mismatch
        ));
        assert!(!error.commit_was_announced());
        let client_error = client
            .await
            .expect("client task must finish")
            .expect_err("client must fail before commit");
        assert!(!client_error.commit_was_observed());
        assert_capability_closed(observer).await;
    }
}

#[tokio::test]
async fn client_rejects_wrong_transfer_fence_and_epoch_after_commit() {
    let mismatches = [
        ResponseMismatch::TransferId,
        ResponseMismatch::EgressFence,
        ResponseMismatch::DaemonEpoch,
    ];
    for mismatch in mismatches {
        let (client_stream, server_stream) =
            UnixStream::pair().expect("control pair must be created");
        let request = request();
        let (listener, observer) = capability();
        let client = tokio::spawn(send_listener(client_stream, request.clone(), listener));
        let pending = receive_listener(server_stream, current_uid())
            .await
            .expect("pending install must arrive");
        let valid = active(&request);
        let response = match mismatch {
            ResponseMismatch::TransferId => ActiveInstallResponse::new(
                LeaseId::new(),
                valid.daemon_epoch(),
                valid.egress_fence().clone(),
                valid.attachment_id(),
                valid.proxy_address(),
                valid.expires_at_millis(),
                valid.activation_revision(),
            ),
            ResponseMismatch::EgressFence => ActiveInstallResponse::new(
                valid.transfer_id().clone(),
                valid.daemon_epoch(),
                fence(),
                valid.attachment_id(),
                valid.proxy_address(),
                valid.expires_at_millis(),
                valid.activation_revision(),
            ),
            ResponseMismatch::DaemonEpoch => ActiveInstallResponse::new(
                valid.transfer_id().clone(),
                valid.daemon_epoch() + 1,
                valid.egress_fence().clone(),
                valid.attachment_id(),
                valid.proxy_address(),
                valid.expires_at_millis(),
                valid.activation_revision(),
            ),
        }
        .expect("mismatched response remains structurally valid");

        let PendingInstall {
            request: _,
            listener: receiver_listener,
            receiver,
        } = pending;
        let committed = receiver.commit().await.expect("commit must be announced");
        let receipted = committed
            .await_receipt()
            .await
            .expect("client must receipt commit");
        let complete = receipted.complete().await.expect("handoff must complete");
        let (mut stream, protocol_descriptors) = complete.into_parts();
        drop(protocol_descriptors);
        drop(receiver_listener);
        write_json_frame(&mut stream, &response)
            .await
            .expect("malicious response must be sent");

        let error = client
            .await
            .expect("client task must finish")
            .expect_err("client must reject mismatched response");
        assert!(matches!(
            error,
            ClientInstallError::CommittedWithInvalidResponse(_)
        ));
        assert!(error.commit_was_observed());
        assert_capability_closed(observer).await;
    }
}

#[tokio::test]
async fn bounded_response_reader_rejects_an_oversized_frame() {
    let (mut writer, mut reader) = UnixStream::pair().expect("control pair must be created");
    writer
        .write_all(
            &u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
                .expect("test frame length must fit")
                .to_be_bytes(),
        )
        .await
        .expect("length must be sent");
    let response: Result<ActiveInstallResponse, _> = read_json_frame(&mut reader).await;
    assert!(response.is_err());
}
