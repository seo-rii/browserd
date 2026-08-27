#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use browserd_core::LeaseId;
use nix::sys::socket::{ControlMessage, MsgFlags, UnixCredentials, sendmsg, setsockopt, sockopt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::UnixStream;

use crate::{
    COORDINATOR_COMMITTED, DESCRIPTOR_OFFER, DescriptorCount, FOLLOWER_FINAL_RECEIPT, FRAME_BYTES,
    HandoffError, Receiver, ReceiverReady, Sender,
};

fn pipe_reader() -> OwnedFd {
    let (reader, writer) = nix::unistd::pipe().expect("test pipe must be created");
    drop(writer);
    reader
}

fn pipe() -> (OwnedFd, OwnedFd) {
    nix::unistd::pipe().expect("test pipe must be created")
}

async fn ready_receiver(
    expected_count: usize,
    pass_credentials: bool,
) -> (Receiver<ReceiverReady>, UnixStream, LeaseId) {
    let (peer, receiver_stream) = UnixStream::pair().expect("socket pair must be created");
    if pass_credentials {
        setsockopt(&receiver_stream, sockopt::PassCred, &true).expect("passcred must be enabled");
    }
    let transfer_id = LeaseId::new();
    let receiver = Receiver::new(
        receiver_stream,
        transfer_id.clone(),
        DescriptorCount::new(expected_count).expect("valid descriptor count"),
    )
    .ready()
    .await
    .expect("receiver sends ready frame");
    let mut peer = peer;
    let mut ready = [0_u8; FRAME_BYTES];
    peer.read_exact(&mut ready)
        .await
        .expect("peer reads ready frame");
    (receiver, peer, transfer_id)
}

async fn accepted_pair() -> (
    Sender<crate::SenderAccepted>,
    Receiver<crate::ReceiverAccepted>,
) {
    let (sender_stream, receiver_stream) = UnixStream::pair().expect("socket pair must be created");
    let transfer_id = LeaseId::new();
    let sender =
        Sender::new(sender_stream, transfer_id.clone(), vec![pipe_reader()]).expect("valid sender");
    let receiver = Receiver::new(
        receiver_stream,
        transfer_id,
        DescriptorCount::new(1).expect("valid descriptor count"),
    );
    let receiver = receiver.ready().await.expect("receiver ready");
    let sender = sender.await_ready().await.expect("sender sees ready");
    let sender = sender.offer().await.expect("sender offers descriptor");
    let receiver = receiver.receive().await.expect("receiver receives offer");
    let receiver = receiver.accept().await.expect("receiver accepts offer");
    let sender = sender
        .await_accepted()
        .await
        .expect("sender sees acceptance");
    (sender, receiver)
}

async fn receiver_follows_raw_coordinator(
    receiver: Receiver<crate::ReceiverAccepted>,
    peer: &mut UnixStream,
    transfer_id: &LeaseId,
    nonce: &[u8; 16],
) -> Receiver<crate::FollowerAccepted> {
    let peer_exchange = async {
        let coordinator = crate::protocol_frame(crate::COORDINATOR_ROLE, transfer_id, nonce);
        raw_send(peer, &coordinator, &[], false).await;
        let mut follower = [0_u8; FRAME_BYTES];
        peer.read_exact(&mut follower)
            .await
            .expect("follower role must be read");
        crate::validate_frame(&follower, crate::FOLLOWER_ROLE, transfer_id, nonce)
            .expect("follower role frame must match");
    };
    let (receiver, ()) = tokio::join!(receiver.into_follower(), peer_exchange);
    receiver.expect("receiver selects follower role")
}

async fn raw_send(
    stream: &UnixStream,
    frame: &[u8; FRAME_BYTES],
    descriptors: &[i32],
    credentials: bool,
) {
    raw_send_bytes(stream, frame, descriptors, credentials).await;
}

async fn raw_send_bytes(stream: &UnixStream, bytes: &[u8], descriptors: &[i32], credentials: bool) {
    let credentials_value = UnixCredentials::new();
    let sent = stream
        .async_io(Interest::WRITABLE, || {
            let buffers = [IoSlice::new(bytes)];
            let rights = ControlMessage::ScmRights(descriptors);
            let credential_message = ControlMessage::ScmCredentials(&credentials_value);
            let controls = if credentials {
                vec![rights, credential_message]
            } else if descriptors.is_empty() {
                Vec::new()
            } else {
                vec![rights]
            };
            sendmsg::<()>(
                stream.as_raw_fd(),
                &buffers,
                &controls,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(std::io::Error::from)
        })
        .await
        .expect("raw protocol frame must be sent");
    assert_eq!(sent, bytes.len());
}

fn assert_writer_closed(reader: &OwnedFd) {
    let current = nix::fcntl::fcntl(reader, nix::fcntl::FcntlArg::F_GETFL)
        .expect("pipe status flags must be read");
    let flags = nix::fcntl::OFlag::from_bits_truncate(current) | nix::fcntl::OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(reader, nix::fcntl::FcntlArg::F_SETFL(flags))
        .expect("pipe must become nonblocking");
    let mut byte = [0_u8; 1];
    assert_eq!(
        nix::unistd::read(reader, &mut byte).expect("closed writer yields EOF"),
        0
    );
}

#[tokio::test]
async fn completes_all_receipted_phases_and_preserves_descriptor_order() {
    let (sender_stream, receiver_stream) = UnixStream::pair().expect("socket pair must be created");
    let transfer_id = LeaseId::new();
    let first = pipe_reader();
    let second = pipe_reader();
    let expected_first = nix::sys::stat::fstat(first.as_fd()).expect("first fd metadata");
    let expected_second = nix::sys::stat::fstat(second.as_fd()).expect("second fd metadata");

    let sender =
        Sender::new(sender_stream, transfer_id.clone(), vec![first, second]).expect("valid sender");
    let receiver = Receiver::new(
        receiver_stream,
        transfer_id,
        DescriptorCount::new(2).expect("valid exact count"),
    );

    let receiver = receiver.ready().await.expect("receiver ready");
    let sender = sender.await_ready().await.expect("sender sees ready");
    let sender = sender.offer().await.expect("sender offers descriptors");
    let receiver = receiver.receive().await.expect("receiver receives offer");
    let receiver = receiver.accept().await.expect("receiver accepts offer");
    let sender = sender
        .await_accepted()
        .await
        .expect("sender sees acceptance");
    let (sender, receiver) = tokio::join!(sender.into_coordinator(), receiver.into_follower(),);
    let sender = sender.expect("sender coordinates");
    let receiver = receiver.expect("receiver follows");
    let sender = sender.commit().await.expect("sender commits");
    assert!(sender.descriptors.is_none());
    let receiver = receiver
        .await_committed()
        .await
        .expect("receiver sees commit");
    let receiver = receiver.receipt().await.expect("receiver sends receipt");
    assert!(receiver.descriptors.is_some());
    let sender = sender.await_receipt().await.expect("sender sees receipt");
    let sender_complete = sender.complete().await.expect("sender completes");
    let received = receiver
        .await_complete()
        .await
        .expect("receiver sees completion");

    assert_eq!(received.descriptors().len(), 2);
    assert_eq!(
        nix::sys::stat::fstat(received.descriptors()[0].as_fd()).expect("received first metadata"),
        expected_first
    );
    assert_eq!(
        nix::sys::stat::fstat(received.descriptors()[1].as_fd()).expect("received second metadata"),
        expected_second
    );
    for descriptor in received.descriptors() {
        let flags = nix::fcntl::fcntl(descriptor, nix::fcntl::FcntlArg::F_GETFD)
            .expect("received descriptor flags");
        assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
    }

    let mut sender_stream = sender_complete.into_stream();
    let (mut receiver_stream, _descriptors) = received.into_parts();
    sender_stream
        .write_all(b"reused")
        .await
        .expect("completed sender stream remains usable");
    let mut reused = [0_u8; 6];
    receiver_stream
        .read_exact(&mut reused)
        .await
        .expect("completed receiver stream remains usable");
    assert_eq!(&reused, b"reused");
}

#[tokio::test]
async fn descriptor_receiver_can_coordinate_the_commit_round_trip() {
    let (sender_stream, receiver_stream) = UnixStream::pair().expect("socket pair must be created");
    let transfer_id = LeaseId::new();
    let descriptor = pipe_reader();
    let sender =
        Sender::new(sender_stream, transfer_id.clone(), vec![descriptor]).expect("valid sender");
    let receiver = Receiver::new(
        receiver_stream,
        transfer_id,
        DescriptorCount::new(1).expect("valid exact count"),
    );

    let receiver = receiver.ready().await.expect("receiver ready");
    let sender = sender.await_ready().await.expect("sender sees ready");
    let sender = sender.offer().await.expect("sender offers descriptor");
    let receiver = receiver.receive().await.expect("receiver receives offer");
    let receiver = receiver.accept().await.expect("receiver accepts offer");
    let sender = sender
        .await_accepted()
        .await
        .expect("sender sees acceptance");
    let (receiver, sender) = tokio::join!(receiver.into_coordinator(), sender.into_follower(),);
    let receiver = receiver.expect("receiver coordinates");
    let sender = sender.expect("sender follows");
    let receiver = receiver.commit().await.expect("receiver commits");
    let sender = sender.await_committed().await.expect("sender sees commit");
    assert!(sender.descriptors.is_none());
    let sender = sender.receipt().await.expect("sender sends receipt");
    let receiver = receiver
        .await_receipt()
        .await
        .expect("receiver sees receipt");
    let receiver = receiver.complete().await.expect("receiver completes");
    let sender = sender
        .await_complete()
        .await
        .expect("sender sees completion");

    assert_eq!(receiver.descriptors().len(), 1);
    assert!(receiver.descriptors.is_some());
    let _sender_stream = sender.into_stream();
}

#[tokio::test]
async fn choosing_coordinator_on_both_peers_fails_closed() {
    let (sender, receiver) = accepted_pair().await;
    let (sender, receiver) = tokio::join!(sender.into_coordinator(), receiver.into_coordinator(),);

    assert!(matches!(
        sender.unwrap_err(),
        HandoffError::UnexpectedPhase {
            expected: crate::FOLLOWER_ROLE,
            received: crate::COORDINATOR_ROLE
        }
    ));
    assert!(matches!(
        receiver.unwrap_err(),
        HandoffError::UnexpectedPhase {
            expected: crate::FOLLOWER_ROLE,
            received: crate::COORDINATOR_ROLE
        }
    ));
}

#[tokio::test]
async fn choosing_follower_on_both_peers_fails_closed() {
    let (sender, receiver) = accepted_pair().await;
    let (sender, receiver) = tokio::join!(sender.into_follower(), receiver.into_follower(),);

    assert!(matches!(
        sender.unwrap_err(),
        HandoffError::UnexpectedPhase {
            expected: crate::COORDINATOR_ROLE,
            received: crate::FOLLOWER_ROLE
        }
    ));
    assert!(matches!(
        receiver.unwrap_err(),
        HandoffError::UnexpectedPhase {
            expected: crate::COORDINATOR_ROLE,
            received: crate::FOLLOWER_ROLE
        }
    ));
}

#[test]
fn descriptor_count_is_nonzero_and_bounded() {
    assert!(DescriptorCount::new(0).is_err());
    assert!(DescriptorCount::new(crate::MAX_DESCRIPTOR_COUNT).is_ok());
    assert!(DescriptorCount::new(crate::MAX_DESCRIPTOR_COUNT + 1).is_err());
}

#[tokio::test]
async fn sender_rejects_zero_and_excess_descriptors_without_leaking_them() {
    let (stream, peer) = UnixStream::pair().expect("socket pair must be created");
    drop(peer);
    assert!(Sender::new(stream, LeaseId::new(), Vec::new()).is_err());

    let (stream, peer) = UnixStream::pair().expect("socket pair must be created");
    drop(peer);
    let descriptors = (0..=crate::MAX_DESCRIPTOR_COUNT)
        .map(|_| pipe_reader())
        .collect();
    assert!(Sender::new(stream, LeaseId::new(), descriptors).is_err());
}

#[test]
fn received_descriptors_are_opaque_owned_capabilities() {
    fn accepts_owned(_: &[OwnedFd]) {}

    let descriptor = pipe_reader();
    accepts_owned(std::slice::from_ref(&descriptor));
    assert!(descriptor.as_raw_fd() >= 0);
}

#[tokio::test]
async fn dropping_a_protocol_state_cancels_only_by_dropping_owned_descriptors() {
    let (stream, peer) = UnixStream::pair().expect("socket pair must be created");
    let (sender_reader, sender_writer) = pipe();
    let sender = Sender::new(stream, LeaseId::new(), vec![sender_writer]).expect("valid sender");
    drop(sender);
    drop(peer);
    assert_writer_closed(&sender_reader);

    let (receiver, peer, transfer_id) = ready_receiver(1, false).await;
    let (receiver_reader, receiver_writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &[receiver_writer.as_raw_fd()], false).await;
    drop(receiver_writer);
    let offered = receiver.receive().await.expect("valid offer is received");
    drop(offered);
    assert_writer_closed(&receiver_reader);
}

#[tokio::test]
async fn wrong_descriptor_count_fails_closed() {
    let (receiver, peer, transfer_id) = ready_receiver(2, false).await;
    let (reader, writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &[writer.as_raw_fd()], false).await;
    drop(writer);

    let error = receiver.receive().await.unwrap_err();
    assert!(matches!(
        error,
        HandoffError::DescriptorCountMismatch {
            expected: 2,
            received: 1
        }
    ));
    assert_writer_closed(&reader);
}

#[tokio::test]
async fn zero_descriptor_offer_is_rejected() {
    let (receiver, peer, transfer_id) = ready_receiver(1, false).await;
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &[], false).await;

    let error = receiver.receive().await.unwrap_err();
    assert!(matches!(
        error,
        HandoffError::RightsMessageCount { received: 0 }
    ));
}

#[tokio::test]
async fn excess_descriptors_fail_closed() {
    let (receiver, peer, transfer_id) = ready_receiver(1, false).await;
    let (first_reader, first_writer) = pipe();
    let (second_reader, second_writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(
        &peer,
        &frame,
        &[first_writer.as_raw_fd(), second_writer.as_raw_fd()],
        false,
    )
    .await;
    drop(first_writer);
    drop(second_writer);

    let error = receiver.receive().await.unwrap_err();
    assert!(matches!(
        error,
        HandoffError::DescriptorCountMismatch {
            expected: 1,
            received: 2
        }
    ));
    assert_writer_closed(&first_reader);
    assert_writer_closed(&second_reader);
}

#[tokio::test]
async fn descriptors_on_a_fragmented_frame_continuation_fail_closed() {
    let (receiver, peer, transfer_id) = ready_receiver(1, false).await;
    let (first_reader, first_writer) = pipe();
    let (second_reader, second_writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send_bytes(&peer, &frame[..1], &[first_writer.as_raw_fd()], false).await;
    let mut receiving = Box::pin(receiver.receive());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), receiving.as_mut())
            .await
            .is_err()
    );
    raw_send_bytes(&peer, &frame[1..], &[second_writer.as_raw_fd()], false).await;
    drop(first_writer);
    drop(second_writer);

    assert!(matches!(
        receiving.await,
        Err(HandoffError::RightsMessageCount { received: 2 })
    ));
    assert_writer_closed(&first_reader);
    assert_writer_closed(&second_reader);
}

#[tokio::test]
async fn malformed_offer_marker_and_transfer_mismatch_fail_closed() {
    let (receiver, peer, transfer_id) = ready_receiver(1, false).await;
    let (reader, writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(0xff, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &[writer.as_raw_fd()], false).await;
    drop(writer);
    assert!(matches!(
        receiver.receive().await.unwrap_err(),
        HandoffError::UnexpectedPhase { received: 0xff, .. }
    ));
    assert_writer_closed(&reader);

    let (receiver, peer, _) = ready_receiver(1, false).await;
    let (reader, writer) = pipe();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &LeaseId::new(), nonce.as_bytes());
    raw_send(&peer, &frame, &[writer.as_raw_fd()], false).await;
    drop(writer);
    assert!(matches!(
        receiver.receive().await.unwrap_err(),
        HandoffError::TransferMismatch
    ));
    assert_writer_closed(&reader);
}

#[tokio::test]
async fn offer_nonce_replay_is_rejected_at_commit() {
    let (receiver, mut peer, transfer_id) = ready_receiver(1, false).await;
    let (reader, writer) = pipe();
    let offer_nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, offer_nonce.as_bytes());
    raw_send(&peer, &frame, &[writer.as_raw_fd()], false).await;
    drop(writer);
    let receiver = receiver
        .receive()
        .await
        .expect("valid offer must be received")
        .accept()
        .await
        .expect("valid offer must be accepted");
    let mut accepted = [0_u8; FRAME_BYTES];
    peer.read_exact(&mut accepted)
        .await
        .expect("acceptance must be read");
    let receiver =
        receiver_follows_raw_coordinator(receiver, &mut peer, &transfer_id, offer_nonce.as_bytes())
            .await;

    let stale_nonce = LeaseId::new();
    let replay = crate::protocol_frame(COORDINATOR_COMMITTED, &transfer_id, stale_nonce.as_bytes());
    raw_send(&peer, &replay, &[], false).await;
    assert!(matches!(
        receiver.await_committed().await.unwrap_err(),
        HandoffError::NonceMismatch
    ));
    assert_writer_closed(&reader);
}

#[tokio::test]
async fn final_receipt_before_commit_is_rejected() {
    let (receiver, mut peer, transfer_id) = ready_receiver(1, false).await;
    let (_reader, writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &[writer.as_raw_fd()], false).await;
    let receiver = receiver
        .receive()
        .await
        .expect("valid offer must be received")
        .accept()
        .await
        .expect("valid offer must be accepted");
    let mut accepted = [0_u8; FRAME_BYTES];
    peer.read_exact(&mut accepted)
        .await
        .expect("acceptance must be read");
    let receiver =
        receiver_follows_raw_coordinator(receiver, &mut peer, &transfer_id, nonce.as_bytes()).await;

    let out_of_order =
        crate::protocol_frame(FOLLOWER_FINAL_RECEIPT, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &out_of_order, &[], false).await;
    assert!(matches!(
        receiver.await_committed().await.unwrap_err(),
        HandoffError::UnexpectedPhase {
            expected: COORDINATOR_COMMITTED,
            received: FOLLOWER_FINAL_RECEIPT
        }
    ));
}

#[tokio::test]
async fn unexpected_credential_control_message_is_rejected() {
    let (receiver, peer, transfer_id) = ready_receiver(1, true).await;
    let (_reader, writer) = pipe();
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &[writer.as_raw_fd()], true).await;

    assert!(matches!(
        receiver.receive().await.unwrap_err(),
        HandoffError::UnexpectedControl
    ));
}

#[tokio::test]
async fn oversized_ancillary_payload_reports_truncation_and_closes_installed_fds() {
    let (receiver, peer, transfer_id) = ready_receiver(crate::MAX_DESCRIPTOR_COUNT, true).await;
    let (reader, writer) = pipe();
    let repeated = vec![writer.as_raw_fd(); crate::MAX_DESCRIPTOR_COUNT];
    let nonce = LeaseId::new();
    let frame = crate::protocol_frame(DESCRIPTOR_OFFER, &transfer_id, nonce.as_bytes());
    raw_send(&peer, &frame, &repeated, true).await;
    drop(writer);

    assert!(matches!(
        receiver.receive().await.unwrap_err(),
        HandoffError::TruncatedControl
    ));
    assert_writer_closed(&reader);
}

#[test]
fn malformed_cmsg_length_is_detected_without_reading_a_payload() {
    let capacity = nix::cmsg_space!([i32; 1]).len();
    let mut control = vec![0_usize; capacity.div_ceil(std::mem::size_of::<usize>())];
    let actual_capacity = control.len() * std::mem::size_of::<usize>();
    // SAFETY: `control` is aligned for `cmsghdr` and contains a complete header.
    let header = unsafe { &mut *control.as_mut_ptr().cast::<nix::libc::cmsghdr>() };
    // SAFETY: a zero payload only asks libc for its platform header size.
    header.cmsg_len = unsafe { nix::libc::CMSG_LEN(0) as usize } - 1;
    header.cmsg_level = nix::libc::SOL_SOCKET;
    header.cmsg_type = nix::libc::SCM_RIGHTS;
    // SAFETY: zero initialization is a valid empty `msghdr` starting point.
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = actual_capacity;

    let parsed =
        crate::parse_control_messages(&message, control.as_ptr() as usize, actual_capacity);
    assert!(parsed.malformed_control);
    assert!(parsed.descriptors.is_empty());
}

#[test]
fn malformed_control_failure_drops_descriptors_already_installed_by_the_kernel() {
    let (reader, writer) = pipe();
    let received = crate::ReceivedFrame {
        frame: [0_u8; FRAME_BYTES],
        flags: MsgFlags::empty(),
        rights_messages: 1,
        unexpected_control: false,
        malformed_control: true,
        descriptors: vec![writer],
    };
    assert!(matches!(
        crate::validate_offer_control(&received, DescriptorCount::new(1).expect("valid count")),
        Err(HandoffError::MalformedControl)
    ));
    drop(received);
    assert_writer_closed(&reader);
}
