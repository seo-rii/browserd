#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs::File;
use std::io::IoSlice;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;

use browserd_launch_gate::{configure_scratch_receiver, receive_scratch_offer, send_scratch_offer};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use nix::sys::stat::fstat;

#[test]
fn scratch_offer_preserves_exact_inode_and_sets_close_on_exec() {
    let directory = tempfile::tempdir().unwrap();
    let original = File::open(directory.path()).unwrap();
    let (receiver, sender) = UnixStream::pair().unwrap();
    configure_scratch_receiver(receiver.as_fd()).unwrap();
    send_scratch_offer(sender.as_fd(), original.as_fd()).unwrap();
    let received = receive_scratch_offer(
        receiver.as_fd(),
        std::process::id(),
        nix::unistd::getuid().as_raw(),
    )
    .unwrap();
    let before = fstat(&original).unwrap();
    let after = fstat(&received).unwrap();
    assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
    assert!(
        FdFlag::from_bits_truncate(fcntl(&received, FcntlArg::F_GETFD).unwrap())
            .contains(FdFlag::FD_CLOEXEC)
    );
}

#[test]
fn scratch_offer_rejects_a_different_sender_pid() {
    let file = File::open("/dev/null").unwrap();
    let (receiver, sender) = UnixStream::pair().unwrap();
    configure_scratch_receiver(receiver.as_fd()).unwrap();
    send_scratch_offer(sender.as_fd(), file.as_fd()).unwrap();
    assert!(
        receive_scratch_offer(
            receiver.as_fd(),
            std::process::id().saturating_add(1),
            nix::unistd::getuid().as_raw()
        )
        .is_err()
    );
}

#[test]
fn scratch_offer_rejects_multiple_descriptors_and_wrong_marker() {
    for (marker, count) in [(b'S', 2usize), (b'X', 1usize)] {
        let file = File::open("/dev/null").unwrap();
        let (receiver, sender) = UnixStream::pair().unwrap();
        configure_scratch_receiver(receiver.as_fd()).unwrap();
        let descriptors = vec![file.as_raw_fd(); count];
        let payload = [marker];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&payload)],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(
            receive_scratch_offer(
                receiver.as_fd(),
                std::process::id(),
                nix::unistd::getuid().as_raw()
            )
            .is_err()
        );
    }
}

#[test]
fn scratch_offer_requires_kernel_sender_credentials() {
    let file = File::open("/dev/null").unwrap();
    let (receiver, sender) = UnixStream::pair().unwrap();
    send_scratch_offer(sender.as_fd(), file.as_fd()).unwrap();
    assert!(
        receive_scratch_offer(
            receiver.as_fd(),
            std::process::id(),
            nix::unistd::getuid().as_raw()
        )
        .is_err()
    );
}

#[test]
fn scratch_offer_rejects_wrong_uid_and_seqpacket_trailing_bytes() {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
    use std::os::fd::OwnedFd;
    let file = File::open("/dev/null").unwrap();
    for wrong_uid in [true, false] {
        let (receiver, sender): (OwnedFd, OwnedFd) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        configure_scratch_receiver(receiver.as_fd()).unwrap();
        let descriptors = [file.as_raw_fd()];
        let payload: &[u8] = if wrong_uid { b"S" } else { b"SX" };
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(payload)],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        let expected_uid = nix::unistd::getuid()
            .as_raw()
            .wrapping_add(u32::from(wrong_uid));
        assert!(receive_scratch_offer(receiver.as_fd(), std::process::id(), expected_uid).is_err());
    }
}
