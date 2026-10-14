#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::os::fd::AsFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use browserd_launch_gate::{
    configure_scratch_receiver, receive_scratch_offer_from_child, send_scratch_offer,
};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn scratch_offer_direct_child_helper() {
    if std::env::var_os("BROWSERD_SCRATCH_CHILD_HELPER").is_none() {
        return;
    }
    let directory = std::fs::File::open("/tmp").unwrap();
    send_scratch_offer(std::io::stdin().as_fd(), directory.as_fd()).unwrap();
    let mut approval = [0u8; 1];
    std::io::stdin().read_exact(&mut approval).unwrap();
}

#[test]
fn scratch_sender_pins_only_the_direct_child_until_approval() {
    for wrong_parent in [false, true] {
        let (parent, child) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        configure_scratch_receiver(parent.as_fd()).unwrap();
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "scratch_offer_direct_child_helper",
                    "--nocapture",
                ])
                .env("BROWSERD_SCRATCH_CHILD_HELPER", "1")
                .stdin(Stdio::from(child))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        let expected_parent = if wrong_parent {
            child.0.id()
        } else {
            std::process::id()
        };
        let result = loop {
            match receive_scratch_offer_from_child(
                parent.as_fd(),
                expected_parent,
                nix::unistd::geteuid().as_raw(),
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "child offer deadline");
                    std::thread::sleep(Duration::from_millis(5));
                }
                result => break result,
            }
        };
        if wrong_parent {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        } else {
            let (_directory, sender) = result.unwrap();
            assert!(sender.is_held().unwrap());
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(
                !sender.is_held().unwrap(),
                "an exited sender cannot be approved"
            );
        }
    }
}
