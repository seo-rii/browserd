#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use browserd_launch_gate::{
    APPROVAL_FRAME, SANDBOX_SCRATCH_MAX_BYTES, SANDBOX_SCRATCH_PATH, configure_scratch_receiver,
    receive_scratch_offer_from_child,
};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires bubblewrap user/mount/PID namespaces; proves the real launch helper handoff"]
fn gate_exports_exact_bounded_mount_before_approval_then_executes() {
    let (child_control, parent_control) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    configure_scratch_receiver(parent_control.as_fd()).unwrap();
    let (info_read, info_write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
    fcntl(&info_read, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
    let info_fd = info_write.as_raw_fd();
    let mut command = Command::new("/usr/bin/bwrap");
    command
        .args([
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--tmpfs",
            "/",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--dir",
            "/profile",
            "--perms",
            "0700",
            "--size",
        ])
        .arg(SANDBOX_SCRATCH_MAX_BYTES.to_string())
        .arg("--tmpfs")
        .arg(SANDBOX_SCRATCH_PATH)
        .arg("--ro-bind")
        .arg(env!("CARGO_BIN_EXE_browserd-launch-gate"))
        .arg("/gate")
        .arg("--info-fd")
        .arg(info_fd.to_string())
        .args(["--", "/gate", "--export-scratch", "--", "/usr/bin/true"])
        .stdin(Stdio::from(child_control))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: after fork this only clears CLOEXEC on the explicitly owned info descriptor.
    unsafe {
        command.pre_exec(move || {
            let flags = nix::libc::fcntl(info_fd, nix::libc::F_GETFD);
            if flags < 0
                || nix::libc::fcntl(info_fd, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ChildGuard(command.spawn().unwrap());
    drop(info_write);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut info = std::fs::File::from(info_read);
    let mut info_bytes = Vec::new();
    let pid = loop {
        let mut bytes = [0u8; 512];
        match info.read(&mut bytes) {
            Ok(0) => {
                let value: serde_json::Value = serde_json::from_slice(&info_bytes).unwrap();
                break Ok(u32::try_from(value["child-pid"].as_u64().unwrap()).unwrap());
            }
            Ok(count) => {
                info_bytes.extend_from_slice(&bytes[..count]);
                assert!(info_bytes.len() < 16384);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "bubblewrap identity must arrive before deadline"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => break Err(error),
        }
    }
    .expect("bubblewrap identity read failed");
    // --info-fd identifies bubblewrap's PID 1 reaper. The gate is its exact direct child,
    // whose kernel credential PID must be pinned independently before approving execution.
    let (scratch, sender): (OwnedFd, _) = loop {
        match receive_scratch_offer_from_child(
            parent_control.as_fd(),
            pid,
            nix::unistd::geteuid().as_raw(),
        ) {
            Ok(offer) => break Ok(offer),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "gate offer must arrive before deadline"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => break Err(error),
        }
    }
    .expect("gate offer rejected");
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "target must remain held without approval"
    );
    let stat = nix::sys::stat::fstat(&scratch).unwrap();
    assert_eq!(stat.st_mode & 0o7777, 0o700);
    assert_eq!(stat.st_uid, nix::unistd::geteuid().as_raw());
    assert_eq!(
        nix::sys::statfs::fstatfs(&scratch)
            .unwrap()
            .filesystem_type()
            .0,
        nix::libc::TMPFS_MAGIC
    );
    let limits = nix::sys::statvfs::fstatvfs(&scratch).unwrap();
    assert_eq!(
        limits.blocks() * limits.fragment_size(),
        SANDBOX_SCRATCH_MAX_BYTES
    );
    assert!(sender.is_held().unwrap());
    assert_eq!(
        nix::unistd::write(&parent_control, APPROVAL_FRAME).unwrap(),
        APPROVAL_FRAME.len()
    );
    drop(parent_control);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "approved target must exit before deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
