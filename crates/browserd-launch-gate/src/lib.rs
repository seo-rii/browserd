//! Shared launch-approval protocol for the fail-closed Chromium exec gate.

use std::io::IoSlice;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;

use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg, setsockopt, sockopt};

/// The complete one-shot frame required before the launch gate may execute Chromium.
pub const APPROVAL_FRAME: &[u8] = b"browserd-launch-gate/v1 approve\n";

pub const SANDBOX_SCRATCH_PATH: &str = "/profile/browserd-files";
pub const SANDBOX_SCRATCH_MAX_BYTES: u64 = 32 * 1024 * 1024;
const SCRATCH_OFFER: u8 = b'S';

/// Enables kernel-authenticated sender credentials before the held child can send its offer.
pub fn configure_scratch_receiver(socket: BorrowedFd<'_>) -> io::Result<()> {
    setsockopt(&socket, sockopt::PassCred, &true).map_err(io::Error::from)
}

/// Sends one directory capability while the launch helper is still behind the approval gate.
/// The receiver independently verifies both the sending process and the filesystem capability.
pub fn send_scratch_offer(socket: BorrowedFd<'_>, directory: BorrowedFd<'_>) -> io::Result<()> {
    let marker = [SCRATCH_OFFER];
    let descriptors = [directory.as_raw_fd()];
    let written = sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(&marker)],
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(io::Error::from)?;
    if written != 1 {
        return Err(io::Error::other("incomplete scratch capability offer"));
    }
    Ok(())
}

/// Receives exactly one offered descriptor from the expected held process. Nonblocking: callers
/// provide their own absolute deadline. Every installed descriptor is closed on protocol failure.
pub fn receive_scratch_offer(
    socket: BorrowedFd<'_>,
    expected_pid: u32,
    expected_uid: u32,
) -> io::Result<OwnedFd> {
    let (directory, sender_pid) = receive_authenticated_scratch_offer(socket, expected_uid)?;
    if sender_pid != expected_pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "scratch capability sender PID mismatch",
        ));
    }
    Ok(directory)
}

/// A pinned gate process, distinct from bubblewrap's namespace PID 1 reaper. The caller must
/// retain its independently pinned reaper identity and this guard until approval is written.
#[derive(Debug)]
pub struct ScratchSender {
    pid: u32,
    parent_pid: u32,
    identity: (u32, u64),
    parent_identity: (u32, u64),
    namespaces: [(u64, u64); 3],
    pidfd: OwnedFd,
}

impl ScratchSender {
    /// Rechecks the exact live sender immediately before the one-shot execution approval.
    pub fn is_held(&self) -> io::Result<bool> {
        let mut descriptor = nix::libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is initialized and writable; timeout zero never blocks.
        let ready = unsafe { nix::libc::poll(&raw mut descriptor, 1, 0) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready != 0 || descriptor.revents != 0 {
            return Ok(false);
        }
        Ok(process_identity(self.pid)? == Some(self.identity)
            && process_identity(self.parent_pid)? == Some(self.parent_identity)
            && process_namespaces(self.pid)? == self.namespaces
            && process_namespaces(self.parent_pid)? == self.namespaces)
    }
}

/// Authenticates the direct child of bubblewrap's pinned namespace reaper. `--info-fd`
/// identifies that reaper, while SCM_CREDENTIALS identifies the subsequently forked gate.
/// A sibling, arbitrary descendant, exited sender, or changed namespace fails closed.
pub fn receive_scratch_offer_from_child(
    socket: BorrowedFd<'_>,
    expected_parent_pid: u32,
    expected_uid: u32,
) -> io::Result<(OwnedFd, ScratchSender)> {
    let (directory, pid) = receive_authenticated_scratch_offer(socket, expected_uid)?;
    let identity = process_identity(pid)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "scratch sender already exited")
    })?;
    if identity.0 != expected_parent_pid || pid == expected_parent_pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "scratch sender is not the direct child of the pinned reaper",
        ));
    }
    let parent_identity = process_identity(expected_parent_pid)?.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "scratch reaper already exited")
    })?;
    // SAFETY: pidfd_open takes only a validated positive PID and flags zero. The returned
    // descriptor is owned here and the kernel creates it with FD_CLOEXEC.
    let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pidfd_open returned one new owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as RawFd) };
    let sender = ScratchSender {
        pid,
        parent_pid: expected_parent_pid,
        identity,
        parent_identity,
        namespaces: process_namespaces(expected_parent_pid)?,
        pidfd,
    };
    if !sender.is_held()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "scratch sender identity changed while pinning capability",
        ));
    }
    Ok((directory, sender))
}

fn process_identity(pid: u32) -> io::Result<Option<(u32, u64)>> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid scratch process identity",
        )
    };
    let mut fields = stat
        .rsplit_once(") ")
        .ok_or_else(invalid)?
        .1
        .split_whitespace();
    let parent = fields
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    let start = fields
        .nth(17)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    if start == 0 {
        return Err(invalid());
    }
    Ok(Some((parent, start)))
}

fn process_namespaces(pid: u32) -> io::Result<[(u64, u64); 3]> {
    let mut identities = [(0, 0); 3];
    for (index, name) in ["pid", "mnt", "net"].into_iter().enumerate() {
        let namespace = std::fs::metadata(format!("/proc/{pid}/ns/{name}"))?;
        identities[index] = (namespace.dev(), namespace.ino());
    }
    Ok(identities)
}

fn receive_authenticated_scratch_offer(
    socket: BorrowedFd<'_>,
    expected_uid: u32,
) -> io::Result<(OwnedFd, u32)> {
    let control_capacity = nix::cmsg_space!([RawFd; 253], nix::libc::ucred).len();
    let mut control = vec![0usize; control_capacity.div_ceil(std::mem::size_of::<usize>())];
    let mut marker = [0u8; 1];
    let mut vector = nix::libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: zeroed msghdr has null/zero unused members; all active buffers stay alive below.
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_capacity;
    // SAFETY: message and its initialized writable buffers remain valid throughout recvmsg.
    let received = unsafe {
        nix::libc::recvmsg(
            socket.as_raw_fd(),
            &raw mut message,
            nix::libc::MSG_DONTWAIT | nix::libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut invalid = received != 1
        || marker[0] != SCRATCH_OFFER
        || message.msg_flags & (nix::libc::MSG_CTRUNC | nix::libc::MSG_TRUNC) != 0;
    let start = control.as_ptr() as usize;
    let end = start.saturating_add(message.msg_controllen.min(control_capacity));
    let mut descriptors: Vec<OwnedFd> = Vec::new();
    let mut rights_count = 0usize;
    let mut credentials_count = 0usize;
    let mut sender_pid = None;
    // SAFETY: the kernel initialized the bounded control buffer described by message.
    let mut current = unsafe { nix::libc::CMSG_FIRSTHDR(&message) };
    while !current.is_null() {
        let address = current as usize;
        if address < start
            || address.saturating_add(std::mem::size_of::<nix::libc::cmsghdr>()) > end
        {
            invalid = true;
            break;
        }
        // SAFETY: the full header lies inside the returned control buffer.
        let header = unsafe { &*current };
        // SAFETY: this asks libc for the platform's ancillary header size only.
        let minimum = unsafe { nix::libc::CMSG_LEN(0) as usize };
        if header.cmsg_len < minimum || header.cmsg_len > end.saturating_sub(address) {
            invalid = true;
            break;
        }
        let length = header.cmsg_len - minimum;
        if header.cmsg_level == nix::libc::SOL_SOCKET && header.cmsg_type == nix::libc::SCM_RIGHTS {
            rights_count += 1;
            invalid |= !length.is_multiple_of(std::mem::size_of::<RawFd>());
            // SAFETY: the complete payload was bounds checked; descriptor reads are unaligned.
            let data = unsafe { nix::libc::CMSG_DATA(current) }.cast::<RawFd>();
            for index in 0..length / std::mem::size_of::<RawFd>() {
                // SAFETY: this index lies in the bounds-checked descriptor payload.
                let raw = unsafe { data.add(index).read_unaligned() };
                if raw < 0 || descriptors.iter().any(|fd| fd.as_raw_fd() == raw) {
                    invalid = true;
                } else {
                    // SAFETY: recvmsg installed this new owned descriptor exactly once.
                    descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        } else if header.cmsg_level == nix::libc::SOL_SOCKET
            && header.cmsg_type == nix::libc::SCM_CREDENTIALS
        {
            credentials_count += 1;
            if length != std::mem::size_of::<nix::libc::ucred>() {
                invalid = true;
            } else {
                // SAFETY: the ucred payload is exactly sized and entirely within the buffer.
                let credentials = unsafe {
                    nix::libc::CMSG_DATA(current)
                        .cast::<nix::libc::ucred>()
                        .read_unaligned()
                };
                sender_pid = u32::try_from(credentials.pid).ok().filter(|pid| *pid != 0);
                invalid |= sender_pid.is_none() || credentials.uid != expected_uid;
            }
        } else {
            invalid = true;
        }
        // SAFETY: libc validates the next header's alignment and remaining bounds.
        let next = unsafe { nix::libc::CMSG_NXTHDR(&message, current) };
        if next == current {
            invalid = true;
            break;
        }
        current = next;
    }
    if invalid || rights_count != 1 || credentials_count != 1 || descriptors.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid scratch capability offer",
        ));
    }
    let directory = descriptors
        .pop()
        .ok_or_else(|| io::Error::other("missing scratch capability"))?;
    let sender_pid = sender_pid.ok_or_else(|| io::Error::other("missing scratch sender"))?;
    Ok((directory, sender_pid))
}

/// Accepts exactly one complete approval frame followed immediately by EOF.
///
/// EOF before the complete frame, a mismatched byte, and any trailing byte all fail closed.
pub fn validate_approval(reader: &mut impl Read) -> io::Result<()> {
    let mut received = [0_u8; APPROVAL_FRAME.len()];
    reader.read_exact(&mut received)?;
    if received != APPROVAL_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid launch approval frame",
        ));
    }

    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing launch approval data",
        ));
    }
    Ok(())
}
