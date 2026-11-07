//! Private, one-shot exec helper for NET namespaces owned by a descendant USER namespace.
//! The daemon never enters a namespace or acquires capabilities. Only its exact executable,
//! an authenticated Unix socket and two already pinned namespace capabilities reach the child.

use std::fs::File;
use std::io::{self, IoSlice, Read};
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sched::{CloneFlags, setns};
use nix::sys::prctl::{get_no_new_privs, set_no_new_privs};
use nix::sys::socket::{
    AddressFamily, ControlMessage, GetSockOpt, MsgFlags, SetSockOpt, SockFlag, SockType, sendmsg,
    socketpair, sockopt,
};
use nix::sys::stat::fstat;
use serde::{Deserialize, Serialize};

use crate::netns_listener::{adopt_native_listener, bind_listener_in_observed_namespace};
use crate::{
    DedicatedEgressListener, DedicatedEgressListenerError, NetworkNamespaceIdentity,
    PinnedNetworkNamespace,
};

const HELPER_ARGUMENT: &str = "--browserd-private-netns-listener-v1";
const MAX_RECEIPT_BYTES: usize = 4096;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivilegeState {
    uids: [u32; 4],
    gids: [u32; 4],
    capabilities: [u64; 5],
    no_new_privs: bool,
    user_namespace: (u64, u64),
    network_namespace: (u64, u64),
}

fn namespace_identity(name: &str) -> io::Result<(u64, u64)> {
    let metadata = std::fs::metadata(format!("/proc/thread-self/ns/{name}"))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn privilege_state() -> io::Result<PrivilegeState> {
    let mut contents = String::new();
    File::open("/proc/thread-self/status")?
        .take(8193)
        .read_to_string(&mut contents)?;
    if contents.len() > 8192 {
        return Err(io::Error::other("oversized process status"));
    }
    let field = |name: &str| -> io::Result<&str> {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| io::Error::other("missing process status field"))
    };
    let ids = |name: &str| -> io::Result<[u32; 4]> {
        let parsed = field(name)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;
        parsed
            .try_into()
            .map_err(|_| io::Error::other("invalid process identities"))
    };
    let mut capabilities = [0; 5];
    for (index, name) in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .into_iter()
        .enumerate()
    {
        capabilities[index] =
            u64::from_str_radix(field(name)?.trim(), 16).map_err(io::Error::other)?;
    }
    Ok(PrivilegeState {
        uids: ids("Uid:")?,
        gids: ids("Gid:")?,
        capabilities,
        no_new_privs: get_no_new_privs().map_err(io::Error::from)?,
        user_namespace: namespace_identity("user")?,
        network_namespace: namespace_identity("net")?,
    })
}

fn unprivileged(state: &PrivilegeState) -> bool {
    state
        .uids
        .iter()
        .all(|uid| *uid != 0 && *uid == state.uids[0])
        && [0, 1, 2, 4]
            .into_iter()
            .all(|index| state.capabilities[index] == 0)
        && state.no_new_privs
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HelperStage {
    Input,
    OwnerUserNamespace,
    EnterUserNamespace,
    EnterNetworkNamespace,
    Loopback,
    DropPrivileges,
    BindListener,
    Receipt,
}

impl HelperStage {
    const fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::OwnerUserNamespace => "owner_user_namespace",
            Self::EnterUserNamespace => "enter_user_namespace",
            Self::EnterNetworkNamespace => "enter_network_namespace",
            Self::Loopback => "loopback",
            Self::DropPrivileges => "drop_privileges",
            Self::BindListener => "bind_listener",
            Self::Receipt => "receipt",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelperFailure {
    stage: HelperStage,
    errno: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelperProof {
    namespace: NetworkNamespaceIdentity,
    user_namespace: (u64, u64),
    owner_uid: u32,
    initial_uid: u32,
    executable: (u64, u64),
    state: PrivilegeState,
    address: SocketAddr,
    listener_identity: (u64, u64),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelperResponse {
    version: u32,
    proof: Option<HelperProof>,
    failure: Option<HelperFailure>,
}

fn failure(stage: HelperStage, error: io::Error) -> HelperFailure {
    HelperFailure {
        stage,
        errno: error.raw_os_error(),
    }
}

fn public_error(stage: HelperStage, errno: Option<i32>) -> DedicatedEgressListenerError {
    DedicatedEgressListenerError::NativeHelper(format!(
        "stage={} errno={}",
        stage.name(),
        errno.map_or_else(|| "none".into(), |value| value.to_string())
    ))
}

fn validate_owner(
    namespace: &PinnedNetworkNamespace,
    owner: &OwnedFd,
    initial: &PrivilegeState,
) -> io::Result<u32> {
    // SAFETY: both ioctls query still-owned namespace descriptors. OWNER_UID writes one uid_t.
    let namespace_type = unsafe { nix::libc::ioctl(owner.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
    if namespace_type != nix::libc::CLONE_NEWUSER {
        return Err(if namespace_type < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other("wrong owner namespace type")
        });
    }
    let derived = namespace
        .owning_user_namespace()
        .map_err(io::Error::other)?;
    let supplied = fstat(owner).map_err(io::Error::from)?;
    let expected = fstat(&derived).map_err(io::Error::from)?;
    if (supplied.st_dev, supplied.st_ino) != (expected.st_dev, expected.st_ino)
        || (supplied.st_dev, supplied.st_ino) == initial.user_namespace
        || (namespace.identity().device(), namespace.identity().inode())
            == initial.network_namespace
    {
        return Err(io::Error::other(
            "namespace is not its pinned descendant owner",
        ));
    }
    let mut owner_uid: nix::libc::uid_t = 0;
    // SAFETY: owner is a USER namespace, and owner_uid is a correctly sized writable uid_t.
    if unsafe {
        nix::libc::ioctl(
            owner.as_raw_fd(),
            nix::libc::NS_GET_OWNER_UID,
            &raw mut owner_uid,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if owner_uid != initial.uids[0] || !unprivileged(initial) {
        return Err(io::Error::from_raw_os_error(nix::libc::EPERM));
    }
    Ok(owner_uid)
}

fn executable_identity() -> io::Result<(u64, u64)> {
    let metadata = File::open("/proc/self/exe")?.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Construct an exact listener with the currently running daemon's own trusted executable.
/// There is no executable, namespace-path or address override. The caller must already have
/// no_new_privs and zero effective, permitted, inheritable and ambient capabilities.
pub fn create_native_dedicated_egress_listener(
    namespace: &PinnedNetworkNamespace,
) -> Result<DedicatedEgressListener, DedicatedEgressListenerError> {
    let initial = privilege_state()
        .map_err(|error| public_error(HelperStage::Input, error.raw_os_error()))?;
    let owner = namespace
        .owning_user_namespace()
        .map_err(|_| public_error(HelperStage::OwnerUserNamespace, None))?;
    let owner_uid = validate_owner(namespace, &owner, &initial)
        .map_err(|error| public_error(HelperStage::OwnerUserNamespace, error.raw_os_error()))?;
    let executable = File::open("/proc/self/exe")
        .map_err(|error| public_error(HelperStage::Input, error.raw_os_error()))?;
    let metadata = executable
        .metadata()
        .map_err(|error| public_error(HelperStage::Input, error.raw_os_error()))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o6022 != 0 {
        return Err(public_error(HelperStage::Input, None));
    }
    let expected_executable = (metadata.dev(), metadata.ino());
    let (channel, child_channel) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )
    .map_err(|error| public_error(HelperStage::Input, Some(error as i32)))?;
    sockopt::PassCred
        .set(&channel, &true)
        .map_err(|error| public_error(HelperStage::Input, Some(error as i32)))?;
    let net = namespace
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| public_error(HelperStage::Input, error.raw_os_error()))?;
    let inherited = [owner.as_raw_fd(), net.as_raw_fd()];
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(HELPER_ARGUMENT)
        .arg(inherited[0].to_string())
        .arg(inherited[1].to_string())
        .env_clear()
        .stdin(Stdio::from(child_channel))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: this child-only pre_exec uses only async-signal-safe syscalls and captured integers.
    // Marking all non-stdio FDs CLOEXEC prevents unrelated daemon capabilities reaching the helper.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::syscall(
                nix::libc::SYS_close_range,
                3u32,
                u32::MAX,
                nix::libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            for raw in inherited {
                let flags = nix::libc::fcntl(raw, nix::libc::F_GETFD);
                if flags < 0
                    || nix::libc::fcntl(raw, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| public_error(HelperStage::Input, error.raw_os_error()))?;
    drop(command);
    let deadline = Instant::now() + HELPER_TIMEOUT;
    let response = receive_response(&channel, child.id(), initial.uids[0], deadline);
    let status = reap_child(child, deadline);
    // Parent credentials, NNP and both namespaces must remain exact even on helper failure.
    let unchanged = privilege_state()
        .map(|observed| observed == initial)
        .unwrap_or(false);
    if !unchanged {
        return Err(public_error(HelperStage::Receipt, None));
    }
    let (response, mut descriptors) = response?;
    let status = status?;
    if response.version != 1 {
        return Err(public_error(HelperStage::Receipt, None));
    }
    if let Some(error) = response.failure {
        if response.proof.is_some() || !descriptors.is_empty() {
            return Err(public_error(HelperStage::Receipt, None));
        }
        return Err(public_error(error.stage, error.errno));
    }
    let proof = response
        .proof
        .ok_or_else(|| public_error(HelperStage::Receipt, None))?;
    if !status.success()
        || descriptors.len() != 1
        || proof.namespace != namespace.identity()
        || proof.owner_uid != owner_uid
        || proof.initial_uid != initial.uids[0]
        || proof.executable != expected_executable
        || proof.user_namespace
            != (
                fstat(&owner)
                    .map_err(|_| public_error(HelperStage::Receipt, None))?
                    .st_dev,
                fstat(&owner)
                    .map_err(|_| public_error(HelperStage::Receipt, None))?
                    .st_ino,
            )
        || proof.state.user_namespace != proof.user_namespace
        || proof.state.network_namespace
            != (namespace.identity().device(), namespace.identity().inode())
        || proof.state.capabilities != [0; 5]
        || !proof.state.no_new_privs
        || proof
            .state
            .uids
            .iter()
            .any(|uid| *uid != proof.state.uids[0])
    {
        return Err(public_error(HelperStage::Receipt, None));
    }
    let descriptor = descriptors
        .pop()
        .ok_or_else(|| public_error(HelperStage::Receipt, None))?;
    let metadata = fstat(&descriptor).map_err(|_| public_error(HelperStage::Receipt, None))?;
    if (metadata.st_dev, metadata.st_ino) != proof.listener_identity {
        return Err(public_error(HelperStage::Receipt, None));
    }
    adopt_native_listener(descriptor, proof.address, proof.namespace)
}

struct HelperProcess(Option<Child>);

impl Drop for HelperProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            // Keep ownership of the exact Child until wait completes if the kernel delays reap.
            // The request deadline never blocks on this exceptional cleanup thread.
            let _ = thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}

fn reap_child(
    child: Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, DedicatedEgressListenerError> {
    let mut owned = HelperProcess(Some(child));
    loop {
        let child = owned
            .0
            .as_mut()
            .ok_or_else(|| public_error(HelperStage::Receipt, None))?;
        if let Some(status) = child
            .try_wait()
            .map_err(|error| public_error(HelperStage::Receipt, error.raw_os_error()))?
        {
            let _ = owned.0.take();
            return Ok(status);
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = owned
        .0
        .as_mut()
        .ok_or_else(|| public_error(HelperStage::Receipt, None))?
        .kill();
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        let child = owned
            .0
            .as_mut()
            .ok_or_else(|| public_error(HelperStage::Receipt, None))?;
        if child
            .try_wait()
            .map_err(|error| public_error(HelperStage::Receipt, error.raw_os_error()))?
            .is_some()
        {
            let _ = owned.0.take();
            return Err(public_error(
                HelperStage::Receipt,
                Some(nix::libc::ETIMEDOUT),
            ));
        }
        if Instant::now() >= deadline {
            return Err(public_error(
                HelperStage::Receipt,
                Some(nix::libc::ETIMEDOUT),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn receive_response(
    channel: &OwnedFd,
    expected_pid: u32,
    expected_uid: u32,
    deadline: Instant,
) -> Result<(HelperResponse, Vec<OwnedFd>), DedicatedEgressListenerError> {
    loop {
        let mut poll = nix::libc::pollfd {
            fd: channel.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll references exactly one valid descriptor and stack-owned pollfd.
        let ready = unsafe { nix::libc::poll(&raw mut poll, 1, 10) };
        if ready < 0 && io::Error::last_os_error().raw_os_error() != Some(nix::libc::EINTR) {
            return Err(public_error(
                HelperStage::Receipt,
                io::Error::last_os_error().raw_os_error(),
            ));
        }
        if ready > 0 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(public_error(
                HelperStage::Receipt,
                Some(nix::libc::ETIMEDOUT),
            ));
        }
    }
    let capacity = nix::cmsg_space!([RawFd; 253], nix::libc::ucred).len();
    let mut control = vec![0usize; capacity.div_ceil(std::mem::size_of::<usize>())];
    let mut bytes = [0u8; MAX_RECEIPT_BYTES];
    let mut vector = nix::libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: a zeroed msghdr has valid null inactive fields. Active buffers are initialized below.
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = capacity;
    // SAFETY: all writable buffers remain live, aligned and correctly sized for this recvmsg.
    let received = unsafe {
        nix::libc::recvmsg(
            channel.as_raw_fd(),
            &raw mut message,
            nix::libc::MSG_DONTWAIT | nix::libc::MSG_CMSG_CLOEXEC,
        )
    };
    if received < 0 {
        return Err(public_error(
            HelperStage::Receipt,
            io::Error::last_os_error().raw_os_error(),
        ));
    }
    let mut invalid =
        received == 0 || message.msg_flags & (nix::libc::MSG_CTRUNC | nix::libc::MSG_TRUNC) != 0;
    let start = control.as_ptr() as usize;
    let end = start.saturating_add(message.msg_controllen.min(capacity));
    let mut descriptors: Vec<OwnedFd> = Vec::new();
    let mut credentials_count = 0;
    let mut rights_count = 0;
    // SAFETY: the kernel initialized this bounded ancillary buffer.
    let mut current = unsafe { nix::libc::CMSG_FIRSTHDR(&message) };
    while !current.is_null() {
        let address = current as usize;
        if address < start
            || address.saturating_add(std::mem::size_of::<nix::libc::cmsghdr>()) > end
        {
            invalid = true;
            break;
        }
        // SAFETY: the complete header lies in the kernel-returned control buffer.
        let header = unsafe { &*current };
        // SAFETY: CMSG_LEN only computes the native header size.
        let minimum = unsafe { nix::libc::CMSG_LEN(0) as usize };
        if header.cmsg_len < minimum || header.cmsg_len > end.saturating_sub(address) {
            invalid = true;
            break;
        }
        let length = header.cmsg_len - minimum;
        if header.cmsg_level == nix::libc::SOL_SOCKET && header.cmsg_type == nix::libc::SCM_RIGHTS {
            rights_count += 1;
            invalid |= !length.is_multiple_of(std::mem::size_of::<RawFd>());
            // SAFETY: the descriptor array lies entirely in the bounds-checked payload.
            let data = unsafe { nix::libc::CMSG_DATA(current) }.cast::<RawFd>();
            for index in 0..length / std::mem::size_of::<RawFd>() {
                // SAFETY: the payload bounds cover each unaligned descriptor read.
                let raw = unsafe { data.add(index).read_unaligned() };
                if raw < 0 || descriptors.iter().any(|fd| fd.as_raw_fd() == raw) {
                    invalid = true;
                } else {
                    // SAFETY: recvmsg installed each received descriptor exactly once.
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
                // SAFETY: this correctly sized ucred payload lies inside the control buffer.
                let credentials = unsafe {
                    nix::libc::CMSG_DATA(current)
                        .cast::<nix::libc::ucred>()
                        .read_unaligned()
                };
                invalid |= u32::try_from(credentials.pid).ok() != Some(expected_pid)
                    || credentials.uid != expected_uid;
            }
        } else {
            invalid = true;
        }
        // SAFETY: libc bounds-checks the next native-aligned header against this msghdr.
        let next = unsafe { nix::libc::CMSG_NXTHDR(&message, current) };
        if next == current {
            invalid = true;
            break;
        }
        current = next;
    }
    if invalid || credentials_count != 1 || rights_count > 1 {
        return Err(public_error(HelperStage::Receipt, None));
    }
    let count = usize::try_from(received).map_err(|_| public_error(HelperStage::Receipt, None))?;
    let response = serde_json::from_slice(&bytes[..count])
        .map_err(|_| public_error(HelperStage::Receipt, None))?;
    Ok((response, descriptors))
}

fn loopback_up() -> io::Result<()> {
    let socket = nix::sys::socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    // SAFETY: zeroed ifreq initializes its union; the NUL-terminated interface name is fixed.
    let mut request: nix::libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as nix::libc::c_char;
    request.ifr_name[1] = b'o' as nix::libc::c_char;
    // SAFETY: SIOCGIFFLAGS writes a correctly sized ifreq on the private NET socket.
    if unsafe {
        nix::libc::ioctl(
            socket.as_raw_fd(),
            nix::libc::SIOCGIFFLAGS,
            &raw mut request,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: SIOCGIFFLAGS initialized this union member; only IFF_UP is added to existing flags.
    unsafe {
        request.ifr_ifru.ifru_flags |= nix::libc::IFF_UP as nix::libc::c_short;
    }
    // SAFETY: this ioctl changes only the fixed lo interface of the already verified private NET.
    if unsafe {
        nix::libc::ioctl(
            socket.as_raw_fd(),
            nix::libc::SIOCSIFFLAGS,
            &raw mut request,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drop_privileges() -> io::Result<()> {
    // Linux UAPI linux/capability.h _LINUX_CAPABILITY_VERSION_3 and its two u32 capability words.
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    for capability in 0..64 {
        // SAFETY: prctl takes only integer arguments and drops capabilities in this USER namespace.
        if unsafe { nix::libc::prctl(nix::libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(nix::libc::EINVAL) {
                break;
            }
            return Err(error);
        }
    }
    // SAFETY: clear ambient capabilities only; no privilege is granted.
    if unsafe {
        nix::libc::prctl(
            nix::libc::PR_CAP_AMBIENT,
            nix::libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: capset reads the native UAPI v3 header and exactly two initialized capability words.
    if unsafe {
        nix::libc::syscall(
            nix::libc::SYS_capset,
            &header as *const Header,
            data.as_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    set_no_new_privs().map_err(io::Error::from)?;
    let observed = privilege_state()?;
    if observed.capabilities != [0; 5] || !observed.no_new_privs {
        return Err(io::Error::other(
            "namespace capabilities were not completely removed",
        ));
    }
    Ok(())
}

fn run_helper(
    user_raw: RawFd,
    net_raw: RawFd,
) -> Result<(DedicatedEgressListener, HelperProof), HelperFailure> {
    if user_raw < 3 || net_raw < 3 || user_raw == net_raw {
        return Err(failure(
            HelperStage::Input,
            io::Error::other("invalid namespace slots"),
        ));
    }
    for raw in [user_raw, net_raw] {
        // SAFETY: fcntl validates the untrusted integer before constructing a BorrowedFd.
        if unsafe { nix::libc::fcntl(raw, nix::libc::F_GETFD) } < 0 {
            return Err(failure(HelperStage::Input, io::Error::last_os_error()));
        }
        // SAFETY: borrowed descriptors are checked without taking ownership until both are valid.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let flags = fcntl(borrowed, FcntlArg::F_GETFD)
            .map_err(|error| failure(HelperStage::Input, error.into()))?;
        fcntl(
            borrowed,
            FcntlArg::F_SETFD(FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC),
        )
        .map_err(|error| failure(HelperStage::Input, error.into()))?;
    }
    // SAFETY: the private exec protocol transfers exactly these two distinct inherited slots.
    let owner = unsafe { OwnedFd::from_raw_fd(user_raw) };
    // SAFETY: the second descriptor is distinct from owner and is transferred once.
    let net = unsafe { OwnedFd::from_raw_fd(net_raw) };
    let namespace = PinnedNetworkNamespace::from_owned_fd(net)
        .map_err(|error| failure(HelperStage::Input, io::Error::other(error)))?;
    let initial = privilege_state().map_err(|error| failure(HelperStage::Input, error))?;
    let owner_uid = validate_owner(&namespace, &owner, &initial)
        .map_err(|error| failure(HelperStage::OwnerUserNamespace, error))?;
    let executable = executable_identity().map_err(|error| failure(HelperStage::Input, error))?;
    let owner_metadata =
        fstat(&owner).map_err(|error| failure(HelperStage::OwnerUserNamespace, error.into()))?;
    let user_namespace = (owner_metadata.st_dev, owner_metadata.st_ino);
    setns(&owner, CloneFlags::CLONE_NEWUSER)
        .map_err(|error| failure(HelperStage::EnterUserNamespace, error.into()))?;
    if namespace_identity("user")
        .map_err(|error| failure(HelperStage::EnterUserNamespace, error))?
        != user_namespace
    {
        return Err(failure(
            HelperStage::EnterUserNamespace,
            io::Error::other("wrong user namespace"),
        ));
    }
    setns(namespace.as_fd(), CloneFlags::CLONE_NEWNET)
        .map_err(|error| failure(HelperStage::EnterNetworkNamespace, error.into()))?;
    if namespace_identity("net")
        .map_err(|error| failure(HelperStage::EnterNetworkNamespace, error))?
        != (namespace.identity().device(), namespace.identity().inode())
    {
        return Err(failure(
            HelperStage::EnterNetworkNamespace,
            io::Error::other("wrong network namespace"),
        ));
    }
    loopback_up().map_err(|error| failure(HelperStage::Loopback, error))?;
    drop_privileges().map_err(|error| failure(HelperStage::DropPrivileges, error))?;
    let listener = bind_listener_in_observed_namespace(namespace.identity())
        .map_err(|error| failure(HelperStage::BindListener, io::Error::other(error)))?;
    let listener_metadata =
        fstat(&listener).map_err(|error| failure(HelperStage::Receipt, error.into()))?;
    let proof = HelperProof {
        namespace: namespace.identity(),
        user_namespace,
        owner_uid,
        initial_uid: initial.uids[0],
        executable,
        state: privilege_state().map_err(|error| failure(HelperStage::Receipt, error))?,
        address: listener.receipt().address(),
        listener_identity: (listener_metadata.st_dev, listener_metadata.st_ino),
    };
    Ok((listener, proof))
}

/// Dispatch the private helper before initializing Tokio or any other threads.
/// Returns false for ordinary daemon invocation. Helper arguments accept only two inherited
/// descriptor numbers; addresses, namespace paths and helper executables are never accepted.
pub fn dispatch_native_egress_listener_helper() -> io::Result<bool> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments
        .get(1)
        .is_none_or(|argument| argument != HELPER_ARGUMENT)
    {
        return Ok(false);
    }
    if arguments.len() != 4 {
        return Err(io::Error::other("invalid private helper invocation"));
    }
    // SAFETY: stdin is owned solely by this early dispatch and is never used by daemon startup.
    let channel = unsafe { OwnedFd::from_raw_fd(0) };
    if sockopt::SockType.get(&channel).map_err(io::Error::from)? != SockType::SeqPacket {
        return Err(io::Error::other(
            "private helper requires a Unix seqpacket socket",
        ));
    }
    let peer = sockopt::PeerCredentials
        .get(&channel)
        .map_err(io::Error::from)?;
    if peer.uid() != nix::unistd::geteuid().as_raw()
        || peer.pid() != nix::unistd::getppid().as_raw()
    {
        return Err(io::Error::from_raw_os_error(nix::libc::EPERM));
    }
    // SAFETY: fixed parent-death SIGKILL affects only this disposable helper. Recheck the exact
    // parent after registration so a parent death in the earlier credential check fails closed.
    if unsafe { nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if peer.pid() != nix::unistd::getppid().as_raw() {
        return Err(io::Error::from_raw_os_error(nix::libc::ESRCH));
    }
    let parse = |index: usize| -> io::Result<RawFd> {
        arguments[index]
            .to_str()
            .and_then(|text| text.parse::<RawFd>().ok())
            .ok_or_else(|| io::Error::other("invalid namespace descriptor"))
    };
    let result = run_helper(parse(2)?, parse(3)?);
    let (listener, response) = match result {
        Ok((listener, proof)) => (
            Some(listener),
            HelperResponse {
                version: 1,
                proof: Some(proof),
                failure: None,
            },
        ),
        Err(error) => (
            None,
            HelperResponse {
                version: 1,
                proof: None,
                failure: Some(error),
            },
        ),
    };
    let bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(io::Error::other("oversized private helper receipt"));
    }
    let rights: Vec<RawFd> = listener
        .iter()
        .map(|listener| listener.as_fd().as_raw_fd())
        .collect();
    let controls = if rights.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&rights)]
    };
    let sent = sendmsg::<()>(
        channel.as_raw_fd(),
        &[IoSlice::new(&bytes)],
        &controls,
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(io::Error::from)?;
    if sent != bytes.len() {
        return Err(io::Error::other("short private helper receipt"));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use nix::fcntl::OFlag;
    use nix::unistd::{pipe2, read};

    fn channel() -> (OwnedFd, OwnedFd) {
        let pair = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )
        .expect("private channel should open");
        sockopt::PassCred
            .set(&pair.0, &true)
            .expect("kernel credentials should be enabled");
        pair
    }

    fn send(channel: &OwnedFd, bytes: &[u8], descriptors: &[RawFd]) {
        let controls = if descriptors.is_empty() {
            Vec::new()
        } else {
            vec![ControlMessage::ScmRights(descriptors)]
        };
        let sent = sendmsg::<()>(
            channel.as_raw_fd(),
            &[IoSlice::new(bytes)],
            &controls,
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .expect("kernel message should transfer");
        assert_eq!(sent, bytes.len());
    }

    fn response_bytes() -> Vec<u8> {
        serde_json::to_vec(&HelperResponse {
            version: 1,
            proof: None,
            failure: Some(HelperFailure {
                stage: HelperStage::Input,
                errno: Some(nix::libc::EPERM),
            }),
        })
        .expect("bounded typed response should encode")
    }

    #[test]
    fn native_receipt_transfers_actual_owned_cloexec_descriptor_with_kernel_credentials() {
        let (receiver, sender) = channel();
        let source = tempfile::tempfile().expect("private file should open");
        send(&sender, &response_bytes(), &[source.as_raw_fd()]);
        let (_, descriptors) = receive_response(
            &receiver,
            std::process::id(),
            nix::unistd::geteuid().as_raw(),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("matching actual kernel credentials should authenticate");
        assert_eq!(descriptors.len(), 1);
        let before = fstat(&source).expect("source identity should be readable");
        let after = fstat(&descriptors[0]).expect("transferred identity should be readable");
        assert_eq!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
        assert_ne!(source.as_raw_fd(), descriptors[0].as_raw_fd());
        assert!(
            FdFlag::from_bits_truncate(
                fcntl(&descriptors[0], FcntlArg::F_GETFD)
                    .expect("received descriptor flags should be readable")
            )
            .contains(FdFlag::FD_CLOEXEC)
        );
    }

    #[test]
    fn native_receipt_rejects_wrong_kernel_sender_pid_or_uid() {
        for (pid, uid) in [
            (std::process::id() + 1, nix::unistd::geteuid().as_raw()),
            (std::process::id(), nix::unistd::geteuid().as_raw() + 1),
        ] {
            let (receiver, sender) = channel();
            send(&sender, &response_bytes(), &[]);
            assert!(
                receive_response(&receiver, pid, uid, Instant::now() + Duration::from_secs(1))
                    .is_err()
            );
        }
    }

    #[test]
    fn malformed_or_truncated_native_receipt_closes_every_received_right() {
        for bytes in [b"invalid-json".to_vec(), vec![b'x'; MAX_RECEIPT_BYTES + 1]] {
            let (receiver, sender) = channel();
            let (reader, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
                .expect("exclusive writer pipe should open");
            send(&sender, &bytes, &[writer.as_raw_fd()]);
            drop(writer);
            assert!(
                receive_response(
                    &receiver,
                    std::process::id(),
                    nix::unistd::geteuid().as_raw(),
                    Instant::now() + Duration::from_secs(1)
                )
                .is_err()
            );
            let mut byte = [0];
            assert_eq!(
                read(&reader, &mut byte).expect("all transferred writer capabilities must close"),
                0
            );
        }
    }

    #[test]
    fn native_channel_timeout_is_bounded_and_typed() {
        let (receiver, _sender) = channel();
        let started = Instant::now();
        let error = receive_response(
            &receiver,
            std::process::id(),
            nix::unistd::geteuid().as_raw(),
            started + Duration::from_millis(20),
        )
        .expect_err("silent helper must time out");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            error,
            public_error(HelperStage::Receipt, Some(nix::libc::ETIMEDOUT))
        );
    }

    #[test]
    fn native_helper_timeout_kills_and_reaps_the_exact_owned_child() {
        let child = Command::new("/usr/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("owned timeout child should start");
        let pid =
            nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("child PID should fit"));
        let error = reap_child(child, Instant::now()).expect_err("owned child must hit deadline");
        assert_eq!(
            error,
            public_error(HelperStage::Receipt, Some(nix::libc::ETIMEDOUT))
        );
        assert_eq!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
    }
}
