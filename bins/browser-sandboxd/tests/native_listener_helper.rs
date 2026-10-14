#![allow(clippy::expect_used, clippy::panic)]

use std::fs::File;
use std::io::{IoSliceMut, Read, Seek, SeekFrom};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::socket::{
    AddressFamily, ControlMessageOwned, MsgFlags, SetSockOpt, SockFlag, SockType, recvmsg,
    socketpair, sockopt,
};
use nix::sys::time::TimeVal;

const HELPER: &str = "--browserd-private-netns-listener-v1";

struct OwnedChild(Child);
impl OwnedChild {
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self
                .0
                .try_wait()
                .expect("exact child status should be readable")
            {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "exact owned helper exceeded its deadline"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn parent_state() -> serde_json::Value {
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .expect("parent status should be readable");
    let fields: serde_json::Map<String, serde_json::Value> = status
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            matches!(
                name,
                "Uid" | "Gid" | "CapInh" | "CapPrm" | "CapEff" | "CapBnd" | "CapAmb" | "NoNewPrivs"
            )
            .then(|| {
                (
                    name.to_owned(),
                    serde_json::Value::String(value.trim().to_owned()),
                )
            })
        })
        .collect();
    let namespaces: Vec<_> = ["user", "net"]
        .into_iter()
        .map(|name| {
            let metadata = std::fs::metadata(format!("/proc/thread-self/ns/{name}"))
                .expect("parent namespace should be observable");
            (metadata.dev(), metadata.ino())
        })
        .collect();
    serde_json::json!({"status": fields, "namespaces": namespaces})
}

fn owner_namespace(net: &File) -> OwnedFd {
    // SAFETY: NS_GET_USERNS returns the owner capability of this exact still-owned NET fd.
    let raw = unsafe { nix::libc::ioctl(net.as_raw_fd(), nix::libc::NS_GET_USERNS) };
    assert!(
        raw >= 0,
        "kernel should derive the exact USER owner: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful ioctl transferred one fresh descriptor.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn helper_response(owner: &OwnedFd, net: &File) -> (serde_json::Value, Vec<OwnedFd>, u32) {
    let (receiver, sender) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .expect("private channel should open");
    sockopt::PassCred
        .set(&receiver, &true)
        .expect("kernel credentials should be enabled");
    sockopt::ReceiveTimeout
        .set(&receiver, &TimeVal::new(5, 0))
        .expect("receive deadline should apply");
    let inherited = [owner.as_raw_fd(), net.as_raw_fd()];
    let mut command = Command::new(env!("CARGO_BIN_EXE_browser-sandboxd"));
    command
        .arg(HELPER)
        .arg(inherited[0].to_string())
        .arg(inherited[1].to_string())
        .env_clear()
        .stdin(Stdio::from(sender))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: this changes only child FD flags and NNP with async-signal-safe integer syscalls.
    unsafe {
        command.pre_exec(move || {
            for raw in inherited {
                let flags = nix::libc::fcntl(raw, nix::libc::F_GETFD);
                if flags < 0
                    || nix::libc::fcntl(raw, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(command.spawn().expect("exact native helper should exec"));
    drop(command);
    let pid = child.0.id();
    let mut bytes = [0u8; 4096];
    let mut vectors = [IoSliceMut::new(&mut bytes)];
    let mut controls = nix::cmsg_space!([RawFd; 253], nix::libc::ucred);
    let message = recvmsg::<()>(
        receiver.as_raw_fd(),
        &mut vectors,
        Some(&mut controls),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .expect("native helper should return a bounded kernel message");
    let length = message.bytes;
    let mut descriptors = Vec::new();
    let mut credentials = Vec::new();
    for control in message
        .cmsgs()
        .expect("bounded helper control should not truncate")
    {
        match control {
            ControlMessageOwned::ScmRights(raw) => {
                for descriptor in raw {
                    // SAFETY: recvmsg installed each unique returned descriptor once.
                    descriptors.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
                }
            }
            ControlMessageOwned::ScmCredentials(credential) => credentials.push(credential),
            _ => unreachable!("private native helper must send only credentials and owned rights"),
        }
    }
    assert!(
        !message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    );
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        u32::try_from(credentials[0].pid()).expect("sender PID should be positive"),
        pid
    );
    assert_eq!(
        credentials[0].uid(),
        nix::unistd::geteuid().as_raw(),
        "SCM UID must be compared in the receiving parent's USER namespace"
    );
    let response =
        serde_json::from_slice(&bytes[..length]).expect("typed helper receipt should decode");
    assert!(
        child.wait().success(),
        "helper dispatch should finish without daemon configuration"
    );
    (response, descriptors, pid)
}

#[test]
fn private_helper_dispatch_rejects_extra_arguments_before_daemon_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_browser-sandboxd"))
        .args([HELPER, "3", "4", "127.0.0.1:1234"])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .expect("native binary should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid private helper invocation"));
    assert!(!stderr.contains("BROWSERD_SANDBOX_SOCKET"));
}

#[test]
fn private_helper_dispatch_rejects_non_unix_stdin_before_daemon_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_browser-sandboxd"))
        .args([HELPER, "3", "4"])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .expect("native binary should execute");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("BROWSERD_SANDBOX_SOCKET"));
}

#[test]
fn private_helper_rejects_host_owner_and_mismatched_user_fd_without_a_listener() {
    let before = parent_state();
    let net = File::open("/proc/thread-self/ns/net").expect("current NET should pin");
    let owner = owner_namespace(&net);
    let (response, descriptors, _) = helper_response(&owner, &net);
    assert_eq!(response["version"], 1);
    assert!(response["proof"].is_null());
    assert_eq!(response["failure"]["stage"], "owner_user_namespace");
    assert!(descriptors.is_empty());
    let (pipe, _writer) =
        nix::unistd::pipe2(OFlag::O_CLOEXEC).expect("wrong USER capability should open");
    let (response, descriptors, _) = helper_response(&pipe, &net);
    assert_eq!(response["failure"]["stage"], "owner_user_namespace");
    assert_eq!(response["failure"]["errno"], nix::libc::ENOTTY);
    assert!(response["proof"].is_null());
    assert!(descriptors.is_empty());
    assert_eq!(parent_state(), before);
}

#[test]
#[ignore = "requires isolated production UID1003, all capability sets zero, NNP1 and genuine nested bubblewrap"]
fn cap0_native_helper_enters_owned_bubblewrap_user_then_net_and_transfers_usable_listener() {
    let before = parent_state();
    assert_eq!(
        nix::unistd::geteuid().as_raw(),
        1003,
        "run in the isolated production daemon identity"
    );
    assert_eq!(before["status"]["NoNewPrivs"], "1");
    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        assert_eq!(
            u64::from_str_radix(
                before["status"][name]
                    .as_str()
                    .expect("capability field should exist"),
                16
            )
            .expect("capability word should parse"),
            0
        );
    }
    let directory =
        tempfile::tempdir().expect("private native kernel evidence directory should exist");
    let mut info = tempfile::tempfile().expect("private info file should open");
    let payload = r#"import json,pathlib,socket,time
p=pathlib.Path('/tmp/browserd-native-listener/address.json')
for i in range(500):
 if p.exists(): break
 time.sleep(.01)
else: raise RuntimeError('listener address deadline')
a=json.loads(p.read_text())
s=socket.create_connection((a['ip'],a['port']),timeout=2)
s.sendall(b'native-kernel-listener')
time.sleep(30)
"#;
    let mut boundary = OwnedChild(
        Command::new("/usr/bin/bwrap")
            .args([
                "--die-with-parent",
                "--unshare-user",
                "--unshare-net",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--bind",
            ])
            .arg(directory.path())
            .args([
                "/tmp/browserd-native-listener",
                "--info-fd",
                "1",
                "--",
                "/usr/bin/python3",
                "-c",
                payload,
            ])
            .stdin(Stdio::null())
            .stdout(info.try_clone().expect("info fd should clone"))
            .stderr(Stdio::null())
            .spawn()
            .expect("genuine nested boundary should start"),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        info.seek(SeekFrom::Start(0))
            .expect("info reader should rewind its own test file");
        let mut bytes = Vec::new();
        (&mut info)
            .take(4097)
            .read_to_end(&mut bytes)
            .expect("bounded info should read");
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(pid) = value["child-pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
        {
            break pid;
        }
        assert!(
            boundary
                .0
                .try_wait()
                .expect("boundary status should read")
                .is_none(),
            "kernel prerequisite blocked: bubblewrap exited"
        );
        assert!(
            Instant::now() < deadline,
            "kernel prerequisite blocked: bubblewrap readiness timed out"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let net =
        File::open(format!("/proc/{pid}/ns/net")).expect("reported exact child NET should pin");
    let net_identity = net.metadata().expect("pinned NET identity should read");
    let owner = owner_namespace(&net);
    let owner_identity = nix::sys::stat::fstat(&owner).expect("derived owner identity should read");
    let (response, mut descriptors, helper_pid) = helper_response(&owner, &net);
    assert!(
        response["failure"].is_null(),
        "native namespace operation failed: {response}"
    );
    assert_eq!(descriptors.len(), 1);
    let proof = &response["proof"];
    assert_eq!(proof["namespace"]["device"], net_identity.dev());
    assert_eq!(proof["namespace"]["inode"], net_identity.ino());
    assert_eq!(proof["owner_uid"], 1003);
    assert_eq!(proof["initial_uid"], 1003);
    assert_eq!(
        proof["user_namespace"],
        serde_json::json!([owner_identity.st_dev, owner_identity.st_ino])
    );
    assert_eq!(
        proof["state"]["capabilities"],
        serde_json::json!([0, 0, 0, 0, 0])
    );
    assert_eq!(proof["state"]["no_new_privs"], true);
    let descriptor = descriptors.pop().expect("one listener should transfer");
    let flags = fcntl(&descriptor, FcntlArg::F_GETFD).expect("received fd flags should read");
    assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
    let listener = TcpListener::from(descriptor);
    let address = listener
        .local_addr()
        .expect("transferred native listener address should read");
    assert_eq!(proof["address"], address.to_string());
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err(),
        "parent host loopback cannot reach the private listener"
    );
    std::fs::write(
        directory.path().join("address.json"),
        serde_json::to_vec(&serde_json::json!({
            "ip": "127.0.0.1", "port": address.port(),
        }))
        .expect("fixed loopback address should encode"),
    )
    .expect("private client instruction should write");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut accepted = loop {
        match listener.accept() {
            Ok((accepted, _)) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "native client must reach exact transferred listener"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("native listener accept failed: {error}"),
        }
    };
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read deadline should apply");
    let mut bytes = [0u8; 22];
    accepted
        .read_exact(&mut bytes)
        .expect("real private namespace client should write to owned listener");
    assert_eq!(&bytes, b"native-kernel-listener");
    assert_eq!(parent_state(), before);
    assert!(
        !std::path::Path::new(&format!("/proc/{helper_pid}")).exists(),
        "exact helper must be reaped"
    );
}
