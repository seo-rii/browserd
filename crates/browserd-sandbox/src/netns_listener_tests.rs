#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sched::{CloneFlags, setns};
use nix::sys::prctl::set_no_new_privs;
use nix::sys::socket::{GetSockOpt, sockopt};
use nix::unistd::{pipe2, read};

use super::linux::PinnedNetworkNamespace;
use super::netns_listener::{
    DedicatedEgressListenerError, bind_listener_in_observed_namespace,
    create_dedicated_egress_listener, run_on_dedicated_thread,
};

fn current_network_namespace() -> PinnedNetworkNamespace {
    let descriptor: OwnedFd = File::open("/proc/thread-self/ns/net")
        .expect("the current network namespace should be openable")
        .into();
    PinnedNetworkNamespace::from_owned_fd(descriptor)
        .expect("the current network namespace should be pinnable")
}

#[test]
fn invalid_capability_is_rejected_before_listener_construction() {
    let (read_end, write_end) = pipe2(OFlag::O_CLOEXEC).expect("pipe creation should work");

    let error = PinnedNetworkNamespace::from_owned_fd(read_end)
        .expect_err("a pipe must not be accepted as a network namespace");
    drop(write_end);

    assert!(error.to_string().contains("not an nsfs descriptor"));
}

#[test]
fn returned_listener_is_exact_loopback_capability_with_transfer_safe_flags() {
    let namespace = current_network_namespace();
    let prepared = bind_listener_in_observed_namespace(namespace.identity())
        .expect("listener construction in the observed namespace should work");
    let receipt = prepared.receipt();

    assert_eq!(receipt.namespace_identity(), namespace.identity());
    assert_eq!(receipt.address().ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(receipt.address().port(), 0);

    let descriptor_flags =
        fcntl(prepared.as_fd(), FcntlArg::F_GETFD).expect("descriptor flags should be readable");
    assert!(FdFlag::from_bits_truncate(descriptor_flags).contains(FdFlag::FD_CLOEXEC));
    let status_flags =
        fcntl(prepared.as_fd(), FcntlArg::F_GETFL).expect("status flags should be readable");
    assert!(OFlag::from_bits_truncate(status_flags).contains(OFlag::O_NONBLOCK));
    assert!(
        sockopt::AcceptConn
            .get(&prepared)
            .expect("listener state should be readable")
    );

    let address = receipt.address();
    let (descriptor, returned_receipt) = prepared.into_parts();
    assert_eq!(returned_receipt, receipt);
    let listener = TcpListener::from(descriptor);
    let mut client = TcpStream::connect(address).expect("client should reach the listener");
    let (accepted, peer) = listener.accept().expect("queued client should be accepted");
    assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);

    client
        .write_all(b"x")
        .expect("client should write through the listener");
    let mut byte = [0_u8; 1];
    let read_count = read(accepted.as_fd(), &mut byte).expect("accepted stream should be readable");
    assert_eq!(read_count, 1);
    assert_eq!(byte, [b'x']);
}

#[test]
fn dedicated_thread_runner_never_changes_the_callers_namespace() {
    let before = current_network_namespace().identity();
    let caller_thread = thread::current().id();

    let helper_thread = run_on_dedicated_thread(|| Ok(thread::current().id()))
        .expect("dedicated helper thread should finish");

    assert_ne!(helper_thread, caller_thread);
    assert_eq!(current_network_namespace().identity(), before);
}

#[test]
fn helper_thread_panic_fails_closed() {
    let error = run_on_dedicated_thread::<(), _>(|| panic!("injected helper panic"))
        .expect_err("a helper panic must not look like listener success");

    assert_eq!(error, DedicatedEgressListenerError::ThreadPanicked);
}

#[test]
fn public_helper_does_not_accept_a_caller_selected_address() {
    let helper: fn(
        &PinnedNetworkNamespace,
    ) -> Result<
        super::netns_listener::DedicatedEgressListener,
        DedicatedEgressListenerError,
    > = create_dedicated_egress_listener;
    let _ = helper;
    let _ = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
}

#[test]
fn native_helper_rejects_current_host_namespace_without_changing_parent_authority() {
    let namespace = current_network_namespace();
    let before_network = namespace.identity();
    let before_user = std::fs::metadata("/proc/thread-self/ns/user")
        .expect("caller user namespace should be observable");
    let before_status = namespace_probe_status(Path::new("/proc/thread-self/status"));
    let before_uid = nix::unistd::geteuid();
    let error = super::create_native_dedicated_egress_listener(&namespace)
        .expect_err("the current host USER/NET capability must never enter the native helper");
    assert!(
        error.to_string().starts_with(
            "native network namespace helper failed: stage=owner_user_namespace errno="
        )
    );
    assert_eq!(current_network_namespace().identity(), before_network);
    let after_user = std::fs::metadata("/proc/thread-self/ns/user")
        .expect("caller user namespace should remain observable");
    assert_eq!(
        (before_user.dev(), before_user.ino()),
        (after_user.dev(), after_user.ino())
    );
    assert_eq!(
        namespace_probe_status(Path::new("/proc/thread-self/status")),
        before_status
    );
    assert_eq!(nix::unistd::geteuid(), before_uid);
}

#[test]
fn listener_descriptor_is_owned_and_closed_on_drop() {
    let namespace = current_network_namespace();
    let prepared = bind_listener_in_observed_namespace(namespace.identity())
        .expect("listener construction should work");
    let address = prepared.receipt().address();
    drop(prepared);

    let rebound = TcpListener::bind(address).expect("dropping the capability should release it");
    assert_eq!(
        rebound
            .local_addr()
            .expect("rebound listener address should be readable"),
        address
    );
}

#[test]
#[ignore = "requires permission to create and enter a foreign Linux network namespace"]
fn privileged_helper_enters_the_exact_foreign_namespace() {
    const USER_NAMESPACE_HELPER: &str = "BROWSERD_NETNS_LISTENER_USER_NAMESPACE_HELPER";

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    if std::env::var_os(USER_NAMESPACE_HELPER).is_none() {
        let executable = std::env::current_exe().expect("the test executable should be known");
        let status = Command::new("unshare")
            .args(["--user", "--map-root-user", "--fork"])
            .arg(executable)
            .args([
                "--ignored",
                "--exact",
                "netns_listener_tests::privileged_helper_enters_the_exact_foreign_namespace",
            ])
            .env(USER_NAMESPACE_HELPER, "1")
            .status()
            .expect("user-namespace helper should start");
        assert!(status.success(), "user-namespace helper should pass");
        return;
    }

    let caller_namespace = current_network_namespace().identity();
    let child = Command::new("unshare")
        .args(["--net", "--fork", "sleep", "30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("unshare should start");
    let child = ChildGuard(child);
    let namespace_path = format!("/proc/{}/ns/net", child.0.id());

    let foreign_namespace = (0..100).find_map(|_| {
        let namespace = File::open(&namespace_path)
            .ok()
            .map(OwnedFd::from)
            .and_then(|descriptor| PinnedNetworkNamespace::from_owned_fd(descriptor).ok());
        if namespace
            .as_ref()
            .is_some_and(|namespace| namespace.identity() != caller_namespace)
        {
            namespace
        } else {
            thread::sleep(Duration::from_millis(10));
            None
        }
    });
    let foreign_namespace = foreign_namespace.expect("unshare should expose a foreign namespace");
    let loopback_status = Command::new("nsenter")
        .arg(format!("--net={namespace_path}"))
        .args(["ip", "link", "set", "lo", "up"])
        .status()
        .expect("loopback setup should start");
    assert!(loopback_status.success(), "foreign loopback should be up");

    let prepared = create_dedicated_egress_listener(&foreign_namespace)
        .expect("the helper should enter the pinned namespace");
    let receipt = prepared.receipt();

    assert_eq!(receipt.namespace_identity(), foreign_namespace.identity());
    assert_eq!(current_network_namespace().identity(), caller_namespace);
    assert!(
        TcpStream::connect_timeout(&receipt.address(), Duration::from_millis(100)).is_err(),
        "the caller namespace must not reach the foreign loopback listener"
    );

    let namespace_descriptor = foreign_namespace
        .as_fd()
        .try_clone_to_owned()
        .expect("the foreign namespace capability should clone");
    let address = receipt.address();
    let client = run_on_dedicated_thread(move || {
        setns(&namespace_descriptor, CloneFlags::CLONE_NEWNET)
            .map_err(|error| DedicatedEgressListenerError::EnterNamespace(error.to_string()))?;
        TcpStream::connect(address)
            .map_err(|error| DedicatedEgressListenerError::BindListener(error.to_string()))
    })
    .expect("a client in the exact foreign namespace should connect");
    let (descriptor, returned_receipt) = prepared.into_parts();
    let listener = TcpListener::from(descriptor);
    let (_accepted, _) = listener
        .accept()
        .expect("the adopted foreign listener should accept on the caller thread");
    drop(client);
    assert_eq!(returned_receipt, receipt);
}

/// Owns only the process started by this prerequisite test. The unshare and
/// bubblewrap parent-death settings also terminate their exact descendants.
struct NamespaceProbeChild(Child);

impl NamespaceProbeChild {
    fn wait_bounded(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self
                .0
                .try_wait()
                .expect("owned child status should be readable")
            {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "owned namespace prerequisite child timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for NamespaceProbeChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        eprintln!("owned namespace prerequisite child did not exit after kill");
    }
}

fn private_probe_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("private prerequisite evidence file should be created")
}

fn bounded_probe_json(path: &Path) -> Option<serde_json::Value> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > 8192 || metadata.mode() & 0o077 != 0 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 8192 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn preserve_namespace_probe_stderr(path: &Path) {
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    else {
        eprintln!("nested netns prerequisite stderr could not be opened");
        return;
    };
    let Ok(metadata) = file.metadata() else {
        eprintln!("nested netns prerequisite stderr metadata could not be read");
        return;
    };
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        eprintln!("nested netns prerequisite stderr is not a private regular file");
        return;
    }
    let mut bytes = Vec::new();
    if file.take(8192).read_to_end(&mut bytes).is_err() {
        eprintln!("nested netns prerequisite stderr could not be read");
        return;
    }
    let mut excerpt = String::from_utf8_lossy(&bytes).into_owned();
    let mut bound = excerpt.len().min(8192);
    while !excerpt.is_char_boundary(bound) {
        bound -= 1;
    }
    excerpt.truncate(bound);
    eprintln!("nested netns prerequisite private stderr excerpt (at most 8192 bytes):\n{excerpt}");
    if metadata.len() > 8192 {
        eprintln!("nested netns prerequisite stderr excerpt was truncated");
    }
}

fn namespace_probe_status(path: &Path) -> serde_json::Value {
    let contents =
        std::fs::read_to_string(path).expect("namespace process status should be readable");
    let mut result = serde_json::Map::new();
    for line in contents.lines() {
        if let Some((name, value)) = line.split_once(':')
            && matches!(
                name,
                "NoNewPrivs" | "CapInh" | "CapPrm" | "CapEff" | "CapBnd" | "CapAmb"
            )
        {
            result.insert(
                name.to_owned(),
                serde_json::Value::String(value.trim().to_owned()),
            );
        }
    }
    serde_json::Value::Object(result)
}

fn namespace_probe_process_start(pid: u32) -> Option<u64> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = contents.rsplit_once(')')?;
    fields.split_whitespace().nth(19)?.parse().ok()
}

#[test]
#[ignore = "requires nested user/PID/network namespaces and pinned bubblewrap"]
fn parent_user_namespace_enters_the_exact_nested_bubblewrap_namespace() {
    const HELPER: &str = "BROWSERD_NESTED_NETNS_AUTHORITY_HELPER";
    const EXACT: &str =
        "netns_listener_tests::parent_user_namespace_enters_the_exact_nested_bubblewrap_namespace";

    set_no_new_privs().expect("the prerequisite must retain no-new-privileges");
    let parent_status = namespace_probe_status(Path::new("/proc/thread-self/status"));
    assert_eq!(parent_status["NoNewPrivs"], "1");
    eprintln!("nested netns authority prerequisite parent status: {parent_status}");
    if std::env::var_os(HELPER).is_none() {
        let executable =
            std::env::current_exe().expect("the exact test executable should be known");
        let child = Command::new("unshare")
            .args(["--user", "--map-root-user", "--fork", "--kill-child=KILL"])
            .arg(executable)
            .args(["--ignored", "--exact", EXACT, "--nocapture"])
            .env(HELPER, "1")
            .stdin(Stdio::null())
            .spawn()
            .expect("the parent user namespace helper should start");
        let mut child = NamespaceProbeChild(child);
        assert!(
            child.wait_bounded(Duration::from_secs(45)).success(),
            "nested namespace authority prerequisite should pass"
        );
        return;
    }

    let directory = tempfile::Builder::new()
        .prefix("browserd-nested-netns-")
        .tempdir()
        .expect("a private prerequisite directory should exist");
    let info_path = directory.path().join("bwrap-info.json");
    let ready_path = directory.path().join("ready.json");
    let stderr_path = directory.path().join("bwrap.stderr");
    let caller_namespace = current_network_namespace().identity();
    let caller_user_inode = std::fs::metadata("/proc/thread-self/ns/user")
        .expect("parent user namespace identity should be readable")
        .ino();
    // The info FD is child stdout, inherited through Command's safe stdio
    // ownership. Only bubblewrap writes its host child-pid there. Guest PID
    // numbers are deliberately excluded from the readiness document.
    let payload = r#"import json,os,time
from pathlib import Path
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
record={'namespaces':{name:os.stat('/proc/self/ns/'+name).st_ino for name in ('user','pid','mnt','net')},'status':{name:status[name].strip() for name in ('NoNewPrivs','CapInh','CapPrm','CapEff','CapBnd','CapAmb')}}
descriptor=os.open('/tmp/browserd-probe/ready.tmp',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
 os.write(descriptor,json.dumps(record).encode()); os.fsync(descriptor)
finally:
 os.close(descriptor)
os.rename('/tmp/browserd-probe/ready.tmp','/tmp/browserd-probe/ready.json')
time.sleep(60)
"#;
    let child = Command::new("/usr/bin/bwrap")
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
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
            "--tmpfs",
            "/dev/shm",
            "--bind",
        ])
        .arg(directory.path())
        .args([
            "/tmp/browserd-probe",
            "--info-fd",
            "1",
            "--",
            "/usr/bin/python3",
            "-c",
            payload,
        ])
        .stdin(Stdio::null())
        .stdout(private_probe_file(&info_path))
        .stderr(private_probe_file(&stderr_path))
        .spawn()
        .expect("the nested bubblewrap boundary should start");
    let mut child = NamespaceProbeChild(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    let (info, ready) = loop {
        if let (Some(info), Some(ready)) = (
            bounded_probe_json(&info_path),
            bounded_probe_json(&ready_path),
        ) {
            break (info, ready);
        }
        if let Some(status) = child
            .0
            .try_wait()
            .expect("bubblewrap status should be readable")
        {
            preserve_namespace_probe_stderr(&stderr_path);
            panic!("nested bubblewrap exited before readiness: {status}");
        }
        if Instant::now() >= deadline {
            child
                .0
                .kill()
                .expect("the timed-out owned bubblewrap monitor should stop");
            let status = child.wait_bounded(Duration::from_secs(5));
            preserve_namespace_probe_stderr(&stderr_path);
            panic!("nested bubblewrap readiness timed out; owned monitor exited: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let host_pid = info["child-pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .expect("bubblewrap info must identify its exact host child PID");
    let child_start = namespace_probe_process_start(host_pid)
        .expect("the exact reported host child start time should be readable");
    eprintln!("nested netns authority prerequisite observed guest: {ready}");
    let namespace_path = format!("/proc/{host_pid}/ns/net");
    let descriptor: OwnedFd = File::open(&namespace_path)
        .expect("the exact reported host child's network namespace should be openable")
        .into();
    let namespace = PinnedNetworkNamespace::from_owned_fd(descriptor)
        .expect("the exact nested network namespace should pin");
    assert_ne!(namespace.identity(), caller_namespace);
    assert_eq!(
        ready["namespaces"]["net"].as_u64(),
        Some(namespace.identity().inode())
    );
    for name in ["user", "pid", "mnt", "net"] {
        let observed = std::fs::metadata(format!("/proc/{host_pid}/ns/{name}"))
            .expect("the exact host child's namespace identity should be readable")
            .ino();
        assert_eq!(ready["namespaces"][name].as_u64(), Some(observed));
        let parent = std::fs::metadata(format!("/proc/thread-self/ns/{name}"))
            .expect("parent namespace identity should be readable")
            .ino();
        assert_ne!(observed, parent);
    }
    assert_eq!(ready["status"]["NoNewPrivs"], "1");
    for name in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        let bits = ready["status"][name]
            .as_str()
            .expect("guest capability status should be present");
        assert_eq!(
            u64::from_str_radix(bits, 16).expect("guest capability bits should parse"),
            0
        );
    }
    let loopback_child = Command::new("nsenter")
        .arg(format!("--net={namespace_path}"))
        .args(["ip", "link", "set", "lo", "up"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(private_probe_file(
            &directory.path().join("loopback.stderr"),
        ))
        .spawn()
        .expect("exact nested namespace loopback setup should start");
    let mut loopback_child = NamespaceProbeChild(loopback_child);
    assert!(
        loopback_child
            .wait_bounded(Duration::from_secs(5))
            .success(),
        "parent user namespace must have authority to configure the exact child netns"
    );
    let prepared = create_dedicated_egress_listener(&namespace)
        .expect("production helper should enter the exact nested bubblewrap namespace");
    let receipt = prepared.receipt();
    assert_eq!(receipt.namespace_identity(), namespace.identity());
    assert_eq!(current_network_namespace().identity(), caller_namespace);
    assert_eq!(
        std::fs::metadata("/proc/thread-self/ns/user")
            .expect("caller user namespace should remain readable")
            .ino(),
        caller_user_inode
    );
    assert!(
        TcpStream::connect_timeout(&receipt.address(), Duration::from_millis(100)).is_err(),
        "caller host network namespace must not reach the exact nested loopback listener"
    );
    let namespace_descriptor = namespace
        .as_fd()
        .try_clone_to_owned()
        .expect("exact nested namespace capability should clone");
    let address = receipt.address();
    let mut client = run_on_dedicated_thread(move || {
        setns(&namespace_descriptor, CloneFlags::CLONE_NEWNET)
            .map_err(|error| DedicatedEgressListenerError::EnterNamespace(error.to_string()))?;
        TcpStream::connect_timeout(&address, Duration::from_secs(1))
            .map_err(|error| DedicatedEgressListenerError::BindListener(error.to_string()))
    })
    .expect("a client inside the exact nested namespace should connect");
    client
        .write_all(b"nested-netns-authority")
        .expect("the exact nested namespace client should write evidence bytes");
    let (descriptor, returned_receipt) = prepared.into_parts();
    let listener = TcpListener::from(descriptor);
    let (mut accepted, peer) = listener
        .accept()
        .expect("the exact nested namespace listener should accept its client");
    assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);
    accepted
        .set_nonblocking(false)
        .expect("the evidence stream should support a bounded blocking read");
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("the accepted evidence read should be bounded");
    let mut bytes = [0_u8; 22];
    accepted
        .read_exact(&mut bytes)
        .expect("the exact nested listener should receive the evidence");
    assert_eq!(&bytes, b"nested-netns-authority");
    assert_eq!(returned_receipt, receipt);
    assert_eq!(current_network_namespace().identity(), caller_namespace);
    drop(client);
    drop(accepted);
    drop(listener);
    drop(namespace);
    child
        .0
        .kill()
        .expect("the owned bubblewrap monitor should stop");
    assert!(!child.wait_bounded(Duration::from_secs(5)).success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while namespace_probe_process_start(host_pid) == Some(child_start) {
        assert!(
            Instant::now() < deadline,
            "the exact nested namespace child must exit after its monitor"
        );
        thread::sleep(Duration::from_millis(10));
    }
    eprintln!(
        "nested netns authority prerequisite passed; no production sandbox or egress qualification receipt"
    );
}
