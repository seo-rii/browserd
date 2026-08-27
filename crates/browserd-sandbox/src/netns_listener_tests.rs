#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sched::{CloneFlags, setns};
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
