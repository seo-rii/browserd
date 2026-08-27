//! One-shot construction of a dedicated egress listener inside a pinned network namespace.

#![forbid(unsafe_code)]

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::thread;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sched::{CloneFlags, setns};
use thiserror::Error;

use crate::{NetworkNamespaceIdentity, PinnedNetworkNamespace};

/// A sealed description of the exact listener created for one shard namespace.
///
/// Its fields are deliberately private so callers cannot manufacture a successful namespace
/// attachment receipt.
///
/// ```compile_fail
/// # fn inspect(receipt: browserd_sandbox::DedicatedEgressListenerReceipt) {
/// let _ = receipt.address;
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DedicatedEgressListenerReceipt {
    address: SocketAddr,
    namespace_identity: NetworkNamespaceIdentity,
}

impl DedicatedEgressListenerReceipt {
    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub const fn namespace_identity(self) -> NetworkNamespaceIdentity {
        self.namespace_identity
    }
}

/// The owned listener capability prepared inside a shard's exact network namespace.
#[derive(Debug)]
pub struct DedicatedEgressListener {
    descriptor: OwnedFd,
    receipt: DedicatedEgressListenerReceipt,
}

impl DedicatedEgressListener {
    #[must_use]
    pub const fn receipt(&self) -> DedicatedEgressListenerReceipt {
        self.receipt
    }

    #[must_use]
    pub fn into_parts(self) -> (OwnedFd, DedicatedEgressListenerReceipt) {
        (self.descriptor, self.receipt)
    }
}

impl AsFd for DedicatedEgressListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DedicatedEgressListenerError {
    #[error("failed to clone the network namespace capability: {0}")]
    CloneNamespace(String),
    #[error("failed to start the dedicated network namespace thread: {0}")]
    SpawnThread(String),
    #[error("the dedicated network namespace thread panicked")]
    ThreadPanicked,
    #[error("failed to enter the pinned network namespace: {0}")]
    EnterNamespace(String),
    #[error("failed to observe the current network namespace: {0}")]
    ObserveNamespace(String),
    #[error("network namespace identity mismatch: expected {expected:?}, observed {observed:?}")]
    NamespaceMismatch {
        expected: NetworkNamespaceIdentity,
        observed: NetworkNamespaceIdentity,
    },
    #[error("failed to bind the dedicated egress listener: {0}")]
    BindListener(String),
    #[error("failed to configure the dedicated egress listener: {0}")]
    ConfigureListener(String),
    #[error("failed to inspect the dedicated egress listener: {0}")]
    InspectListener(String),
    #[error("the dedicated egress listener has an invalid local address: {0}")]
    InvalidListenerAddress(SocketAddr),
}

/// Creates a loopback listener in the exact pinned namespace without changing the caller thread.
///
/// The helper selects `127.0.0.1:0` internally. Only the resulting listener descriptor and its
/// sealed receipt leave the one-shot namespace thread; the raw namespace descriptor does not.
pub fn create_dedicated_egress_listener(
    namespace: &PinnedNetworkNamespace,
) -> Result<DedicatedEgressListener, DedicatedEgressListenerError> {
    let expected_identity = namespace.identity();
    let namespace_descriptor = namespace
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| DedicatedEgressListenerError::CloneNamespace(error.to_string()))?;

    run_on_dedicated_thread(move || {
        setns(&namespace_descriptor, CloneFlags::CLONE_NEWNET)
            .map_err(|error| DedicatedEgressListenerError::EnterNamespace(error.to_string()))?;
        bind_listener_in_observed_namespace(expected_identity)
    })
}

pub(crate) fn run_on_dedicated_thread<T, Operation>(
    operation: Operation,
) -> Result<T, DedicatedEgressListenerError>
where
    T: Send + 'static,
    Operation: FnOnce() -> Result<T, DedicatedEgressListenerError> + Send + 'static,
{
    thread::Builder::new()
        .name("browserd-netns-listener".into())
        .spawn(operation)
        .map_err(|error| DedicatedEgressListenerError::SpawnThread(error.to_string()))?
        .join()
        .map_err(|_| DedicatedEgressListenerError::ThreadPanicked)?
}

pub(crate) fn bind_listener_in_observed_namespace(
    expected_identity: NetworkNamespaceIdentity,
) -> Result<DedicatedEgressListener, DedicatedEgressListenerError> {
    require_current_namespace(expected_identity)?;

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| DedicatedEgressListenerError::BindListener(error.to_string()))?;
    configure_listener(&listener)?;

    let address = listener
        .local_addr()
        .map_err(|error| DedicatedEgressListenerError::InspectListener(error.to_string()))?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err(DedicatedEgressListenerError::InvalidListenerAddress(
            address,
        ));
    }

    require_current_namespace(expected_identity)?;

    Ok(DedicatedEgressListener {
        descriptor: listener.into(),
        receipt: DedicatedEgressListenerReceipt {
            address,
            namespace_identity: expected_identity,
        },
    })
}

fn configure_listener(listener: &TcpListener) -> Result<(), DedicatedEgressListenerError> {
    let descriptor_flags = fcntl(listener, FcntlArg::F_GETFD)
        .map_err(|error| DedicatedEgressListenerError::ConfigureListener(error.to_string()))?;
    let descriptor_flags = FdFlag::from_bits_truncate(descriptor_flags) | FdFlag::FD_CLOEXEC;
    fcntl(listener, FcntlArg::F_SETFD(descriptor_flags))
        .map_err(|error| DedicatedEgressListenerError::ConfigureListener(error.to_string()))?;

    let status_flags = fcntl(listener, FcntlArg::F_GETFL)
        .map_err(|error| DedicatedEgressListenerError::ConfigureListener(error.to_string()))?;
    let status_flags = OFlag::from_bits_truncate(status_flags) | OFlag::O_NONBLOCK;
    fcntl(listener, FcntlArg::F_SETFL(status_flags))
        .map_err(|error| DedicatedEgressListenerError::ConfigureListener(error.to_string()))?;
    Ok(())
}

fn require_current_namespace(
    expected_identity: NetworkNamespaceIdentity,
) -> Result<(), DedicatedEgressListenerError> {
    let observed = current_namespace_identity()?;
    if observed != expected_identity {
        return Err(DedicatedEgressListenerError::NamespaceMismatch {
            expected: expected_identity,
            observed,
        });
    }
    Ok(())
}

fn current_namespace_identity() -> Result<NetworkNamespaceIdentity, DedicatedEgressListenerError> {
    let descriptor: OwnedFd = File::open("/proc/thread-self/ns/net")
        .map_err(|error| DedicatedEgressListenerError::ObserveNamespace(error.to_string()))?
        .into();
    PinnedNetworkNamespace::from_owned_fd(descriptor)
        .map(|namespace| namespace.identity())
        .map_err(|error| DedicatedEgressListenerError::ObserveNamespace(error.to_string()))
}
