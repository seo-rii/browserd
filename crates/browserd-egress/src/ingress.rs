use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::OwnedFd;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::socket::{SockType, getsockopt, sockopt};
use tokio::net::{TcpListener, TcpStream};

use crate::route::RouteIngressGuard;
use crate::{MonotonicMillis, RouteClaim, RouteError, RouteRegistry};

#[derive(Debug)]
pub struct RouteIngressListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    claim: RouteClaim,
    registry: RouteRegistry,
}

impl RouteIngressListener {
    pub fn from_owned_fd(
        descriptor: OwnedFd,
        claim: RouteClaim,
        registry: RouteRegistry,
    ) -> Result<Self, RouteIngressError> {
        let descriptor_flags = fcntl(&descriptor, FcntlArg::F_GETFD)
            .map(FdFlag::from_bits_retain)
            .map_err(|error| RouteIngressError::InvalidDescriptor(error.into()))?;
        if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) {
            return Err(RouteIngressError::MissingCloseOnExec);
        }
        let socket_type = getsockopt(&descriptor, sockopt::SockType)
            .map_err(|error| RouteIngressError::InvalidDescriptor(error.into()))?;
        if socket_type != SockType::Stream {
            return Err(RouteIngressError::NotStreamSocket);
        }
        let is_listening = getsockopt(&descriptor, sockopt::AcceptConn)
            .map_err(|error| RouteIngressError::InvalidDescriptor(error.into()))?;
        if !is_listening {
            return Err(RouteIngressError::NotListeningSocket);
        }
        let listener = StdTcpListener::from(descriptor);
        listener
            .set_nonblocking(true)
            .map_err(RouteIngressError::Io)?;
        let listener = TcpListener::from_std(listener).map_err(RouteIngressError::Io)?;
        Self::new(listener, claim, registry)
    }

    pub(crate) fn new(
        listener: TcpListener,
        claim: RouteClaim,
        registry: RouteRegistry,
    ) -> Result<Self, RouteIngressError> {
        let local_addr = listener.local_addr().map_err(RouteIngressError::Io)?;
        if !local_addr.ip().is_loopback() || local_addr.port() == 0 {
            return Err(RouteIngressError::InvalidLocalAddress(local_addr));
        }
        Ok(Self {
            listener,
            local_addr,
            claim,
            registry,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn accept<F>(&self, now: F) -> Result<AcceptedRouteIngress, RouteIngressError>
    where
        F: FnOnce() -> MonotonicMillis,
    {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(RouteIngressError::Io)?;
        let accepted_at = now();
        let guard = self
            .registry
            .begin_ingress(&self.claim, accepted_at)
            .map_err(RouteIngressError::Route)?;
        Ok(AcceptedRouteIngress {
            stream,
            guard,
            accepted_at,
        })
    }
}

#[derive(Debug)]
pub struct AcceptedRouteIngress {
    stream: TcpStream,
    guard: RouteIngressGuard,
    accepted_at: MonotonicMillis,
}

impl AcceptedRouteIngress {
    pub(crate) fn into_parts(self) -> (TcpStream, RouteIngressGuard, MonotonicMillis) {
        (self.stream, self.guard, self.accepted_at)
    }
}

#[derive(Debug)]
pub enum RouteIngressError {
    InvalidLocalAddress(SocketAddr),
    InvalidDescriptor(io::Error),
    MissingCloseOnExec,
    NotStreamSocket,
    NotListeningSocket,
    Io(io::Error),
    Route(RouteError),
}

impl fmt::Display for RouteIngressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLocalAddress(address) => {
                write!(
                    formatter,
                    "route ingress listener is not explicit loopback: {address}"
                )
            }
            Self::InvalidDescriptor(error) => {
                write!(formatter, "route ingress descriptor is invalid: {error}")
            }
            Self::MissingCloseOnExec => {
                write!(formatter, "route ingress descriptor is missing CLOEXEC")
            }
            Self::NotStreamSocket => {
                write!(formatter, "route ingress descriptor is not a stream socket")
            }
            Self::NotListeningSocket => {
                write!(
                    formatter,
                    "route ingress descriptor is not a listening socket"
                )
            }
            Self::Io(error) => write!(formatter, "route ingress listener I/O failed: {error}"),
            Self::Route(error) => write!(formatter, "route ingress rejected: {error:?}"),
        }
    }
}

impl std::error::Error for RouteIngressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDescriptor(error) | Self::Io(error) => Some(error),
            Self::InvalidLocalAddress(_)
            | Self::MissingCloseOnExec
            | Self::NotStreamSocket
            | Self::NotListeningSocket
            | Self::Route(_) => None,
        }
    }
}
