#![forbid(unsafe_code)]

//! Authenticated installation of one sandbox-created egress listener.
//!
//! The metadata frame is deliberately separate from the descriptor handoff:
//! the server authenticates the connected Unix peer and validates the complete
//! immutable request before it tells the client that it may send a capability.

use std::net::SocketAddr;
use std::os::fd::OwnedFd;

use browserd_core::{EgressFence, LeaseId};
use browserd_local_ipc::{CoordinatorAccepted, DescriptorCount, HandoffError, Receiver, Sender};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Maximum JSON payload size for both protocol messages.
pub const MAX_CONTROL_FRAME_BYTES: usize = 4 * 1024;

const LENGTH_BYTES: usize = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    transfer_id: LeaseId,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    binding_digest: [u8; 32],
    prepare_revision: u64,
}

impl InstallRequest {
    pub fn new(
        transfer_id: LeaseId,
        daemon_epoch: u64,
        egress_fence: EgressFence,
        binding_digest: [u8; 32],
        prepare_revision: u64,
    ) -> Result<Self, WireValidationError> {
        let request = Self {
            transfer_id,
            daemon_epoch,
            egress_fence,
            binding_digest,
            prepare_revision,
        };
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub const fn transfer_id(&self) -> &LeaseId {
        &self.transfer_id
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }

    #[must_use]
    pub const fn prepare_revision(&self) -> u64 {
        self.prepare_revision
    }

    fn validate(&self) -> Result<(), WireValidationError> {
        if self.daemon_epoch == 0 {
            return Err(WireValidationError::ZeroDaemonEpoch);
        }
        if self.binding_digest == [0; 32] {
            return Err(WireValidationError::ZeroBindingDigest);
        }
        if self.prepare_revision == 0 {
            return Err(WireValidationError::ZeroPrepareRevision);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveInstallResponse {
    transfer_id: LeaseId,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    proxy_address: SocketAddr,
    expires_at_millis: u64,
    activation_revision: u64,
}

impl ActiveInstallResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transfer_id: LeaseId,
        daemon_epoch: u64,
        egress_fence: EgressFence,
        attachment_id: u64,
        proxy_address: SocketAddr,
        expires_at_millis: u64,
        activation_revision: u64,
    ) -> Result<Self, WireValidationError> {
        let response = Self {
            transfer_id,
            daemon_epoch,
            egress_fence,
            attachment_id,
            proxy_address,
            expires_at_millis,
            activation_revision,
        };
        response.validate()?;
        Ok(response)
    }

    #[must_use]
    pub const fn transfer_id(&self) -> &LeaseId {
        &self.transfer_id
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> u64 {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    #[must_use]
    pub const fn attachment_id(&self) -> u64 {
        self.attachment_id
    }

    #[must_use]
    pub const fn proxy_address(&self) -> SocketAddr {
        self.proxy_address
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    #[must_use]
    pub const fn activation_revision(&self) -> u64 {
        self.activation_revision
    }

    fn validate(&self) -> Result<(), WireValidationError> {
        if self.daemon_epoch == 0 {
            return Err(WireValidationError::ZeroDaemonEpoch);
        }
        if self.attachment_id == 0 {
            return Err(WireValidationError::ZeroAttachmentId);
        }
        if !self.proxy_address.ip().is_loopback() || self.proxy_address.port() == 0 {
            return Err(WireValidationError::InvalidProxyAddress(self.proxy_address));
        }
        if self.expires_at_millis == 0 {
            return Err(WireValidationError::ZeroExpiry);
        }
        if self.activation_revision == 0 {
            return Err(WireValidationError::ZeroActivationRevision);
        }
        Ok(())
    }

    fn validate_for(&self, request: &InstallRequest) -> Result<(), ResponseMismatch> {
        if self.transfer_id != request.transfer_id {
            return Err(ResponseMismatch::TransferId);
        }
        if self.daemon_epoch != request.daemon_epoch {
            return Err(ResponseMismatch::DaemonEpoch);
        }
        if self.egress_fence != request.egress_fence {
            return Err(ResponseMismatch::EgressFence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireValidationError {
    #[error("daemon epoch must be nonzero")]
    ZeroDaemonEpoch,
    #[error("prepare revision must be nonzero")]
    ZeroPrepareRevision,
    #[error("binding digest must be nonzero")]
    ZeroBindingDigest,
    #[error("attachment ID must be nonzero")]
    ZeroAttachmentId,
    #[error("proxy address must be a nonzero loopback socket address: {0}")]
    InvalidProxyAddress(SocketAddr),
    #[error("attachment expiry must be nonzero")]
    ZeroExpiry,
    #[error("activation revision must be nonzero")]
    ZeroActivationRevision,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResponseMismatch {
    #[error("active response transfer ID does not match the install request")]
    TransferId,
    #[error("active response daemon epoch does not match the install request")]
    DaemonEpoch,
    #[error("active response egress fence does not match the install request")]
    EgressFence,
}

#[derive(Debug, Error)]
pub enum ControlFrameError {
    #[error("control frame I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control frame cannot be empty")]
    Empty,
    #[error("control frame has {actual} bytes, exceeding the {maximum}-byte limit")]
    TooLarge { actual: usize, maximum: usize },
    #[error("control frame JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum ReceiveInstallError {
    #[error("could not authenticate the Unix peer: {0}")]
    PeerCredentials(#[source] std::io::Error),
    #[error("Unix peer UID mismatch: expected {expected}, received {received}")]
    PeerUidMismatch { expected: u32, received: u32 },
    #[error("install metadata was rejected: {0}")]
    Metadata(#[from] ControlFrameError),
    #[error("install metadata failed validation: {0}")]
    Validation(#[from] WireValidationError),
    #[error("listener descriptor handoff failed: {0}")]
    Handoff(#[from] HandoffError),
    #[error("listener capability could not be cloned: {0}")]
    Clone(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ClientInstallError {
    #[error("listener installation failed before the server committed: {0}")]
    BeforeCommit(#[source] ClientProtocolError),
    #[error("the server committed the listener installation, but confirmation was lost: {0}")]
    CommittedButUnconfirmed(#[source] ClientProtocolError),
    #[error(
        "the server committed the listener installation, but returned an invalid response: {0}"
    )]
    CommittedWithInvalidResponse(#[source] CommittedResponseError),
}

impl ClientInstallError {
    #[must_use]
    pub const fn commit_was_observed(&self) -> bool {
        !matches!(self, Self::BeforeCommit(_))
    }

    #[must_use]
    pub const fn requires_status_reconciliation(&self) -> bool {
        self.commit_was_observed()
    }
}

#[derive(Debug, Error)]
pub enum ClientProtocolError {
    #[error("control frame failed: {0}")]
    Frame(#[from] ControlFrameError),
    #[error("descriptor handoff failed: {0}")]
    Handoff(#[from] HandoffError),
}

#[derive(Debug, Error)]
pub enum CommittedResponseError {
    #[error("active response failed validation: {0}")]
    Validation(#[from] WireValidationError),
    #[error("active response correlation failed: {0}")]
    Mismatch(#[from] ResponseMismatch),
}

#[derive(Debug, Error)]
pub enum ServerCommitError {
    #[error("active response failed validation before commit: {0}")]
    InvalidResponse(#[from] WireValidationError),
    #[error("active response does not match the pending install: {0}")]
    ResponseMismatch(#[from] ResponseMismatch),
    #[error("the listener install commit could not be announced: {0}")]
    BeforeAnnouncement(#[source] HandoffError),
    #[error("the install was committed, but the peer did not complete the handoff: {0}")]
    CommittedButUnconfirmed(#[source] HandoffError),
    #[error("the install was committed, but the active response was lost: {0}")]
    ResponseLost(#[source] ControlFrameError),
}

impl ServerCommitError {
    #[must_use]
    pub const fn commit_was_announced(&self) -> bool {
        matches!(
            self,
            Self::CommittedButUnconfirmed(_) | Self::ResponseLost(_)
        )
    }
}

/// A validated request plus the receiver's owned listener clone.
///
/// The descriptor handoff also retains its protocol-owned copy until the final
/// completion marker. Dropping this value before [`Self::commit`] closes both
/// receiver-owned copies and causes the client to fail before observing commit.
#[derive(Debug)]
pub struct PendingInstall {
    request: InstallRequest,
    listener: Option<OwnedFd>,
    receiver: Receiver<CoordinatorAccepted>,
}

/// Authenticated, syntactically valid metadata awaiting domain authorization.
///
/// Dropping this value rejects the request before the receiver announces that
/// it is ready for the listener capability.
#[derive(Debug)]
pub struct PendingListenerOffer {
    request: InstallRequest,
    stream: UnixStream,
}

impl PendingListenerOffer {
    #[must_use]
    pub const fn request(&self) -> &InstallRequest {
        &self.request
    }

    /// Accepts exactly one listener after the caller has authorized the full
    /// immutable request against its domain state.
    pub async fn receive_listener(self) -> Result<PendingInstall, ReceiveInstallError> {
        let expected_count = DescriptorCount::new(1)?;
        let receiver = Receiver::new(
            self.stream,
            self.request.transfer_id.clone(),
            expected_count,
        );
        let ready = receiver.ready().await?;
        let offered = ready.receive().await?;
        let mut listener_clones = offered
            .try_clone_descriptors()
            .map_err(ReceiveInstallError::Clone)?;
        let listener = listener_clones.pop();
        let accepted = offered.accept().await?;
        let receiver = accepted.into_coordinator().await?;
        Ok(PendingInstall {
            request: self.request,
            listener,
            receiver,
        })
    }
}

impl PendingInstall {
    #[must_use]
    pub const fn request(&self) -> &InstallRequest {
        &self.request
    }

    #[must_use]
    pub fn listener(&self) -> Option<&OwnedFd> {
        self.listener.as_ref()
    }

    /// Transfers the validated domain-owned listener clone to the installer.
    ///
    /// The handoff protocol keeps its separate copy until [`Self::commit`]
    /// completes, so taking this value does not weaken the two-phase transfer.
    pub fn take_listener(&mut self) -> Option<OwnedFd> {
        self.listener.take()
    }

    pub async fn commit(
        self,
        response: ActiveInstallResponse,
    ) -> Result<ActiveInstallResponse, ServerCommitError> {
        response.validate()?;
        response.validate_for(&self.request)?;

        let committed = self
            .receiver
            .commit()
            .await
            .map_err(ServerCommitError::BeforeAnnouncement)?;
        let receipted = committed
            .await_receipt()
            .await
            .map_err(ServerCommitError::CommittedButUnconfirmed)?;
        let complete = receipted
            .complete()
            .await
            .map_err(ServerCommitError::CommittedButUnconfirmed)?;
        let (mut stream, protocol_descriptors) = complete.into_parts();
        drop(protocol_descriptors);

        write_json_frame(&mut stream, &response)
            .await
            .map_err(ServerCommitError::ResponseLost)?;
        Ok(response)
    }
}

/// Sends one listener capability and waits for the correlated active receipt.
pub async fn send_listener(
    mut stream: UnixStream,
    request: InstallRequest,
    listener: OwnedFd,
) -> Result<ActiveInstallResponse, ClientInstallError> {
    request.validate().map_err(|error| {
        ClientInstallError::BeforeCommit(ClientProtocolError::Frame(ControlFrameError::Json(
            serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidInput, error)),
        )))
    })?;
    write_json_frame(&mut stream, &request)
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;

    let sender = Sender::new(stream, request.transfer_id.clone(), vec![listener])
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;
    let ready = sender
        .await_ready()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;
    let offered = ready
        .offer()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;
    let accepted = offered
        .await_accepted()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;
    let follower = accepted
        .into_follower()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;
    let committed = follower
        .await_committed()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::BeforeCommit)?;
    let receipted = committed
        .receipt()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::CommittedButUnconfirmed)?;
    let complete = receipted
        .await_complete()
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::CommittedButUnconfirmed)?;
    let mut stream = complete.into_stream();
    let response: ActiveInstallResponse = read_json_frame(&mut stream)
        .await
        .map_err(ClientProtocolError::from)
        .map_err(ClientInstallError::CommittedButUnconfirmed)?;
    response
        .validate()
        .map_err(CommittedResponseError::from)
        .map_err(ClientInstallError::CommittedWithInvalidResponse)?;
    response
        .validate_for(&request)
        .map_err(CommittedResponseError::from)
        .map_err(ClientInstallError::CommittedWithInvalidResponse)?;
    Ok(response)
}

/// Authenticates and receives exactly one listener capability.
pub async fn receive_listener(
    stream: UnixStream,
    expected_peer_uid: u32,
) -> Result<PendingInstall, ReceiveInstallError> {
    receive_install_request(stream, expected_peer_uid)
        .await?
        .receive_listener()
        .await
}

/// Authenticates the Unix peer and validates the bounded metadata frame
/// without announcing readiness for any descriptor.
pub async fn receive_install_request(
    mut stream: UnixStream,
    expected_peer_uid: u32,
) -> Result<PendingListenerOffer, ReceiveInstallError> {
    let peer = stream
        .peer_cred()
        .map_err(ReceiveInstallError::PeerCredentials)?;
    if peer.uid() != expected_peer_uid {
        return Err(ReceiveInstallError::PeerUidMismatch {
            expected: expected_peer_uid,
            received: peer.uid(),
        });
    }

    let request: InstallRequest = read_json_frame(&mut stream).await?;
    request.validate()?;
    Ok(PendingListenerOffer { request, stream })
}

async fn write_json_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
) -> Result<(), ControlFrameError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() {
        return Err(ControlFrameError::Empty);
    }
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::TooLarge {
            actual: payload.len(),
            maximum: MAX_CONTROL_FRAME_BYTES,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| ControlFrameError::TooLarge {
        actual: payload.len(),
        maximum: MAX_CONTROL_FRAME_BYTES,
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

async fn read_json_frame<T: DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<T, ControlFrameError> {
    let mut length = [0_u8; LENGTH_BYTES];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(ControlFrameError::Empty);
    }
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::TooLarge {
            actual: length,
            maximum: MAX_CONTROL_FRAME_BYTES,
        });
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(test)]
mod tests;
