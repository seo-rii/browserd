use std::io::IoSlice;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use browserd_core::{LeaseId, ShardId, WorkerId};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::sync::CancellationToken;

use crate::{
    ChromiumCdpPipes, CleanupReason, CreateShardOutcome, InspectResources, KillShardOutcome,
    LaunchSpec, RenewLeaseError, SandboxBackend, SandboxError, SandboxSupervisor, WorkerOwnership,
};

const CLIENT_DESCRIPTOR_READY: u8 = 0x51;
const DESCRIPTOR_OFFER: u8 = 0x52;
const CLIENT_DESCRIPTOR_ACCEPTED: u8 = 0x53;
const DESCRIPTOR_COMMITTED: u8 = 0x54;
const CLIENT_FINAL_RECEIPT: u8 = 0x55;
const DESCRIPTOR_HANDOFF_COMPLETE: u8 = 0x56;
const HANDOFF_FRAME_BYTES: usize = 17;
const SCM_RIGHTS_MAX_FDS: usize = 253;
const _: () = assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<nix::libc::cmsghdr>());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxRpcConfig {
    max_frame_bytes: usize,
    max_connections: usize,
    request_timeout: Duration,
    lease_sweep_interval: Duration,
    allowed_uid: Option<u32>,
}

impl SandboxRpcConfig {
    pub fn new(
        max_frame_bytes: usize,
        max_connections: usize,
        request_timeout: Duration,
        lease_sweep_interval: Duration,
        allowed_uid: Option<u32>,
    ) -> Result<Self, SandboxRpcError> {
        if max_frame_bytes == 0
            || max_connections == 0
            || request_timeout.is_zero()
            || lease_sweep_interval.is_zero()
            || lease_sweep_interval > request_timeout
            || allowed_uid.is_none()
        {
            return Err(SandboxRpcError::InvalidConfig);
        }
        Ok(Self {
            max_frame_bytes,
            max_connections,
            request_timeout,
            lease_sweep_interval,
            allowed_uid,
        })
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcFailureCode {
    InvalidLease,
    MissingCapability,
    OwnershipMismatch,
    ShardNotFound,
    WorkerEpochMismatch,
    LeaseExpired,
    CdpClaimInProgress,
    CdpPipesAlreadyClaimed,
    IncompleteCleanup,
    Backend,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RpcFailure {
    code: RpcFailureCode,
    message: String,
}

impl From<SandboxError> for RpcFailure {
    fn from(error: SandboxError) -> Self {
        let code = match error {
            SandboxError::ZeroLeaseTtl
            | SandboxError::ZeroCleanupTimeout
            | SandboxError::InvalidLeaseOrdering
            | SandboxError::InvalidOwnerLease => RpcFailureCode::InvalidLease,
            SandboxError::MissingCapability { .. } => RpcFailureCode::MissingCapability,
            SandboxError::OwnershipMismatch => RpcFailureCode::OwnershipMismatch,
            SandboxError::ShardNotFound => RpcFailureCode::ShardNotFound,
            SandboxError::WorkerEpochMismatch { .. } => RpcFailureCode::WorkerEpochMismatch,
            SandboxError::IncompleteCleanup { .. } => RpcFailureCode::IncompleteCleanup,
            SandboxError::CdpClaimInProgress => RpcFailureCode::CdpClaimInProgress,
            SandboxError::CdpPipesAlreadyClaimed => RpcFailureCode::CdpPipesAlreadyClaimed,
            SandboxError::Backend(_) => RpcFailureCode::Backend,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

impl From<RenewLeaseError> for RpcFailure {
    fn from(error: RenewLeaseError) -> Self {
        let code = match error {
            RenewLeaseError::ShardNotFound => RpcFailureCode::ShardNotFound,
            RenewLeaseError::WorkerEpochMismatch { .. } => RpcFailureCode::WorkerEpochMismatch,
            RenewLeaseError::LeaseExpired => RpcFailureCode::LeaseExpired,
            RenewLeaseError::InvalidNewExpiry => RpcFailureCode::InvalidLease,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum RpcRequest {
    CreateShard {
        shard_id: ShardId,
        worker_id: WorkerId,
        worker_epoch: u64,
        lease_ttl_ms: u64,
    },
    RenewOwnerLease {
        shard_id: ShardId,
        worker_epoch: u64,
        lease_ttl_ms: u64,
    },
    KillShard {
        shard_id: ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    },
    InspectResources {
        shard_id: ShardId,
        worker_epoch: u64,
    },
    ClaimCdpPipes {
        shard_id: ShardId,
        worker_id: WorkerId,
        worker_epoch: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", content = "value", rename_all = "snake_case")]
enum RpcSuccess {
    CreateShard(CreateShardOutcome),
    Renewed,
    KillShard(KillShardOutcome),
    InspectResources(InspectResources),
    CdpPipesReady { transfer_id: LeaseId },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
enum RpcResponse {
    Success(RpcSuccess),
    Failure(RpcFailure),
}

#[derive(Clone, Debug)]
pub struct SandboxRpcClient {
    socket_path: PathBuf,
    max_frame_bytes: usize,
    request_timeout: Duration,
}

impl SandboxRpcClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        max_frame_bytes: usize,
        request_timeout: Duration,
    ) -> Result<Self, SandboxRpcError> {
        let socket_path = socket_path.into();
        if !socket_path.is_absolute() || max_frame_bytes == 0 || request_timeout.is_zero() {
            return Err(SandboxRpcError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            max_frame_bytes,
            request_timeout,
        })
    }

    pub async fn create_shard(
        &self,
        spec: LaunchSpec,
        lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, SandboxRpcError> {
        let lease_ttl_ms =
            u64::try_from(lease_ttl.as_millis()).map_err(|_| SandboxRpcError::InvalidLease)?;
        if lease_ttl_ms == 0 {
            return Err(SandboxRpcError::InvalidLease);
        }
        let response = self
            .exchange(RpcRequest::CreateShard {
                shard_id: spec.shard_id,
                worker_id: spec.worker_id,
                worker_epoch: spec.worker_epoch,
                lease_ttl_ms,
            })
            .await?;
        match response {
            RpcSuccess::CreateShard(outcome) => Ok(outcome),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn renew_owner_lease(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        lease_ttl: Duration,
    ) -> Result<(), SandboxRpcError> {
        let lease_ttl_ms =
            u64::try_from(lease_ttl.as_millis()).map_err(|_| SandboxRpcError::InvalidLease)?;
        if lease_ttl_ms == 0 {
            return Err(SandboxRpcError::InvalidLease);
        }
        let response = self
            .exchange(RpcRequest::RenewOwnerLease {
                shard_id: shard_id.clone(),
                worker_epoch,
                lease_ttl_ms,
            })
            .await?;
        match response {
            RpcSuccess::Renewed => Ok(()),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, SandboxRpcError> {
        let response = self
            .exchange(RpcRequest::KillShard {
                shard_id: shard_id.clone(),
                worker_epoch,
                reason,
            })
            .await?;
        match response {
            RpcSuccess::KillShard(outcome) => Ok(outcome),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn inspect_resources(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
    ) -> Result<InspectResources, SandboxRpcError> {
        let response = self
            .exchange(RpcRequest::InspectResources {
                shard_id: shard_id.clone(),
                worker_epoch,
            })
            .await?;
        match response {
            RpcSuccess::InspectResources(resources) => Ok(resources),
            _ => Err(SandboxRpcError::Protocol),
        }
    }

    pub async fn claim_cdp_pipes(
        &self,
        shard_id: &ShardId,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<ChromiumCdpPipes, SandboxRpcError> {
        let operation = async {
            let stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(self.max_frame_bytes)
                .new_codec();
            let mut framed = Framed::new(stream, codec);
            let encoded = serde_json::to_vec(&RpcRequest::ClaimCdpPipes {
                shard_id: shard_id.clone(),
                worker_id: worker_id.clone(),
                worker_epoch,
            })
            .map_err(|error| SandboxRpcError::Serialization(error.to_string()))?;
            if encoded.len() > self.max_frame_bytes {
                return Err(SandboxRpcError::FrameTooLarge);
            }
            framed
                .send(Bytes::from(encoded))
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let response = framed
                .next()
                .await
                .ok_or(SandboxRpcError::ConnectionClosed)?
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let transfer_id = match serde_json::from_slice::<RpcResponse>(&response)
                .map_err(|error| SandboxRpcError::Serialization(error.to_string()))?
            {
                RpcResponse::Success(RpcSuccess::CdpPipesReady { transfer_id }) => transfer_id,
                RpcResponse::Success(_) => return Err(SandboxRpcError::Protocol),
                RpcResponse::Failure(failure) => {
                    return Err(SandboxRpcError::Remote {
                        code: failure.code,
                        message: failure.message,
                    });
                }
            };
            let cleanup_client = self.clone();
            let cleanup_shard_id = shard_id.clone();
            let cleanup_window = self
                .request_timeout
                .saturating_mul(4)
                .max(Duration::from_millis(100));
            let (handoff_completed, handoff_completion) = oneshot::channel();
            tokio::spawn(async move {
                if handoff_completion.await.is_ok() {
                    return;
                }
                let cleanup_deadline = Instant::now() + cleanup_window;
                loop {
                    match cleanup_client
                        .kill_shard(
                            &cleanup_shard_id,
                            worker_epoch,
                            CleanupReason::BrowserFailure,
                        )
                        .await
                    {
                        Ok(
                            KillShardOutcome::Terminated(_) | KillShardOutcome::AlreadyTerminated,
                        )
                        | Err(SandboxRpcError::Remote {
                            code:
                                RpcFailureCode::ShardNotFound | RpcFailureCode::WorkerEpochMismatch,
                            ..
                        }) => return,
                        Ok(
                            KillShardOutcome::CleanupIncomplete(_)
                            | KillShardOutcome::CancellationRequested,
                        ) if Instant::now() < cleanup_deadline => {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Err(_) if Instant::now() < cleanup_deadline => {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Ok(_) | Err(_) => return,
                    }
                }
            });
            let parts = framed.into_parts();
            if !parts.read_buf.is_empty() || !parts.write_buf.is_empty() {
                return Err(SandboxRpcError::Protocol);
            }
            let mut stream = parts.io;
            let mut ready = [0_u8; HANDOFF_FRAME_BYTES];
            ready[0] = CLIENT_DESCRIPTOR_READY;
            ready[1..].copy_from_slice(transfer_id.as_bytes());
            stream
                .write_all(&ready)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;

            let (
                marker,
                bytes,
                flags,
                rights_messages,
                unexpected_control,
                invalid_control,
                descriptors,
            ) = stream
                .async_io(Interest::READABLE, || {
                    let mut marker = [0_u8; 1];
                    let required_control_bytes =
                        nix::cmsg_space!([RawFd; SCM_RIGHTS_MAX_FDS]).len();
                    let mut control = vec![
                        0_usize;
                        required_control_bytes
                            .div_ceil(std::mem::size_of::<usize>())
                    ];
                    let control_capacity =
                        control.len().saturating_mul(std::mem::size_of::<usize>());
                    let mut buffer = nix::libc::iovec {
                        iov_base: marker.as_mut_ptr().cast(),
                        iov_len: marker.len(),
                    };
                    // SAFETY: every pointer installed below remains valid for the recvmsg call.
                    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
                    message.msg_iov = &raw mut buffer;
                    message.msg_iovlen = 1;
                    message.msg_control = control.as_mut_ptr().cast();
                    message.msg_controllen = control_capacity;
                    // SAFETY: the nonblocking Unix socket and all msghdr buffers are valid, and
                    // MSG_CMSG_CLOEXEC atomically protects every installed descriptor.
                    let bytes = unsafe {
                        nix::libc::recvmsg(
                            stream.as_raw_fd(),
                            &raw mut message,
                            nix::libc::MSG_DONTWAIT | nix::libc::MSG_CMSG_CLOEXEC,
                        )
                    };
                    if bytes < 0 {
                        return Err(std::io::Error::last_os_error());
                    }

                    let flags = MsgFlags::from_bits_truncate(message.msg_flags);
                    let control_start = control.as_ptr() as usize;
                    let control_end =
                        control_start.saturating_add(message.msg_controllen.min(control_capacity));
                    let mut rights_messages = 0_usize;
                    let mut unexpected_control = false;
                    let mut invalid_control = false;
                    let mut descriptors: Vec<OwnedFd> = Vec::new();
                    // SAFETY: message describes the initialized control buffer returned by the
                    // kernel. Each header is bounds-checked before its payload is inspected.
                    let mut control_message = unsafe { nix::libc::CMSG_FIRSTHDR(&message) };
                    while !control_message.is_null() {
                        let header_address = control_message as usize;
                        let Some(header_end) =
                            header_address.checked_add(std::mem::size_of::<nix::libc::cmsghdr>())
                        else {
                            invalid_control = true;
                            break;
                        };
                        if header_address < control_start || header_end > control_end {
                            invalid_control = true;
                            break;
                        }
                        // SAFETY: the complete cmsghdr lies inside the returned control buffer.
                        let header = unsafe { &*control_message };
                        // SAFETY: a zero-length payload is valid and only asks libc for the
                        // platform header size.
                        let minimum_length = unsafe { nix::libc::CMSG_LEN(0) as usize };
                        if header.cmsg_len < minimum_length
                            || header.cmsg_len > control_end.saturating_sub(header_address)
                        {
                            invalid_control = true;
                            break;
                        }
                        if header.cmsg_level == nix::libc::SOL_SOCKET
                            && header.cmsg_type == nix::libc::SCM_RIGHTS
                        {
                            rights_messages += 1;
                            let payload_bytes = header.cmsg_len - minimum_length;
                            if !payload_bytes.is_multiple_of(std::mem::size_of::<RawFd>()) {
                                invalid_control = true;
                            }
                            let descriptor_count = payload_bytes / std::mem::size_of::<RawFd>();
                            // SAFETY: CMSG_DATA points at the bounds-checked payload. Unaligned
                            // reads are used because cmsghdr payload alignment is platform-owned.
                            let descriptor_data =
                                unsafe { nix::libc::CMSG_DATA(control_message) }.cast::<RawFd>();
                            for index in 0..descriptor_count {
                                // SAFETY: the index is bounded by the complete payload length.
                                let raw_descriptor =
                                    unsafe { descriptor_data.add(index).read_unaligned() };
                                if raw_descriptor < 0
                                    || descriptors
                                        .iter()
                                        .any(|descriptor| descriptor.as_raw_fd() == raw_descriptor)
                                {
                                    invalid_control = true;
                                    continue;
                                }
                                // SAFETY: recvmsg installed this SCM_RIGHTS descriptor into this
                                // process and ownership transfers exactly once to the receiver.
                                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw_descriptor) });
                            }
                        } else {
                            unexpected_control = true;
                        }
                        // SAFETY: CMSG_NXTHDR validates alignment and remaining message bounds.
                        let next = unsafe { nix::libc::CMSG_NXTHDR(&message, control_message) };
                        if next == control_message {
                            invalid_control = true;
                            break;
                        }
                        control_message = next;
                    }
                    Ok((
                        marker[0],
                        bytes as usize,
                        flags,
                        rights_messages,
                        unexpected_control,
                        invalid_control,
                        descriptors,
                    ))
                })
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            if marker != DESCRIPTOR_OFFER
                || bytes != 1
                || flags.intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC)
                || rights_messages != 1
                || unexpected_control
                || invalid_control
                || descriptors.len() != 2
            {
                return Err(SandboxRpcError::Protocol);
            }
            let mut descriptors = descriptors.into_iter();
            let command_writer = descriptors.next().ok_or(SandboxRpcError::Protocol)?;
            let event_reader = descriptors.next().ok_or(SandboxRpcError::Protocol)?;
            let pipes = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
                .map_err(|error| SandboxRpcError::InvalidCapabilities(error.to_string()))?;

            let mut offer_challenge = [0_u8; 16];
            stream
                .read_exact(&mut offer_challenge)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let mut accepted = [0_u8; HANDOFF_FRAME_BYTES];
            accepted[0] = CLIENT_DESCRIPTOR_ACCEPTED;
            accepted[1..].copy_from_slice(&offer_challenge);
            stream
                .write_all(&accepted)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;

            let mut committed = [0_u8; HANDOFF_FRAME_BYTES];
            stream
                .read_exact(&mut committed)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            if committed[0] != DESCRIPTOR_COMMITTED {
                return Err(SandboxRpcError::Protocol);
            }
            let mut final_receipt = committed;
            final_receipt[0] = CLIENT_FINAL_RECEIPT;
            stream
                .write_all(&final_receipt)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let mut completed = [0_u8; HANDOFF_FRAME_BYTES];
            stream
                .read_exact(&mut completed)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            if completed[0] != DESCRIPTOR_HANDOFF_COMPLETE || completed[1..] != committed[1..] {
                return Err(SandboxRpcError::Protocol);
            }
            let _ = handoff_completed.send(());
            Ok(pipes)
        };
        tokio::time::timeout(self.request_timeout, operation)
            .await
            .map_err(|_| SandboxRpcError::TimedOut)?
    }

    async fn exchange(&self, request: RpcRequest) -> Result<RpcSuccess, SandboxRpcError> {
        let operation = async {
            let stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(self.max_frame_bytes)
                .new_codec();
            let mut framed = Framed::new(stream, codec);
            let encoded = serde_json::to_vec(&request)
                .map_err(|error| SandboxRpcError::Serialization(error.to_string()))?;
            if encoded.len() > self.max_frame_bytes {
                return Err(SandboxRpcError::FrameTooLarge);
            }
            framed
                .send(Bytes::from(encoded))
                .await
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            let response = framed
                .next()
                .await
                .ok_or(SandboxRpcError::ConnectionClosed)?
                .map_err(|error| SandboxRpcError::Io(error.to_string()))?;
            serde_json::from_slice::<RpcResponse>(&response)
                .map_err(|error| SandboxRpcError::Serialization(error.to_string()))
        };
        let response = tokio::time::timeout(self.request_timeout, operation)
            .await
            .map_err(|_| SandboxRpcError::TimedOut)??;
        match response {
            RpcResponse::Success(success) => Ok(success),
            RpcResponse::Failure(failure) => Err(SandboxRpcError::Remote {
                code: failure.code,
                message: failure.message,
            }),
        }
    }
}

pub struct SandboxRpcServer<B> {
    supervisor: Arc<SandboxSupervisor<B>>,
    config: SandboxRpcConfig,
}

impl<B> SandboxRpcServer<B>
where
    B: SandboxBackend,
{
    #[must_use]
    pub fn new(supervisor: Arc<SandboxSupervisor<B>>, config: SandboxRpcConfig) -> Self {
        Self { supervisor, config }
    }

    pub async fn serve(
        self,
        listener: UnixListener,
        shutdown: CancellationToken,
    ) -> Result<(), SandboxRpcError> {
        let permits = Arc::new(Semaphore::new(self.config.max_connections));
        let sweeper_supervisor = Arc::clone(&self.supervisor);
        let sweeper_shutdown = CancellationToken::new();
        let sweeper_task_shutdown = sweeper_shutdown.clone();
        let sweep_interval = self.config.lease_sweep_interval;
        let sweeper = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval_at(Instant::now() + sweep_interval, sweep_interval);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = sweeper_task_shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let _expired = sweeper_supervisor.expire_leases(Instant::now()).await;
                    }
                }
            }
        });
        let mut connections = JoinSet::new();
        let terminal = loop {
            tokio::select! {
                () = shutdown.cancelled() => break Ok(()),
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    if joined.is_err() {
                        break Err(SandboxRpcError::ConnectionTaskFailed);
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _address) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => break Err(SandboxRpcError::Io(error.to_string())),
                    };
                    if let Some(allowed_uid) = self.config.allowed_uid {
                        let peer = match stream.peer_cred() {
                            Ok(peer) => peer,
                            Err(_) => continue,
                        };
                        if peer.uid() != allowed_uid {
                            continue;
                        }
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let supervisor = Arc::clone(&self.supervisor);
                    let config = self.config;
                    connections.spawn(async move {
                        let _permit = permit;
                        let codec = LengthDelimitedCodec::builder()
                            .max_frame_length(config.max_frame_bytes)
                            .new_codec();
                        let mut framed = Framed::new(stream, codec);
                        let request = match tokio::time::timeout(
                            config.request_timeout,
                            framed.next(),
                        )
                        .await
                        {
                            Ok(Some(Ok(request))) => request,
                            Ok(Some(Err(_))) | Ok(None) | Err(_) => return,
                        };
                        let Ok(request) = serde_json::from_slice::<RpcRequest>(&request) else {
                            return;
                        };
                        let request = match request {
                            RpcRequest::ClaimCdpPipes {
                                shard_id,
                                worker_id,
                                worker_epoch,
                            } => {
                                let handoff = async {
                                    let pending = match supervisor
                                        .prepare_cdp_pipes(
                                            &shard_id,
                                            &worker_id,
                                            worker_epoch,
                                        )
                                        .await
                                    {
                                        Ok(pending) => pending,
                                        Err(error) => {
                                            let failure = match error {
                                                SandboxError::InvalidOwnerLease => RpcFailure {
                                                    code: RpcFailureCode::LeaseExpired,
                                                    message: SandboxError::InvalidOwnerLease
                                                        .to_string(),
                                                },
                                                error => error.into(),
                                            };
                                            let response = RpcResponse::Failure(failure);
                                            let response = serde_json::to_vec(&response).map_err(
                                                |error| {
                                                    SandboxRpcError::Serialization(
                                                        error.to_string(),
                                                    )
                                                },
                                            )?;
                                            if response.len() > config.max_frame_bytes {
                                                return Err(SandboxRpcError::FrameTooLarge);
                                            }
                                            framed
                                                .send(Bytes::from(response))
                                                .await
                                                .map_err(|error| {
                                                    SandboxRpcError::Io(error.to_string())
                                                })?;
                                            return Ok(());
                                        }
                                    };
                                    let claim_completed = supervisor
                                        .start_cdp_claim_cleanup_guard(&shard_id, worker_epoch);
                                    let transfer_id = pending.transfer_id().clone();
                                    let response = RpcResponse::Success(
                                        RpcSuccess::CdpPipesReady {
                                            transfer_id: transfer_id.clone(),
                                        },
                                    );
                                    let response = serde_json::to_vec(&response).map_err(|error| {
                                        SandboxRpcError::Serialization(error.to_string())
                                    })?;
                                    if response.len() > config.max_frame_bytes {
                                        return Err(SandboxRpcError::FrameTooLarge);
                                    }
                                    framed
                                        .send(Bytes::from(response))
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    let parts = framed.into_parts();
                                    if !parts.read_buf.is_empty() || !parts.write_buf.is_empty() {
                                        return Err(SandboxRpcError::Protocol);
                                    }
                                    let mut stream = parts.io;
                                    let mut ready = [0_u8; HANDOFF_FRAME_BYTES];
                                    stream
                                        .read_exact(&mut ready)
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    if ready[0] != CLIENT_DESCRIPTOR_READY
                                        || ready[1..] != transfer_id.as_bytes()[..]
                                    {
                                        return Err(SandboxRpcError::Protocol);
                                    }

                                    let descriptors = [
                                        pending.pipes().command_writer().as_raw_fd(),
                                        pending.pipes().event_reader().as_raw_fd(),
                                    ];
                                    let marker = [DESCRIPTOR_OFFER];
                                    let bytes_sent = stream
                                        .async_io(Interest::WRITABLE, || {
                                            let buffers = [IoSlice::new(&marker)];
                                            let rights = ControlMessage::ScmRights(&descriptors);
                                            sendmsg::<()>(
                                                stream.as_raw_fd(),
                                                &buffers,
                                                &[rights],
                                                MsgFlags::MSG_DONTWAIT
                                                    | MsgFlags::MSG_NOSIGNAL,
                                                None,
                                            )
                                            .map_err(std::io::Error::from)
                                        })
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    if bytes_sent != 1 {
                                        return Err(SandboxRpcError::Protocol);
                                    }
                                    let offer_challenge = LeaseId::new();
                                    stream
                                        .write_all(offer_challenge.as_bytes())
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    let mut accepted = [0_u8; HANDOFF_FRAME_BYTES];
                                    stream
                                        .read_exact(&mut accepted)
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    if accepted[0] != CLIENT_DESCRIPTOR_ACCEPTED
                                        || accepted[1..] != offer_challenge.as_bytes()[..]
                                    {
                                        return Err(SandboxRpcError::Protocol);
                                    }

                                    let committed = pending.commit().await.map_err(|error| {
                                        SandboxRpcError::Io(error.to_string())
                                    })?;
                                    let committed_challenge = LeaseId::new();
                                    let mut committed_frame = [0_u8; HANDOFF_FRAME_BYTES];
                                    committed_frame[0] = DESCRIPTOR_COMMITTED;
                                    committed_frame[1..]
                                        .copy_from_slice(committed_challenge.as_bytes());
                                    stream
                                        .write_all(&committed_frame)
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    let mut final_receipt = [0_u8; HANDOFF_FRAME_BYTES];
                                    stream
                                        .read_exact(&mut final_receipt)
                                        .await
                                        .map_err(|error| {
                                            SandboxRpcError::Io(error.to_string())
                                        })?;
                                    if final_receipt[0] != CLIENT_FINAL_RECEIPT
                                        || final_receipt[1..]
                                            != committed_challenge.as_bytes()[..]
                                    {
                                        return Err(SandboxRpcError::Protocol);
                                    }
                                    let pipes = committed.finish().await.map_err(|error| {
                                        SandboxRpcError::Io(error.to_string())
                                    })?;
                                    drop(pipes);
                                    committed_frame[0] = DESCRIPTOR_HANDOFF_COMPLETE;
                                    stream.write_all(&committed_frame).await.map_err(|error| {
                                        SandboxRpcError::Io(error.to_string())
                                    })?;
                                    let _ = claim_completed.send(());
                                    Ok(())
                                };
                                let _handoff_result = tokio::time::timeout(
                                    config.request_timeout,
                                    handoff,
                                )
                                .await;
                                return;
                            }
                            request => request,
                        };
                        let response = match request {
                                RpcRequest::CreateShard {
                                    shard_id,
                                    worker_id,
                                    worker_epoch,
                                    lease_ttl_ms,
                                } => {
                                    let lease_ttl = Duration::from_millis(lease_ttl_ms);
                                    if lease_ttl.is_zero()
                                        || lease_ttl > supervisor.config.supervisor_lease_ttl
                                    {
                                        RpcResponse::Failure(RpcFailure {
                                            code: RpcFailureCode::InvalidLease,
                                            message: "owner lease exceeds the supervisor TTL".to_owned(),
                                        })
                                    } else {
                                        let now = Instant::now();
                                        let spec = LaunchSpec::production(
                                            shard_id,
                                            worker_id.clone(),
                                            worker_epoch,
                                        );
                                        match supervisor
                                            .create_shard(
                                                spec,
                                                WorkerOwnership::new(
                                                    worker_id,
                                                    worker_epoch,
                                                    now + lease_ttl,
                                                ),
                                            )
                                            .await
                                        {
                                            Ok(outcome) => RpcResponse::Success(
                                                RpcSuccess::CreateShard(outcome),
                                            ),
                                            Err(error) => RpcResponse::Failure(error.into()),
                                        }
                                    }
                                }
                                RpcRequest::RenewOwnerLease {
                                    shard_id,
                                    worker_epoch,
                                    lease_ttl_ms,
                                } => {
                                    let now = Instant::now();
                                    match supervisor
                                        .renew_owner_lease(
                                            &shard_id,
                                            worker_epoch,
                                            now,
                                            now + Duration::from_millis(lease_ttl_ms),
                                        )
                                        .await
                                    {
                                        Ok(()) => RpcResponse::Success(RpcSuccess::Renewed),
                                        Err(error) => RpcResponse::Failure(error.into()),
                                    }
                                }
                                RpcRequest::KillShard {
                                    shard_id,
                                    worker_epoch,
                                    reason,
                                } => match supervisor
                                    .kill_shard(&shard_id, worker_epoch, reason)
                                    .await
                                {
                                    Ok(outcome) => {
                                        RpcResponse::Success(RpcSuccess::KillShard(outcome))
                                    }
                                    Err(error) => RpcResponse::Failure(error.into()),
                                },
                                RpcRequest::InspectResources {
                                    shard_id,
                                    worker_epoch,
                                } => match supervisor
                                    .inspect_resources(&shard_id, worker_epoch)
                                    .await
                                {
                                    Ok(resources) => RpcResponse::Success(
                                        RpcSuccess::InspectResources(resources),
                                    ),
                                    Err(error) => RpcResponse::Failure(error.into()),
                                },
                                RpcRequest::ClaimCdpPipes { .. } => return,
                        };
                        let Ok(response) = serde_json::to_vec(&response) else {
                            return;
                        };
                        if response.len() > config.max_frame_bytes {
                            return;
                        }
                        let _result = tokio::time::timeout(
                            config.request_timeout,
                            framed.send(Bytes::from(response)),
                        )
                        .await;
                    });
                }
            }
        };

        while connections.join_next().await.is_some() {}
        sweeper_shutdown.cancel();
        let _sweeper_result = sweeper.await;
        terminal
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SandboxRpcError {
    #[error("sandbox RPC configuration is invalid")]
    InvalidConfig,
    #[error("sandbox owner lease is invalid")]
    InvalidLease,
    #[error("sandbox RPC frame exceeds its configured limit")]
    FrameTooLarge,
    #[error("sandbox RPC request timed out")]
    TimedOut,
    #[error("sandbox RPC peer closed the connection")]
    ConnectionClosed,
    #[error("sandbox RPC protocol response did not match the request")]
    Protocol,
    #[error("sandbox RPC returned invalid CDP capabilities: {0}")]
    InvalidCapabilities(String),
    #[error("sandbox RPC serialization failed: {0}")]
    Serialization(String),
    #[error("sandbox RPC I/O failed: {0}")]
    Io(String),
    #[error("sandbox RPC failed remotely ({code:?}): {message}")]
    Remote {
        code: RpcFailureCode,
        message: String,
    },
    #[error("sandbox RPC connection task failed")]
    ConnectionTaskFailed,
}
