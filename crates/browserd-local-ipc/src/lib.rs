//! Fail-closed, capability-only descriptor transfer over connected Unix streams.
//!
//! Descriptor direction and domain commit authority are independent. A
//! descriptor-sending coordinator drops its originals after announcing commit;
//! a descriptor-sending follower drops them after observing commit and before
//! acknowledging it. The descriptor receiver retains installed descriptors
//! through the final completion frame. Dropping either side before completion
//! is cancellation: it closes only descriptors owned by that protocol state and
//! performs no domain cleanup.

use std::io::IoSlice;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use browserd_core::LeaseId;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use thiserror::Error;
use tokio::io::Interest;
use tokio::net::UnixStream;

const RECEIVER_READY: u8 = 0x51;
const DESCRIPTOR_OFFER: u8 = 0x52;
const RECEIVER_ACCEPTED: u8 = 0x53;
const COORDINATOR_COMMITTED: u8 = 0x54;
const FOLLOWER_FINAL_RECEIPT: u8 = 0x55;
const COORDINATOR_COMPLETE: u8 = 0x56;
const COORDINATOR_ROLE: u8 = 0x57;
const FOLLOWER_ROLE: u8 = 0x58;
const FRAME_BYTES: usize = 33;
const ID_BYTES: usize = 16;

/// Linux's per-message `SCM_RIGHTS` limit.
pub const MAX_DESCRIPTOR_COUNT: usize = 253;

const _: () = assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<nix::libc::cmsghdr>());

/// The exact number of descriptors a receiver permits in one offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorCount(usize);

impl DescriptorCount {
    pub fn new(count: usize) -> Result<Self, HandoffError> {
        if !(1..=MAX_DESCRIPTOR_COUNT).contains(&count) {
            return Err(HandoffError::InvalidDescriptorCount {
                count,
                maximum: MAX_DESCRIPTOR_COUNT,
            });
        }
        Ok(Self(count))
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

#[derive(Debug, Error)]
pub enum HandoffError {
    #[error("descriptor count {count} is outside the supported range 1..={maximum}")]
    InvalidDescriptorCount { count: usize, maximum: usize },
    #[error("local descriptor handoff I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the peer closed the handoff stream")]
    ConnectionClosed,
    #[error("unexpected handoff phase marker: expected {expected:#04x}, received {received:#04x}")]
    UnexpectedPhase { expected: u8, received: u8 },
    #[error("handoff transfer ID does not match")]
    TransferMismatch,
    #[error("handoff offer nonce does not match")]
    NonceMismatch,
    #[error("descriptor ancillary data was truncated")]
    TruncatedControl,
    #[error("descriptor ancillary data is malformed")]
    MalformedControl,
    #[error("an unexpected ancillary control message was received")]
    UnexpectedControl,
    #[error("expected one SCM_RIGHTS message, received {received}")]
    RightsMessageCount { received: usize },
    #[error("expected exactly {expected} descriptors, received {received}")]
    DescriptorCountMismatch { expected: usize, received: usize },
    #[error("the kernel accepted only {sent} of {expected} protocol frame bytes")]
    PartialFrame { expected: usize, sent: usize },
}

#[derive(Debug)]
pub struct SenderAwaitingReady;
#[derive(Debug)]
pub struct SenderReady;
#[derive(Debug)]
pub struct SenderOffered;
#[derive(Debug)]
pub struct SenderAccepted;
#[derive(Debug)]
pub struct CoordinatorAccepted;
#[derive(Debug)]
pub struct CoordinatorCommitted;
#[derive(Debug)]
pub struct CoordinatorReceipted;
#[derive(Debug)]
pub struct FollowerAccepted;
#[derive(Debug)]
pub struct FollowerCommitted;
#[derive(Debug)]
pub struct FollowerReceipted;
#[derive(Debug)]
pub struct SenderComplete;

/// Sender half of the descriptor handoff state machine.
///
/// Each protocol method exists only on the state where that transition is
/// legal. Consequently, an out-of-order commit does not compile:
///
/// ```compile_fail
/// use browserd_local_ipc::Sender;
///
/// async fn commit_before_accept(sender: Sender) {
///     let _ = sender.commit().await;
/// }
/// ```
#[derive(Debug)]
pub struct Sender<State = SenderAwaitingReady> {
    stream: UnixStream,
    transfer_id: LeaseId,
    offer_nonce: Option<LeaseId>,
    descriptors: Option<Vec<OwnedFd>>,
    state: PhantomData<State>,
}

impl Sender<SenderAwaitingReady> {
    pub fn new(
        stream: UnixStream,
        transfer_id: LeaseId,
        descriptors: Vec<OwnedFd>,
    ) -> Result<Self, HandoffError> {
        DescriptorCount::new(descriptors.len())?;
        Ok(Self {
            stream,
            transfer_id,
            offer_nonce: None,
            descriptors: Some(descriptors),
            state: PhantomData,
        })
    }

    pub async fn await_ready(mut self) -> Result<Sender<SenderReady>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(&frame, RECEIVER_READY, &self.transfer_id, &[0_u8; ID_BYTES])?;
        Ok(self.transition())
    }
}

impl Sender<SenderReady> {
    pub async fn offer(mut self) -> Result<Sender<SenderOffered>, HandoffError> {
        let offer_nonce = LeaseId::new();
        let frame = protocol_frame(DESCRIPTOR_OFFER, &self.transfer_id, offer_nonce.as_bytes());
        let descriptors = self
            .descriptors
            .as_deref()
            .ok_or(HandoffError::MalformedControl)?;
        send_offer(&self.stream, &frame, descriptors).await?;
        self.offer_nonce = Some(offer_nonce);
        Ok(self.transition())
    }
}

impl Sender<SenderOffered> {
    pub async fn await_accepted(mut self) -> Result<Sender<SenderAccepted>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            RECEIVER_ACCEPTED,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        Ok(self.transition())
    }
}

impl Sender<SenderAccepted> {
    /// Selects this peer as the domain commit coordinator.
    ///
    /// Role negotiation completes only after the peer concurrently selects the
    /// complementary follower role. No domain commit may occur before this
    /// method returns successfully.
    pub async fn into_coordinator(mut self) -> Result<Sender<CoordinatorAccepted>, HandoffError> {
        let nonce = *self.nonce_bytes()?;
        negotiate_role(
            &mut self.stream,
            &self.transfer_id,
            &nonce,
            COORDINATOR_ROLE,
            FOLLOWER_ROLE,
        )
        .await?;
        Ok(self.transition())
    }

    /// Selects this peer as the domain commit follower.
    ///
    /// Role negotiation completes only after the peer concurrently selects the
    /// complementary coordinator role.
    pub async fn into_follower(mut self) -> Result<Sender<FollowerAccepted>, HandoffError> {
        let nonce = *self.nonce_bytes()?;
        negotiate_role(
            &mut self.stream,
            &self.transfer_id,
            &nonce,
            FOLLOWER_ROLE,
            COORDINATOR_ROLE,
        )
        .await?;
        Ok(self.transition())
    }
}

impl Sender<CoordinatorAccepted> {
    /// Announces that the caller's domain-level commit has succeeded.
    pub async fn commit(mut self) -> Result<Sender<CoordinatorCommitted>, HandoffError> {
        let frame = protocol_frame(
            COORDINATOR_COMMITTED,
            &self.transfer_id,
            self.nonce_bytes()?,
        );
        send_plain_frame(&self.stream, &frame).await?;
        drop(self.descriptors.take());
        Ok(self.transition())
    }
}

impl Sender<CoordinatorCommitted> {
    pub async fn await_receipt(mut self) -> Result<Sender<CoordinatorReceipted>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            FOLLOWER_FINAL_RECEIPT,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        Ok(self.transition())
    }
}

impl Sender<CoordinatorReceipted> {
    pub async fn complete(self) -> Result<Sender<SenderComplete>, HandoffError> {
        let frame = protocol_frame(COORDINATOR_COMPLETE, &self.transfer_id, self.nonce_bytes()?);
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Sender<FollowerAccepted> {
    pub async fn await_committed(mut self) -> Result<Sender<FollowerCommitted>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            COORDINATOR_COMMITTED,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        drop(self.descriptors.take());
        Ok(self.transition())
    }
}

impl Sender<FollowerCommitted> {
    pub async fn receipt(self) -> Result<Sender<FollowerReceipted>, HandoffError> {
        let frame = protocol_frame(
            FOLLOWER_FINAL_RECEIPT,
            &self.transfer_id,
            self.nonce_bytes()?,
        );
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Sender<FollowerReceipted> {
    pub async fn await_complete(mut self) -> Result<Sender<SenderComplete>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            COORDINATOR_COMPLETE,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        Ok(self.transition())
    }
}

impl Sender<SenderComplete> {
    #[must_use]
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }
}

impl<State> Sender<State> {
    #[must_use]
    pub const fn transfer_id(&self) -> &LeaseId {
        &self.transfer_id
    }

    fn nonce_bytes(&self) -> Result<&[u8; ID_BYTES], HandoffError> {
        self.offer_nonce
            .as_ref()
            .map(LeaseId::as_bytes)
            .ok_or(HandoffError::NonceMismatch)
    }

    fn transition<Next>(self) -> Sender<Next> {
        Sender {
            stream: self.stream,
            transfer_id: self.transfer_id,
            offer_nonce: self.offer_nonce,
            descriptors: self.descriptors,
            state: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct ReceiverInitial;
#[derive(Debug)]
pub struct ReceiverReady;
#[derive(Debug)]
pub struct ReceiverOffered;
#[derive(Debug)]
pub struct ReceiverAccepted;
#[derive(Debug)]
pub struct ReceiverComplete;

/// Receiver half of the descriptor handoff state machine.
#[derive(Debug)]
pub struct Receiver<State = ReceiverInitial> {
    stream: UnixStream,
    transfer_id: LeaseId,
    offer_nonce: Option<[u8; ID_BYTES]>,
    expected_count: DescriptorCount,
    descriptors: Option<Vec<OwnedFd>>,
    state: PhantomData<State>,
}

impl Receiver<ReceiverInitial> {
    #[must_use]
    pub fn new(stream: UnixStream, transfer_id: LeaseId, expected_count: DescriptorCount) -> Self {
        Self {
            stream,
            transfer_id,
            offer_nonce: None,
            expected_count,
            descriptors: None,
            state: PhantomData,
        }
    }

    pub async fn ready(self) -> Result<Receiver<ReceiverReady>, HandoffError> {
        let frame = protocol_frame(RECEIVER_READY, &self.transfer_id, &[0_u8; ID_BYTES]);
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Receiver<ReceiverReady> {
    pub async fn receive(mut self) -> Result<Receiver<ReceiverOffered>, HandoffError> {
        let received = receive_raw_frame(&mut self.stream).await?;
        validate_offer_control(&received, self.expected_count)?;
        validate_marker_and_transfer(&received.frame, DESCRIPTOR_OFFER, &self.transfer_id)?;
        let mut nonce = [0_u8; ID_BYTES];
        nonce.copy_from_slice(&received.frame[1 + ID_BYTES..]);
        if nonce == [0_u8; ID_BYTES] {
            return Err(HandoffError::NonceMismatch);
        }
        self.offer_nonce = Some(nonce);
        self.descriptors = Some(received.descriptors);
        Ok(self.transition())
    }
}

impl Receiver<ReceiverOffered> {
    /// Descriptors may be inspected before the offer is accepted.
    #[must_use]
    pub fn descriptors(&self) -> &[OwnedFd] {
        self.descriptors.as_deref().unwrap_or_default()
    }

    pub async fn accept(self) -> Result<Receiver<ReceiverAccepted>, HandoffError> {
        let frame = protocol_frame(RECEIVER_ACCEPTED, &self.transfer_id, self.nonce_bytes()?);
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Receiver<ReceiverAccepted> {
    /// Selects this peer as the domain commit coordinator.
    ///
    /// Role negotiation completes only after the peer concurrently selects the
    /// complementary follower role. No domain commit may occur before this
    /// method returns successfully.
    pub async fn into_coordinator(mut self) -> Result<Receiver<CoordinatorAccepted>, HandoffError> {
        let nonce = *self.nonce_bytes()?;
        negotiate_role(
            &mut self.stream,
            &self.transfer_id,
            &nonce,
            COORDINATOR_ROLE,
            FOLLOWER_ROLE,
        )
        .await?;
        Ok(self.transition())
    }

    /// Selects this peer as the domain commit follower.
    ///
    /// Role negotiation completes only after the peer concurrently selects the
    /// complementary coordinator role.
    pub async fn into_follower(mut self) -> Result<Receiver<FollowerAccepted>, HandoffError> {
        let nonce = *self.nonce_bytes()?;
        negotiate_role(
            &mut self.stream,
            &self.transfer_id,
            &nonce,
            FOLLOWER_ROLE,
            COORDINATOR_ROLE,
        )
        .await?;
        Ok(self.transition())
    }
}

impl Receiver<CoordinatorAccepted> {
    /// Announces that the caller's domain-level commit has succeeded.
    pub async fn commit(self) -> Result<Receiver<CoordinatorCommitted>, HandoffError> {
        let frame = protocol_frame(
            COORDINATOR_COMMITTED,
            &self.transfer_id,
            self.nonce_bytes()?,
        );
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Receiver<CoordinatorCommitted> {
    pub async fn await_receipt(mut self) -> Result<Receiver<CoordinatorReceipted>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            FOLLOWER_FINAL_RECEIPT,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        Ok(self.transition())
    }
}

impl Receiver<CoordinatorReceipted> {
    pub async fn complete(self) -> Result<Receiver<ReceiverComplete>, HandoffError> {
        let frame = protocol_frame(COORDINATOR_COMPLETE, &self.transfer_id, self.nonce_bytes()?);
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Receiver<FollowerAccepted> {
    pub async fn await_committed(mut self) -> Result<Receiver<FollowerCommitted>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            COORDINATOR_COMMITTED,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        Ok(self.transition())
    }
}

impl Receiver<FollowerCommitted> {
    pub async fn receipt(self) -> Result<Receiver<FollowerReceipted>, HandoffError> {
        let frame = protocol_frame(
            FOLLOWER_FINAL_RECEIPT,
            &self.transfer_id,
            self.nonce_bytes()?,
        );
        send_plain_frame(&self.stream, &frame).await?;
        Ok(self.transition())
    }
}

impl Receiver<FollowerReceipted> {
    pub async fn await_complete(mut self) -> Result<Receiver<ReceiverComplete>, HandoffError> {
        let frame = receive_plain_frame(&mut self.stream).await?;
        validate_frame(
            &frame,
            COORDINATOR_COMPLETE,
            &self.transfer_id,
            self.nonce_bytes()?,
        )?;
        Ok(self.transition())
    }
}

impl Receiver<ReceiverComplete> {
    #[must_use]
    pub fn descriptors(&self) -> &[OwnedFd] {
        self.descriptors.as_deref().unwrap_or_default()
    }

    #[must_use]
    pub fn into_parts(mut self) -> (UnixStream, Vec<OwnedFd>) {
        (self.stream, self.descriptors.take().unwrap_or_default())
    }
}

impl<State> Receiver<State> {
    #[must_use]
    pub const fn transfer_id(&self) -> &LeaseId {
        &self.transfer_id
    }

    fn nonce_bytes(&self) -> Result<&[u8; ID_BYTES], HandoffError> {
        self.offer_nonce.as_ref().ok_or(HandoffError::NonceMismatch)
    }

    fn transition<Next>(self) -> Receiver<Next> {
        Receiver {
            stream: self.stream,
            transfer_id: self.transfer_id,
            offer_nonce: self.offer_nonce,
            expected_count: self.expected_count,
            descriptors: self.descriptors,
            state: PhantomData,
        }
    }
}

async fn negotiate_role(
    stream: &mut UnixStream,
    transfer_id: &LeaseId,
    nonce: &[u8; ID_BYTES],
    local_role: u8,
    expected_peer_role: u8,
) -> Result<(), HandoffError> {
    let role = protocol_frame(local_role, transfer_id, nonce);
    send_plain_frame(stream, &role).await?;
    let peer_role = receive_plain_frame(stream).await?;
    validate_frame(&peer_role, expected_peer_role, transfer_id, nonce)
}

struct ReceivedFrame {
    frame: [u8; FRAME_BYTES],
    flags: MsgFlags,
    rights_messages: usize,
    unexpected_control: bool,
    malformed_control: bool,
    descriptors: Vec<OwnedFd>,
}

struct ParsedControl {
    rights_messages: usize,
    unexpected_control: bool,
    malformed_control: bool,
    descriptors: Vec<OwnedFd>,
}

async fn send_plain_frame(
    stream: &UnixStream,
    frame: &[u8; FRAME_BYTES],
) -> Result<(), HandoffError> {
    let sent = stream
        .async_io(Interest::WRITABLE, || {
            let buffers = [IoSlice::new(frame)];
            sendmsg::<()>(
                stream.as_raw_fd(),
                &buffers,
                &[],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(std::io::Error::from)
        })
        .await?;
    if sent != frame.len() {
        return Err(HandoffError::PartialFrame {
            expected: frame.len(),
            sent,
        });
    }
    Ok(())
}

async fn send_offer(
    stream: &UnixStream,
    frame: &[u8; FRAME_BYTES],
    descriptors: &[OwnedFd],
) -> Result<(), HandoffError> {
    let raw_descriptors: Vec<RawFd> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
    let sent = stream
        .async_io(Interest::WRITABLE, || {
            let buffers = [IoSlice::new(frame)];
            let rights = ControlMessage::ScmRights(&raw_descriptors);
            sendmsg::<()>(
                stream.as_raw_fd(),
                &buffers,
                &[rights],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(std::io::Error::from)
        })
        .await?;
    if sent != frame.len() {
        return Err(HandoffError::PartialFrame {
            expected: frame.len(),
            sent,
        });
    }
    Ok(())
}

async fn receive_plain_frame(stream: &mut UnixStream) -> Result<[u8; FRAME_BYTES], HandoffError> {
    let received = receive_raw_frame(stream).await?;
    if received
        .flags
        .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC)
    {
        return Err(HandoffError::TruncatedControl);
    }
    if received.malformed_control {
        return Err(HandoffError::MalformedControl);
    }
    if received.unexpected_control
        || received.rights_messages != 0
        || !received.descriptors.is_empty()
    {
        return Err(HandoffError::UnexpectedControl);
    }
    Ok(received.frame)
}

async fn receive_raw_frame(stream: &mut UnixStream) -> Result<ReceivedFrame, HandoffError> {
    let mut received = ReceivedFrame {
        frame: [0_u8; FRAME_BYTES],
        flags: MsgFlags::empty(),
        rights_messages: 0,
        unexpected_control: false,
        malformed_control: false,
        descriptors: Vec::new(),
    };
    let mut filled = 0_usize;
    while filled < FRAME_BYTES {
        let mut bytes = [0_u8; FRAME_BYTES];
        let remaining = FRAME_BYTES - filled;
        let (flags, parsed, count) = stream
            .async_io(Interest::READABLE, || {
                receive_raw_frame_now(stream, &mut bytes[..remaining])
            })
            .await?;
        if count == 0 {
            return Err(HandoffError::ConnectionClosed);
        }
        received.frame[filled..filled + count].copy_from_slice(&bytes[..count]);
        received.flags |= flags;
        received.rights_messages = received
            .rights_messages
            .saturating_add(parsed.rights_messages);
        received.unexpected_control |= parsed.unexpected_control;
        received.malformed_control |= parsed.malformed_control;
        received.descriptors.extend(parsed.descriptors);
        filled += count;
    }
    Ok(received)
}

fn receive_raw_frame_now(
    stream: &UnixStream,
    frame: &mut [u8],
) -> std::io::Result<(MsgFlags, ParsedControl, usize)> {
    let required_control_bytes = nix::cmsg_space!([RawFd; MAX_DESCRIPTOR_COUNT]).len();
    let mut control = vec![0_usize; required_control_bytes.div_ceil(std::mem::size_of::<usize>())];
    let control_capacity = control.len().saturating_mul(std::mem::size_of::<usize>());
    let mut buffer = nix::libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    // SAFETY: all pointers installed below remain valid for the `recvmsg` call.
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut buffer;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_capacity;
    // SAFETY: the socket and all `msghdr` buffers are valid. `MSG_CMSG_CLOEXEC`
    // atomically protects every descriptor installed by the kernel.
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

    let control_start = control.as_ptr() as usize;
    let parsed = parse_control_messages(&message, control_start, control_capacity);
    Ok((
        MsgFlags::from_bits_truncate(message.msg_flags),
        parsed,
        bytes as usize,
    ))
}

fn parse_control_messages(
    message: &nix::libc::msghdr,
    control_start: usize,
    control_capacity: usize,
) -> ParsedControl {
    let mut malformed_control = message.msg_controllen > control_capacity;
    let control_end = control_start.saturating_add(message.msg_controllen.min(control_capacity));
    let mut rights_messages = 0_usize;
    let mut unexpected_control = false;
    let mut descriptors = Vec::new();

    // SAFETY: `message` describes the initialized control buffer returned by the
    // kernel. Every header and payload is bounds-checked before access.
    let mut control_message = unsafe { nix::libc::CMSG_FIRSTHDR(message) };
    while !control_message.is_null() {
        let header_address = control_message as usize;
        let Some(header_end) =
            header_address.checked_add(std::mem::size_of::<nix::libc::cmsghdr>())
        else {
            malformed_control = true;
            break;
        };
        if header_address < control_start || header_end > control_end {
            malformed_control = true;
            break;
        }
        // SAFETY: the complete header lies within the returned control buffer.
        let header = unsafe { &*control_message };
        // SAFETY: a zero payload asks libc only for the platform header length.
        let minimum_length = unsafe { nix::libc::CMSG_LEN(0) as usize };
        if header.cmsg_len < minimum_length
            || header.cmsg_len > control_end.saturating_sub(header_address)
        {
            malformed_control = true;
            break;
        }
        if header.cmsg_level == nix::libc::SOL_SOCKET && header.cmsg_type == nix::libc::SCM_RIGHTS {
            rights_messages += 1;
            let payload_bytes = header.cmsg_len - minimum_length;
            if !payload_bytes.is_multiple_of(std::mem::size_of::<RawFd>()) {
                malformed_control = true;
            }
            let descriptor_count = payload_bytes / std::mem::size_of::<RawFd>();
            // SAFETY: `CMSG_DATA` points at the bounds-checked payload. Unaligned
            // reads are used because payload alignment is platform-owned.
            let descriptor_data = unsafe { nix::libc::CMSG_DATA(control_message) }.cast::<RawFd>();
            for index in 0..descriptor_count {
                // SAFETY: the index is bounded by the complete payload length.
                let raw_descriptor = unsafe { descriptor_data.add(index).read_unaligned() };
                if raw_descriptor < 0
                    || descriptors
                        .iter()
                        .any(|descriptor: &OwnedFd| descriptor.as_raw_fd() == raw_descriptor)
                {
                    malformed_control = true;
                    continue;
                }
                // SAFETY: the kernel installed this descriptor into this process;
                // ownership transfers exactly once into `OwnedFd`.
                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw_descriptor) });
            }
        } else {
            unexpected_control = true;
        }
        // SAFETY: libc validates alignment and remaining message bounds.
        let next = unsafe { nix::libc::CMSG_NXTHDR(message, control_message) };
        if next == control_message {
            malformed_control = true;
            break;
        }
        control_message = next;
    }

    ParsedControl {
        rights_messages,
        unexpected_control,
        malformed_control,
        descriptors,
    }
}

fn validate_offer_control(
    received: &ReceivedFrame,
    expected_count: DescriptorCount,
) -> Result<(), HandoffError> {
    if received
        .flags
        .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC)
    {
        return Err(HandoffError::TruncatedControl);
    }
    if received.malformed_control {
        return Err(HandoffError::MalformedControl);
    }
    if received.unexpected_control {
        return Err(HandoffError::UnexpectedControl);
    }
    if received.rights_messages != 1 {
        return Err(HandoffError::RightsMessageCount {
            received: received.rights_messages,
        });
    }
    if received.descriptors.len() != expected_count.get() {
        return Err(HandoffError::DescriptorCountMismatch {
            expected: expected_count.get(),
            received: received.descriptors.len(),
        });
    }
    Ok(())
}

fn protocol_frame(marker: u8, transfer_id: &LeaseId, nonce: &[u8; ID_BYTES]) -> [u8; FRAME_BYTES] {
    let mut frame = [0_u8; FRAME_BYTES];
    frame[0] = marker;
    frame[1..1 + ID_BYTES].copy_from_slice(transfer_id.as_bytes());
    frame[1 + ID_BYTES..].copy_from_slice(nonce);
    frame
}

fn validate_marker_and_transfer(
    frame: &[u8; FRAME_BYTES],
    expected_marker: u8,
    transfer_id: &LeaseId,
) -> Result<(), HandoffError> {
    if frame[0] != expected_marker {
        return Err(HandoffError::UnexpectedPhase {
            expected: expected_marker,
            received: frame[0],
        });
    }
    if frame[1..1 + ID_BYTES] != transfer_id.as_bytes()[..] {
        return Err(HandoffError::TransferMismatch);
    }
    Ok(())
}

fn validate_frame(
    frame: &[u8; FRAME_BYTES],
    expected_marker: u8,
    transfer_id: &LeaseId,
    expected_nonce: &[u8; ID_BYTES],
) -> Result<(), HandoffError> {
    validate_marker_and_transfer(frame, expected_marker, transfer_id)?;
    if frame[1 + ID_BYTES..] != expected_nonce[..] {
        return Err(HandoffError::NonceMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
