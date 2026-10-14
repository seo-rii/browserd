use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;
use tokio_util::time::{DelayQueue, delay_queue};
use zeroize::Zeroizing;

use crate::{
    CdpCommand, CdpError, CdpFrameCodec, CdpIncoming, CdpProtocolError, PendingRegistry,
    ResolveOutcome,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CdpTransportConfig {
    pub max_frame_bytes: usize,
    pub max_pending_commands: usize,
    pub command_queue_capacity: usize,
    pub event_queue_capacity: usize,
    pub write_timeout: Duration,
    pub default_command_timeout: Duration,
}

impl Default for CdpTransportConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: 16 * 1024 * 1024,
            max_pending_commands: 1_024,
            command_queue_capacity: 1_024,
            event_queue_capacity: 4_096,
            write_timeout: Duration::from_secs(5),
            default_command_timeout: Duration::from_secs(30),
        }
    }
}

impl CdpTransportConfig {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.max_frame_bytes > 0
            && self.max_pending_commands > 0
            && self.command_queue_capacity > 0
            && self.event_queue_capacity > 0
            && !self.write_timeout.is_zero()
            && !self.default_command_timeout.is_zero()
    }
}

#[derive(Clone, Debug)]
pub struct CdpClient {
    requests: mpsc::Sender<CommandRequest>,
    closed: Arc<AtomicBool>,
    sensitive_frame_limit: usize,
}

impl CdpClient {
    pub async fn command(
        &self,
        method: impl Into<String>,
        params: Value,
        session_id: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Value, CdpCommandError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CdpCommandError::TransportClosed);
        }
        let (response, receiver) = oneshot::channel();
        let request = CommandRequest {
            method: method.into(),
            params: CommandParams::Ordinary(params),
            session_id,
            timeout,
            expires_at: None,
            response,
        };
        match self.requests.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(CdpCommandError::CommandQueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(CdpCommandError::TransportClosed);
            }
        }
        receiver
            .await
            .unwrap_or(Err(CdpCommandError::TransportClosed))
    }

    /// Serializes borrowed secret arguments without constructing a `Value` or using the
    /// ordinary codec's reusable write buffer. Method/session identifiers must not be secret.
    pub async fn command_sensitive<T: Serialize + ?Sized>(
        &self,
        method: impl Into<String>,
        params: &T,
        session_id: Option<String>,
        deadline: Instant,
    ) -> Result<Value, CdpCommandError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CdpCommandError::TransportClosed);
        }
        if Instant::now() >= deadline {
            return Err(CdpCommandError::TimedOut);
        }
        let mut encoded = SensitiveBuffer::new(self.sensitive_frame_limit);
        serde_json::to_writer(&mut encoded, params)
            .map_err(|_| CdpCommandError::SensitivePayloadRejected)?;
        let (response, receiver) = oneshot::channel();
        let request = CommandRequest {
            method: method.into(),
            params: CommandParams::Sensitive(encoded.bytes),
            session_id,
            timeout: None,
            expires_at: Some(deadline),
            response,
        };
        match self.requests.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(CdpCommandError::CommandQueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(CdpCommandError::TransportClosed);
            }
        }
        match tokio::time::timeout_at(deadline.into(), receiver).await {
            Ok(result) => result.unwrap_or(Err(CdpCommandError::TransportClosed)),
            Err(_) => Err(CdpCommandError::TimedOut),
        }
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

struct CommandRequest {
    method: String,
    params: CommandParams,
    session_id: Option<String>,
    timeout: Option<Duration>,
    expires_at: Option<Instant>,
    response: oneshot::Sender<Result<Value, CdpCommandError>>,
}

impl fmt::Debug for CommandRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandRequest { params: [REDACTED], .. }")
    }
}

enum CommandParams {
    Ordinary(Value),
    Sensitive(Zeroizing<Vec<u8>>),
}

struct PendingResponse {
    response: oneshot::Sender<Result<Value, CdpCommandError>>,
    sensitive: bool,
}

// Allocate the entire bound once: growing a Vec could leave an earlier secret allocation
// unzeroized. The delimiter has its own reserved byte, outside the protocol frame limit.
struct SensitiveBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl SensitiveBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit + 1)),
            limit,
        }
    }
}

impl Write for SensitiveBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("sensitive CDP frame exceeds its bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sensitive_frame(
    id: u64,
    method: &str,
    params: &[u8],
    session_id: Option<&str>,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, CdpCommandError> {
    let mut frame = SensitiveBuffer::new(limit);
    let encode = || -> io::Result<()> {
        frame.write_all(b"{\"id\":")?;
        serde_json::to_writer(&mut frame, &id)?;
        frame.write_all(b",\"method\":")?;
        serde_json::to_writer(&mut frame, method)?;
        frame.write_all(b",\"params\":")?;
        frame.write_all(params)?;
        if let Some(session) = session_id {
            frame.write_all(b",\"sessionId\":")?;
            serde_json::to_writer(&mut frame, session)?;
        }
        frame.write_all(b"}")?;
        Ok(())
    };
    let mut encode = encode;
    encode().map_err(|_| CdpCommandError::SensitivePayloadRejected)?;
    frame.bytes.push(0);
    Ok(frame.bytes)
}

#[derive(Debug)]
pub struct CdpDriver {
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), CdpTransportError>>,
    closed: Arc<AtomicBool>,
}

impl CdpDriver {
    pub async fn wait(mut self) -> Result<(), CdpTransportError> {
        match (&mut self.task).await {
            Ok(result) => result,
            Err(_) => Err(CdpTransportError::DriverTaskFailed),
        }
    }

    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        let _result = (&mut self.task).await;
    }
}

impl Drop for CdpDriver {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown.cancel();
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CdpTransport;

impl CdpTransport {
    pub fn spawn<T>(
        io: T,
        config: CdpTransportConfig,
    ) -> (CdpClient, mpsc::Receiver<CdpIncoming>, CdpDriver)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(io);
        Self::spawn_split(reader, writer, config)
    }

    pub fn spawn_split<R, W>(
        reader: R,
        writer: W,
        config: CdpTransportConfig,
    ) -> (CdpClient, mpsc::Receiver<CdpIncoming>, CdpDriver)
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        // Allows worst-case JSON escaping of a 16 KiB secret plus fixed invocation metadata.
        let sensitive_frame_limit = config.max_frame_bytes.min(128 * 1024);
        let (request_tx, request_rx) =
            mpsc::channel::<CommandRequest>(config.command_queue_capacity.max(1));
        let (event_tx, event_rx) = mpsc::channel::<CdpIncoming>(config.event_queue_capacity.max(1));
        let closed = Arc::new(AtomicBool::new(false));
        let shutdown = CancellationToken::new();
        let task_closed = Arc::clone(&closed);
        let driver_closed = Arc::clone(&closed);
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            let mut requests = request_rx;
            if !config.is_valid() {
                task_closed.store(true, Ordering::Release);
                requests.close();
                while let Some(request) = requests.recv().await {
                    let _sent = request.response.send(Err(CdpCommandError::TransportClosed));
                }
                return Err(CdpTransportError::InvalidConfig);
            }

            let mut incoming = FramedRead::new(reader, CdpFrameCodec::new(config.max_frame_bytes));
            let mut outgoing = FramedWrite::new(writer, CdpFrameCodec::new(config.max_frame_bytes));
            let mut pending = PendingRegistry::new(config.max_pending_commands);
            let mut responders = HashMap::<u64, PendingResponse>::new();
            let mut deadlines = DelayQueue::<u64>::new();
            let mut deadline_keys = HashMap::<u64, delay_queue::Key>::new();
            let mut requests_open = true;
            let terminal = loop {
                tokio::select! {
                    () = task_shutdown.cancelled() => break Ok(()),
                    Some(expired) = deadlines.next(), if !deadlines.is_empty() => {
                        let id = expired.into_inner();
                        deadline_keys.remove(&id);
                        pending.abandon(id);
                        if let Some(response) = responders.remove(&id) {
                            let _sent = response.response.send(Err(CdpCommandError::TimedOut));
                        }
                    }
                    message = incoming.next() => {
                        match message {
                            Some(Ok(CdpIncoming::Response { id, result, .. })) => {
                                if matches!(pending.resolve(id), ResolveOutcome::Matched { .. }) {
                                    if let Some(key) = deadline_keys.remove(&id) {
                                        deadlines.try_remove(&key);
                                    }
                                    if let Some(response) = responders.remove(&id) {
                                        let _sent = response.response.send(Ok(result));
                                    }
                                }
                            }
                            Some(Ok(CdpIncoming::ProtocolError { id, error, .. })) => {
                                if matches!(pending.resolve(id), ResolveOutcome::Matched { .. }) {
                                    if let Some(key) = deadline_keys.remove(&id) {
                                        deadlines.try_remove(&key);
                                    }
                                    if let Some(response) = responders.remove(&id) {
                                        let error = if response.sensitive {
                                            CdpCommandError::SensitiveProtocol { code: error.code }
                                        } else {
                                            CdpCommandError::Protocol(error)
                                        };
                                        let _sent = response.response.send(Err(error));
                                    }
                                }
                            }
                            Some(Ok(event @ CdpIncoming::Event { .. })) => {
                                if event_tx.try_send(event).is_err() {
                                    break Err(CdpTransportError::EventQueueOverflow);
                                }
                            }
                            Some(Err(error)) => break Err(CdpTransportError::Protocol(error)),
                            None => break Err(CdpTransportError::TransportClosed),
                        }
                    }
                    request = requests.recv(), if requests_open => {
                        let Some(request) = request else {
                            requests_open = false;
                            continue;
                        };
                        let sensitive = matches!(request.params, CommandParams::Sensitive(_));
                        if sensitive && request.response.is_closed() {
                            // A canceled caller has not committed a queued frame to the writer.
                            continue;
                        }
                        let command_timeout = request.expires_at.map_or_else(
                            || request.timeout.unwrap_or(config.default_command_timeout),
                            |expiry| expiry.saturating_duration_since(Instant::now()));
                        if command_timeout.is_zero() {
                            let _sent = request.response.send(Err(CdpCommandError::TimedOut));
                            continue;
                        }
                        let registered = match pending.register(request.method.clone()) {
                            Ok(registered) => registered,
                            Err(CdpError::PendingLimitExceeded { .. }) => {
                                let _sent = request.response.send(Err(CdpCommandError::PendingLimitExceeded));
                                continue;
                            }
                            Err(CdpError::SequenceExhausted) => {
                                let _sent = request.response.send(Err(CdpCommandError::SequenceExhausted));
                                continue;
                            }
                            Err(_) => {
                                let _sent = request.response.send(Err(CdpCommandError::TransportClosed));
                                continue;
                            }
                        };
                        let id = registered.id();
                        let written = match request.params {
                            CommandParams::Ordinary(params) => {
                                let mut command = CdpCommand::new(id, request.method, params);
                                if let Some(session_id) = request.session_id {
                                    command = command.with_session_id(session_id);
                                }
                                tokio::time::timeout(config.write_timeout, outgoing.send(command))
                                    .await.map(|result| result.map_err(|_| ()))
                            }
                            CommandParams::Sensitive(params) => {
                                let frame = match sensitive_frame(id, &request.method, &params,
                                    request.session_id.as_deref(), sensitive_frame_limit) {
                                    Ok(frame) => frame,
                                    Err(error) => {
                                        pending.abandon(id);
                                        let _sent = request.response.send(Err(error));
                                        continue;
                                    }
                                };
                                drop(params);
                                // Flush ordinary frames first, then use the same writer directly:
                                // the codec's reusable BytesMut never receives secret bytes.
                                let write_timeout = request.expires_at.map_or(config.write_timeout,
                                    |expiry| config.write_timeout.min(expiry.saturating_duration_since(Instant::now())));
                                tokio::time::timeout(write_timeout, async {
                                    outgoing.flush().await.map_err(|_| ())?;
                                    if request.response.is_closed()
                                        || request.expires_at.is_some_and(|expiry| Instant::now() >= expiry) {
                                        return Err(());
                                    }
                                    outgoing.get_mut().write_all(&frame).await.map_err(|_| ())?;
                                    outgoing.get_mut().flush().await.map_err(|_| ())
                                }).await
                            }
                        };
                        match written {
                            Ok(Ok(())) => {
                                responders.insert(id, PendingResponse { response: request.response, sensitive });
                                let remaining = request.expires_at.map_or(command_timeout,
                                    |expiry| expiry.saturating_duration_since(Instant::now()));
                                let key = deadlines.insert(id, remaining);
                                deadline_keys.insert(id, key);
                            }
                            Ok(Err(_)) | Err(_) => {
                                pending.abandon(id);
                                let _sent = request.response.send(Err(CdpCommandError::WriteUncertain));
                                break Err(CdpTransportError::WriteUncertain);
                            }
                        }
                    }
                }
            };

            task_closed.store(true, Ordering::Release);
            let _closed_commands = pending.close();
            for (_, response) in responders {
                let _sent = response
                    .response
                    .send(Err(CdpCommandError::TransportClosed));
            }
            requests.close();
            while let Some(request) = requests.recv().await {
                let _sent = request.response.send(Err(CdpCommandError::TransportClosed));
            }
            terminal
        });
        (
            CdpClient {
                requests: request_tx,
                closed,
                sensitive_frame_limit,
            },
            event_rx,
            CdpDriver {
                shutdown,
                task,
                closed: driver_closed,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CdpCommandError {
    #[error("CDP command submission queue is full")]
    CommandQueueFull,
    #[error("CDP pending command limit is reached")]
    PendingLimitExceeded,
    #[error("CDP command sequence is exhausted")]
    SequenceExhausted,
    #[error("CDP rejected the command: {0:?}")]
    Protocol(CdpProtocolError),
    #[error("sensitive CDP command serialization was rejected")]
    SensitivePayloadRejected,
    #[error("sensitive CDP command was rejected (code {code})")]
    SensitiveProtocol { code: i64 },
    #[error("CDP command deadline expired")]
    TimedOut,
    #[error("CDP write may have been partially dispatched")]
    WriteUncertain,
    #[error("CDP transport is closed")]
    TransportClosed,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CdpTransportError {
    #[error("CDP transport configuration is invalid")]
    InvalidConfig,
    #[error("CDP protocol transport failed: {0}")]
    Protocol(CdpError),
    #[error("CDP event queue overflowed")]
    EventQueueOverflow,
    #[error("CDP writer may have partially dispatched a frame")]
    WriteUncertain,
    #[error("CDP transport closed")]
    TransportClosed,
    #[error("CDP driver task failed")]
    DriverTaskFailed,
}

#[cfg(test)]
mod sensitive_tests {
    use super::*;

    #[test]
    fn bounded_serialization_never_reallocates_and_request_debug_is_redacted() {
        let secret = "dummy-한글-sensitive";
        let mut buffer = SensitiveBuffer::new(256);
        let allocation = buffer.bytes.as_ptr();
        assert!(serde_json::to_writer(&mut buffer, secret).is_ok());
        assert_eq!(buffer.bytes.as_ptr(), allocation);
        assert!(buffer.write_all(&[b'x'; 256]).is_err());
        assert_eq!(buffer.bytes.as_ptr(), allocation);
        let (response, _receiver) = oneshot::channel();
        let request = CommandRequest {
            method: "Runtime.callFunctionOn".to_owned(),
            params: CommandParams::Sensitive(buffer.bytes),
            session_id: None,
            timeout: None,
            expires_at: None,
            response,
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(secret));
        // Dropping or rejecting a queue entry drops its Zeroizing buffer, without a copy.
        drop(request);
    }
}
