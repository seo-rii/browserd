use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;
use tokio_util::time::{DelayQueue, delay_queue};

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
            params,
            session_id,
            timeout,
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

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct CommandRequest {
    method: String,
    params: Value,
    session_id: Option<String>,
    timeout: Option<Duration>,
    response: oneshot::Sender<Result<Value, CdpCommandError>>,
}

#[derive(Debug)]
pub struct CdpDriver {
    shutdown: CancellationToken,
    task: JoinHandle<Result<(), CdpTransportError>>,
}

impl CdpDriver {
    pub async fn wait(self) -> Result<(), CdpTransportError> {
        match self.task.await {
            Ok(result) => result,
            Err(_) => Err(CdpTransportError::DriverTaskFailed),
        }
    }

    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _result = self.task.await;
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
        let (request_tx, request_rx) =
            mpsc::channel::<CommandRequest>(config.command_queue_capacity.max(1));
        let (event_tx, event_rx) = mpsc::channel::<CdpIncoming>(config.event_queue_capacity.max(1));
        let closed = Arc::new(AtomicBool::new(false));
        let shutdown = CancellationToken::new();
        let task_closed = Arc::clone(&closed);
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
            let mut responders =
                HashMap::<u64, oneshot::Sender<Result<Value, CdpCommandError>>>::new();
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
                            let _sent = response.send(Err(CdpCommandError::TimedOut));
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
                                        let _sent = response.send(Ok(result));
                                    }
                                }
                            }
                            Some(Ok(CdpIncoming::ProtocolError { id, error, .. })) => {
                                if matches!(pending.resolve(id), ResolveOutcome::Matched { .. }) {
                                    if let Some(key) = deadline_keys.remove(&id) {
                                        deadlines.try_remove(&key);
                                    }
                                    if let Some(response) = responders.remove(&id) {
                                        let _sent = response.send(Err(CdpCommandError::Protocol(error)));
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
                        let command_timeout = request.timeout.unwrap_or(config.default_command_timeout);
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
                        let mut command = CdpCommand::new(id, request.method, request.params);
                        if let Some(session_id) = request.session_id {
                            command = command.with_session_id(session_id);
                        }
                        let written = tokio::time::timeout(
                            config.write_timeout,
                            outgoing.send(command),
                        )
                        .await;
                        match written {
                            Ok(Ok(())) => {
                                responders.insert(id, request.response);
                                let key = deadlines.insert(id, command_timeout);
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
                let _sent = response.send(Err(CdpCommandError::TransportClosed));
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
            },
            event_rx,
            CdpDriver { shutdown, task },
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
