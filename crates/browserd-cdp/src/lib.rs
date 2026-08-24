//! Bounded Chrome DevTools Protocol framing and command correlation.

use std::collections::{BTreeMap, VecDeque};
use std::io;

use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CdpCommand {
    id: u64,
    method: String,
    params: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
}

impl CdpCommand {
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            id,
            method: method.into(),
            params,
            session_id: None,
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub const fn id(&self) -> u64 {
        self.id
    }

    pub fn method(&self) -> &str {
        &self.method
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CdpProtocolError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CdpIncoming {
    Response {
        id: u64,
        result: Value,
        session_id: Option<String>,
    },
    ProtocolError {
        id: u64,
        error: CdpProtocolError,
        session_id: Option<String>,
    },
    Event {
        method: String,
        params: Value,
        session_id: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct CdpFrameCodec {
    max_frame_bytes: usize,
    desynchronized: bool,
}

impl CdpFrameCodec {
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            desynchronized: false,
        }
    }

    pub const fn is_desynchronized(&self) -> bool {
        self.desynchronized
    }
}

impl Decoder for CdpFrameCodec {
    type Item = CdpIncoming;
    type Error = CdpError;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.desynchronized {
            return Err(CdpError::TransportDesynchronized);
        }

        let delimiter = source.iter().position(|byte| *byte == 0);
        let Some(delimiter) = delimiter else {
            if source.len() > self.max_frame_bytes {
                let observed = source.len();
                source.clear();
                self.desynchronized = true;
                return Err(CdpError::FrameTooLarge {
                    limit: self.max_frame_bytes,
                    observed,
                });
            }
            return Ok(None);
        };

        if delimiter > self.max_frame_bytes {
            let observed = delimiter;
            source.clear();
            self.desynchronized = true;
            return Err(CdpError::FrameTooLarge {
                limit: self.max_frame_bytes,
                observed,
            });
        }

        let mut frame = source.split_to(delimiter + 1);
        frame.truncate(delimiter);
        let envelope: Value = serde_json::from_slice(&frame).map_err(|_| {
            self.desynchronized = true;
            CdpError::InvalidJson
        })?;

        let session_id = envelope
            .get("sessionId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        if let Some(id) = envelope.get("id").and_then(Value::as_u64) {
            if let Some(error) = envelope.get("error") {
                let error = serde_json::from_value(error.clone()).map_err(|_| {
                    self.desynchronized = true;
                    CdpError::InvalidEnvelope
                })?;
                return Ok(Some(CdpIncoming::ProtocolError {
                    id,
                    error,
                    session_id,
                }));
            }
            return Ok(Some(CdpIncoming::Response {
                id,
                result: envelope.get("result").cloned().unwrap_or(Value::Null),
                session_id,
            }));
        }

        if let Some(method) = envelope.get("method").and_then(Value::as_str) {
            return Ok(Some(CdpIncoming::Event {
                method: method.to_owned(),
                params: envelope.get("params").cloned().unwrap_or(Value::Null),
                session_id,
            }));
        }

        self.desynchronized = true;
        Err(CdpError::InvalidEnvelope)
    }
}

impl Encoder<CdpCommand> for CdpFrameCodec {
    type Error = CdpError;

    fn encode(
        &mut self,
        command: CdpCommand,
        destination: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        if self.desynchronized {
            return Err(CdpError::TransportDesynchronized);
        }
        let encoded = serde_json::to_vec(&command).map_err(|_| CdpError::InvalidJson)?;
        if encoded.len() > self.max_frame_bytes {
            return Err(CdpError::FrameTooLarge {
                limit: self.max_frame_bytes,
                observed: encoded.len(),
            });
        }
        destination.reserve(encoded.len() + 1);
        destination.extend_from_slice(&encoded);
        destination.put_u8(0);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCommand {
    id: u64,
    method: String,
}

impl PendingCommand {
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub fn method(&self) -> &str {
        &self.method
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveOutcome {
    Matched { method: String },
    LateOrDuplicate,
}

#[derive(Debug)]
pub struct PendingRegistry {
    limit: usize,
    next_id: Option<u64>,
    pending: BTreeMap<u64, PendingCommand>,
    late_responses: u64,
    closed: bool,
}

impl PendingRegistry {
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            next_id: Some(1),
            pending: BTreeMap::new(),
            late_responses: 0,
            closed: false,
        }
    }

    pub fn register(&mut self, method: impl Into<String>) -> Result<PendingCommand, CdpError> {
        if self.closed {
            return Err(CdpError::TransportClosed);
        }
        if self.pending.len() >= self.limit {
            return Err(CdpError::PendingLimitExceeded { limit: self.limit });
        }
        let id = self.next_id.ok_or(CdpError::SequenceExhausted)?;
        self.next_id = id.checked_add(1);
        let command = PendingCommand {
            id,
            method: method.into(),
        };
        self.pending.insert(id, command.clone());
        Ok(command)
    }

    pub fn resolve(&mut self, id: u64) -> ResolveOutcome {
        if let Some(command) = self.pending.remove(&id) {
            ResolveOutcome::Matched {
                method: command.method,
            }
        } else {
            self.late_responses = self.late_responses.saturating_add(1);
            ResolveOutcome::LateOrDuplicate
        }
    }

    pub fn close(&mut self) -> Vec<PendingCommand> {
        self.closed = true;
        std::mem::take(&mut self.pending).into_values().collect()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub const fn late_responses(&self) -> u64 {
        self.late_responses
    }
}

#[derive(Debug)]
pub struct BoundedEventQueue {
    capacity: usize,
    events: VecDeque<CdpIncoming>,
    desynchronized: bool,
}

impl BoundedEventQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
            desynchronized: false,
        }
    }

    pub fn push(&mut self, event: CdpIncoming) -> Result<(), CdpError> {
        if self.desynchronized {
            return Err(CdpError::TransportDesynchronized);
        }
        if !matches!(event, CdpIncoming::Event { .. }) {
            self.events.clear();
            self.desynchronized = true;
            return Err(CdpError::InvalidEnvelope);
        }
        if self.events.len() >= self.capacity {
            self.events.clear();
            self.desynchronized = true;
            return Err(CdpError::EventQueueOverflow {
                capacity: self.capacity,
            });
        }
        self.events.push_back(event);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<CdpIncoming> {
        if self.desynchronized {
            None
        } else {
            self.events.pop_front()
        }
    }

    pub const fn is_desynchronized(&self) -> bool {
        self.desynchronized
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CdpError {
    #[error("CDP frame exceeds the configured bound ({observed} > {limit})")]
    FrameTooLarge { limit: usize, observed: usize },
    #[error("CDP frame is not valid JSON")]
    InvalidJson,
    #[error("CDP frame has no recognized response or event envelope")]
    InvalidEnvelope,
    #[error("CDP pending command limit reached ({limit})")]
    PendingLimitExceeded { limit: usize },
    #[error("CDP command sequence is exhausted")]
    SequenceExhausted,
    #[error("CDP event queue overflowed ({capacity})")]
    EventQueueOverflow { capacity: usize },
    #[error("CDP transport is desynchronized")]
    TransportDesynchronized,
    #[error("CDP transport is closed")]
    TransportClosed,
    #[error("CDP transport I/O failed")]
    Io,
}

impl From<io::Error> for CdpError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}
