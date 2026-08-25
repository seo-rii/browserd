use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const FRAME_HEADER_BYTES: usize = 8;
const RECORD_HEADER_BYTES: usize = 17;
const FILE_HEADER_BYTES: usize = 16;
const FILE_MAGIC: &[u8; 4] = b"BDAW";
const FILE_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuditEventId(String);

impl AuditEventId {
    pub fn new(value: impl Into<String>) -> Result<Self, AuditWalError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > u16::MAX as usize
            || value.chars().any(char::is_control)
        {
            return Err(AuditWalError::InvalidEventId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuditEvent {
    id: AuditEventId,
    kind: String,
    payload: Vec<u8>,
    critical: bool,
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditEvent")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("payload_bytes", &self.payload.len())
            .field("critical", &self.critical)
            .finish()
    }
}

impl AuditEvent {
    #[must_use]
    pub fn new(
        id: AuditEventId,
        kind: impl Into<String>,
        payload: Vec<u8>,
        critical: bool,
    ) -> Self {
        Self {
            id,
            kind: kind.into(),
            payload,
            critical,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &AuditEventId {
        &self.id
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.critical
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuditSequence(u64);

impl AuditSequence {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAuditEvent {
    sequence: AuditSequence,
    event: AuditEvent,
}

impl PendingAuditEvent {
    #[must_use]
    pub const fn sequence(&self) -> AuditSequence {
        self.sequence
    }

    #[must_use]
    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditWalPolicy {
    max_bytes: u64,
    max_record_bytes: usize,
}

impl AuditWalPolicy {
    pub fn new(max_bytes: u64, max_record_bytes: usize) -> Result<Self, AuditWalError> {
        if max_bytes <= FILE_HEADER_BYTES as u64
            || max_record_bytes < RECORD_HEADER_BYTES
            || u64::try_from(max_record_bytes).map_or(true, |record_bytes| record_bytes > max_bytes)
        {
            return Err(AuditWalError::InvalidPolicy);
        }
        Ok(Self {
            max_bytes,
            max_record_bytes,
        })
    }
}

struct WalState {
    file: File,
    bytes: u64,
    last_sequence: u64,
    pending: BTreeMap<AuditSequence, PendingAuditEvent>,
    by_event_id: HashMap<AuditEventId, AuditSequence>,
}

pub struct AuditWal {
    path: PathBuf,
    policy: AuditWalPolicy,
    state: Mutex<WalState>,
}

impl AuditWal {
    pub fn open(path: impl AsRef<Path>, policy: AuditWalPolicy) -> Result<Self, AuditWalError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(AuditWalError::io)?;
        let mut file_len = file.metadata().map_err(AuditWalError::io)?.len();
        if file_len == 0 {
            file.write_all(FILE_MAGIC).map_err(AuditWalError::io)?;
            file.write_all(&FILE_VERSION.to_be_bytes())
                .map_err(AuditWalError::io)?;
            file.write_all(&0_u64.to_be_bytes())
                .map_err(AuditWalError::io)?;
            file.sync_all().map_err(AuditWalError::io)?;
            file_len = FILE_HEADER_BYTES as u64;
            file.seek(SeekFrom::Start(0)).map_err(AuditWalError::io)?;
        }
        if file_len > policy.max_bytes {
            return Err(AuditWalError::WalExceedsLimit);
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(file_len).map_err(|_| AuditWalError::WalExceedsLimit)?,
        );
        file.read_to_end(&mut bytes).map_err(AuditWalError::io)?;
        if bytes.len() < FILE_HEADER_BYTES
            || &bytes[0..4] != FILE_MAGIC
            || u32::from_be_bytes(
                bytes[4..8]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            ) != FILE_VERSION
        {
            return Err(AuditWalError::CorruptRecord);
        }
        let stored_high_watermark = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| AuditWalError::CorruptRecord)?,
        );

        let mut pending = BTreeMap::new();
        let mut by_event_id = HashMap::new();
        let mut position = FILE_HEADER_BYTES;
        let mut previous_sequence = 0_u64;
        let mut last_sequence = stored_high_watermark;
        while position < bytes.len() {
            if bytes.len() - position < FRAME_HEADER_BYTES {
                break;
            }
            let body_len = u32::from_be_bytes(
                bytes[position..position + 4]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            ) as usize;
            if body_len < RECORD_HEADER_BYTES || body_len > policy.max_record_bytes {
                return Err(AuditWalError::CorruptRecord);
            }
            let frame_end = position
                .checked_add(FRAME_HEADER_BYTES)
                .and_then(|header_end| header_end.checked_add(body_len))
                .ok_or(AuditWalError::CorruptRecord)?;
            if frame_end > bytes.len() {
                break;
            }
            let expected_checksum = u32::from_be_bytes(
                bytes[position + 4..position + 8]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            );
            let body = &bytes[position + FRAME_HEADER_BYTES..frame_end];
            if crc32(body) != expected_checksum {
                return Err(AuditWalError::CorruptRecord);
            }
            let sequence = u64::from_be_bytes(
                body[0..8]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            );
            let critical = match body[8] {
                0 => false,
                1 => true,
                _ => return Err(AuditWalError::CorruptRecord),
            };
            let id_len = u16::from_be_bytes(
                body[9..11]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            ) as usize;
            let kind_len = u16::from_be_bytes(
                body[11..13]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            ) as usize;
            let payload_len = u32::from_be_bytes(
                body[13..17]
                    .try_into()
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            ) as usize;
            let expected_body_len = RECORD_HEADER_BYTES
                .checked_add(id_len)
                .and_then(|length| length.checked_add(kind_len))
                .and_then(|length| length.checked_add(payload_len))
                .ok_or(AuditWalError::CorruptRecord)?;
            if expected_body_len != body.len() || sequence == 0 || sequence <= previous_sequence {
                return Err(AuditWalError::CorruptRecord);
            }
            let id_end = RECORD_HEADER_BYTES + id_len;
            let kind_end = id_end + kind_len;
            let event_id = AuditEventId::new(
                std::str::from_utf8(&body[RECORD_HEADER_BYTES..id_end])
                    .map_err(|_| AuditWalError::CorruptRecord)?,
            )
            .map_err(|_| AuditWalError::CorruptRecord)?;
            let kind = std::str::from_utf8(&body[id_end..kind_end])
                .map_err(|_| AuditWalError::CorruptRecord)?
                .to_owned();
            if kind.is_empty() || by_event_id.contains_key(&event_id) {
                return Err(AuditWalError::CorruptRecord);
            }
            let sequence = AuditSequence(sequence);
            let record = PendingAuditEvent {
                sequence,
                event: AuditEvent {
                    id: event_id.clone(),
                    kind,
                    payload: body[kind_end..].to_vec(),
                    critical,
                },
            };
            pending.insert(sequence, record);
            by_event_id.insert(event_id, sequence);
            previous_sequence = sequence.get();
            last_sequence = last_sequence.max(sequence.get());
            position = frame_end;
        }

        if position < bytes.len() {
            file.set_len(position as u64).map_err(AuditWalError::io)?;
        }
        if last_sequence != stored_high_watermark {
            file.seek(SeekFrom::Start(8)).map_err(AuditWalError::io)?;
            file.write_all(&last_sequence.to_be_bytes())
                .map_err(AuditWalError::io)?;
        }
        file.sync_all().map_err(AuditWalError::io)?;
        file.seek(SeekFrom::End(0)).map_err(AuditWalError::io)?;
        Ok(Self {
            path,
            policy,
            state: Mutex::new(WalState {
                file,
                bytes: position as u64,
                last_sequence,
                pending,
                by_event_id,
            }),
        })
    }

    pub fn append(&self, event: AuditEvent) -> Result<AppendOutcome, AuditWalError> {
        let mut state = self.lock_state()?;
        if let Some(sequence) = state.by_event_id.get(event.id()).copied() {
            let existing = state
                .pending
                .get(&sequence)
                .ok_or(AuditWalError::StateUnavailable)?;
            return if existing.event == event {
                Ok(AppendOutcome::Existing(sequence))
            } else {
                Err(AuditWalError::EventIdConflict)
            };
        }
        let sequence = AuditSequence(
            state
                .last_sequence
                .checked_add(1)
                .ok_or(AuditWalError::SequenceExhausted)?,
        );
        let frame = self.encode_record(sequence, &event)?;
        let frame_len = u64::try_from(frame.len()).map_err(|_| AuditWalError::RecordTooLarge)?;
        if state.bytes.saturating_add(frame_len) > self.policy.max_bytes {
            return if event.is_critical() {
                Err(AuditWalError::FullCritical)
            } else {
                Ok(AppendOutcome::DroppedNonCritical)
            };
        }

        let original_len = state.bytes;
        let original_sequence_bytes = state.last_sequence.to_be_bytes();
        if let Err(error) = state
            .file
            .write_all(&frame)
            .and_then(|()| state.file.seek(SeekFrom::Start(8)).map(|_| ()))
            .and_then(|()| state.file.write_all(&sequence.get().to_be_bytes()))
            .and_then(|()| state.file.seek(SeekFrom::End(0)).map(|_| ()))
            .and_then(|()| state.file.sync_all())
        {
            state
                .file
                .set_len(original_len)
                .and_then(|()| state.file.seek(SeekFrom::Start(8)).map(|_| ()))
                .and_then(|()| state.file.write_all(&original_sequence_bytes))
                .and_then(|()| state.file.seek(SeekFrom::End(0)).map(|_| ()))
                .and_then(|()| state.file.sync_all())
                .map_err(AuditWalError::io)?;
            return Err(AuditWalError::io(error));
        }
        state.bytes += frame_len;
        state.last_sequence = sequence.get();
        state.by_event_id.insert(event.id().clone(), sequence);
        state
            .pending
            .insert(sequence, PendingAuditEvent { sequence, event });
        Ok(AppendOutcome::Durable(sequence))
    }

    pub fn ack(&self, sequence: AuditSequence) -> Result<AckOutcome, AuditWalError> {
        let mut state = self.lock_state()?;
        if !state.pending.contains_key(&sequence) {
            return Ok(AckOutcome::AlreadyAbsent);
        }
        let temporary_path = self.path.with_extension("compact.tmp");
        let mut temporary = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary_path)
            .map_err(AuditWalError::io)?;
        temporary
            .write_all(FILE_MAGIC)
            .and_then(|()| temporary.write_all(&FILE_VERSION.to_be_bytes()))
            .and_then(|()| temporary.write_all(&state.last_sequence.to_be_bytes()))
            .map_err(AuditWalError::io)?;
        let mut compacted_bytes = FILE_HEADER_BYTES as u64;
        for (pending_sequence, pending) in &state.pending {
            if *pending_sequence == sequence {
                continue;
            }
            let frame = self.encode_record(*pending_sequence, pending.event())?;
            temporary.write_all(&frame).map_err(AuditWalError::io)?;
            compacted_bytes = compacted_bytes
                .checked_add(u64::try_from(frame.len()).map_err(|_| AuditWalError::RecordTooLarge)?)
                .ok_or(AuditWalError::WalExceedsLimit)?;
        }
        temporary.sync_all().map_err(AuditWalError::io)?;
        std::fs::rename(&temporary_path, &self.path).map_err(AuditWalError::io)?;
        let mut replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(AuditWalError::io)?;
        replacement
            .seek(SeekFrom::End(0))
            .map_err(AuditWalError::io)?;
        state.file = replacement;
        state.bytes = compacted_bytes;
        let removed = state
            .pending
            .remove(&sequence)
            .ok_or(AuditWalError::StateUnavailable)?;
        state.by_event_id.remove(removed.event().id());
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(AuditWalError::io)?;
        }
        Ok(AckOutcome::Acked)
    }

    pub fn pending(&self) -> Result<Vec<PendingAuditEvent>, AuditWalError> {
        Ok(self.lock_state()?.pending.values().cloned().collect())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, WalState>, AuditWalError> {
        self.state
            .lock()
            .map_err(|_| AuditWalError::StateUnavailable)
    }

    fn encode_record(
        &self,
        sequence: AuditSequence,
        event: &AuditEvent,
    ) -> Result<Vec<u8>, AuditWalError> {
        let id = event.id().as_str().as_bytes();
        let kind = event.kind().as_bytes();
        let id_len = u16::try_from(id.len()).map_err(|_| AuditWalError::RecordTooLarge)?;
        let kind_len = u16::try_from(kind.len()).map_err(|_| AuditWalError::RecordTooLarge)?;
        let payload_len =
            u32::try_from(event.payload().len()).map_err(|_| AuditWalError::RecordTooLarge)?;
        if kind.is_empty() {
            return Err(AuditWalError::InvalidEventKind);
        }
        let body_len = RECORD_HEADER_BYTES
            .checked_add(id.len())
            .and_then(|length| length.checked_add(kind.len()))
            .and_then(|length| length.checked_add(event.payload().len()))
            .ok_or(AuditWalError::RecordTooLarge)?;
        if body_len > self.policy.max_record_bytes || body_len > u32::MAX as usize {
            return Err(AuditWalError::RecordTooLarge);
        }
        let mut body = Vec::with_capacity(body_len);
        body.extend_from_slice(&sequence.get().to_be_bytes());
        body.push(u8::from(event.is_critical()));
        body.extend_from_slice(&id_len.to_be_bytes());
        body.extend_from_slice(&kind_len.to_be_bytes());
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(id);
        body.extend_from_slice(kind);
        body.extend_from_slice(event.payload());

        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&crc32(&body).to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendOutcome {
    Durable(AuditSequence),
    Existing(AuditSequence),
    DroppedNonCritical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckOutcome {
    Acked,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditWalError {
    InvalidPolicy,
    InvalidEventId,
    InvalidEventKind,
    RecordTooLarge,
    FullCritical,
    WalExceedsLimit,
    CorruptRecord,
    EventIdConflict,
    SequenceExhausted,
    StateUnavailable,
    Io(String),
}

impl AuditWalError {
    fn io(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl fmt::Display for AuditWalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "audit WAL error: {self:?}")
    }
}

impl std::error::Error for AuditWalError {}
