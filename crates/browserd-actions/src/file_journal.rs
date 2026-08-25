use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use browserd_core::ActionId;
use nix::unistd::Uid;
use sha2::{Digest, Sha256};

use crate::{
    ApprovalDecision, DurableActionJournal, JournalEntry, JournalEntryKind, JournalError,
    KnownFailureReason, ReplayableActionJournal, TerminalDetail,
};

const FILE_HEADER: &[u8; 8] = b"BRACTJ01";
const LENGTH_BYTES: u64 = 4;
const CHECKSUM_BYTES: u64 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionJournalLimits {
    max_record_bytes: usize,
    max_records: usize,
    max_file_bytes: usize,
}

impl ActionJournalLimits {
    #[must_use]
    pub const fn new(max_record_bytes: usize, max_records: usize, max_file_bytes: usize) -> Self {
        Self {
            max_record_bytes,
            max_records,
            max_file_bytes,
        }
    }

    #[must_use]
    pub const fn max_record_bytes(self) -> usize {
        self.max_record_bytes
    }

    #[must_use]
    pub const fn max_records(self) -> usize {
        self.max_records
    }

    #[must_use]
    pub const fn max_file_bytes(self) -> usize {
        self.max_file_bytes
    }
}

impl Default for ActionJournalLimits {
    fn default() -> Self {
        Self::new(64 * 1024, 100_000, 64 * 1024 * 1024)
    }
}

#[derive(Debug)]
struct FileJournalState {
    file: File,
    records: usize,
    file_bytes: u64,
    last_action_sequence: u64,
    dispatch_intents: HashSet<ActionId>,
    approval_decisions: HashMap<ActionId, ApprovalDecision>,
    terminal_records: HashSet<ActionId>,
    poisoned: bool,
}

#[derive(Debug)]
pub struct FileActionJournal {
    path: PathBuf,
    limits: ActionJournalLimits,
    state: Mutex<FileJournalState>,
}

impl FileActionJournal {
    pub fn open(path: impl AsRef<Path>, limits: ActionJournalLimits) -> Result<Self, JournalError> {
        if limits.max_record_bytes == 0
            || limits.max_records == 0
            || limits.max_file_bytes < FILE_HEADER.len()
        {
            return Err(JournalError::new("action journal limits are invalid"));
        }
        let path = path.as_ref();
        if path.file_name().is_none() {
            return Err(JournalError::new("action journal path has no file name"));
        }
        let parent = path
            .parent()
            .filter(|candidate| !candidate.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let effective_uid = Uid::effective().as_raw();
        let mut inspected_parent = PathBuf::new();
        for component in parent.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => {
                    inspected_parent.push(component.as_os_str());
                }
                Component::CurDir => continue,
                Component::ParentDir => {
                    return Err(JournalError::new(
                        "action journal parent must not contain parent traversal",
                    ));
                }
                Component::Normal(component) => {
                    inspected_parent.push(component);
                }
            }
            let component_metadata = fs::symlink_metadata(&inspected_parent).map_err(|error| {
                JournalError::new(format!(
                    "action journal parent component is unavailable: {error}"
                ))
            })?;
            if component_metadata.file_type().is_symlink() {
                return Err(JournalError::new(
                    "action journal parent must not contain symbolic links",
                ));
            }
            if !component_metadata.is_dir() {
                return Err(JournalError::new(
                    "action journal parent component is not a directory",
                ));
            }
            if component_metadata.uid() != 0 && component_metadata.uid() != effective_uid {
                return Err(JournalError::new(
                    "action journal parent component has an untrusted owner",
                ));
            }
            if component_metadata.mode() & 0o022 != 0 && component_metadata.mode() & 0o1000 == 0 {
                return Err(JournalError::new(
                    "action journal parent permissions allow path replacement",
                ));
            }
        }
        let parent_metadata = fs::metadata(parent).map_err(|error| {
            JournalError::new(format!("action journal parent is unavailable: {error}"))
        })?;
        if !parent_metadata.is_dir() {
            return Err(JournalError::new(
                "action journal parent is not a directory",
            ));
        }
        if parent_metadata.uid() != 0 && parent_metadata.uid() != effective_uid {
            return Err(JournalError::new(
                "action journal parent has an untrusted owner",
            ));
        }
        if parent_metadata.mode() & 0o022 != 0 {
            return Err(JournalError::new(
                "action journal parent permissions allow path replacement",
            ));
        }

        let open_file = |create_new: bool| {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .append(true)
                .create_new(create_new)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
            options.open(path)
        };
        let (mut file, created) = match open_file(true) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let file = open_file(false).map_err(|open_error| {
                    JournalError::new(format!(
                        "action journal cannot be opened safely: {open_error}"
                    ))
                })?;
                (file, false)
            }
            Err(error) => {
                return Err(JournalError::new(format!(
                    "action journal cannot be created: {error}"
                )));
            }
        };
        file.try_lock().map_err(|error| {
            JournalError::new(format!("action journal already has a writer: {error}"))
        })?;

        let metadata = file.metadata().map_err(|error| {
            JournalError::new(format!("action journal metadata is unavailable: {error}"))
        })?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(JournalError::new(
                "action journal must be a regular, singly linked file",
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(JournalError::new(
                "action journal permissions must not grant group or other access",
            ));
        }

        if created {
            file.write_all(FILE_HEADER).map_err(|error| {
                JournalError::new(format!("action journal header write failed: {error}"))
            })?;
            file.flush().map_err(|error| {
                JournalError::new(format!("action journal header flush failed: {error}"))
            })?;
            file.sync_all().map_err(|error| {
                JournalError::new(format!("action journal header sync failed: {error}"))
            })?;
            let parent_file = File::open(parent).map_err(|error| {
                JournalError::new(format!("action journal parent cannot be opened: {error}"))
            })?;
            parent_file.sync_all().map_err(|error| {
                JournalError::new(format!("action journal parent sync failed: {error}"))
            })?;
        }

        let (entries, file_bytes) = scan(&mut file, limits)?;
        let mut last_action_sequence = 0_u64;
        let mut dispatch_intents = HashSet::new();
        let mut approval_decisions = HashMap::new();
        let mut terminal_records = HashSet::new();
        for entry in &entries {
            if matches!(entry.kind(), JournalEntryKind::Accepted { .. }) {
                let expected = last_action_sequence.checked_add(1).ok_or_else(|| {
                    JournalError::new("action journal accepted sequence overflow")
                })?;
                if entry.action_sequence().get() != expected {
                    return Err(JournalError::new(
                        "action journal accepted sequences are not contiguous",
                    ));
                }
                last_action_sequence = expected;
            }
            if matches!(entry.kind(), JournalEntryKind::DispatchIntent { .. })
                && !dispatch_intents.insert(entry.action_id().clone())
            {
                return Err(JournalError::new(
                    "action journal contains duplicate dispatch intents",
                ));
            }
            if let Some(decision) = approval_decision(entry.kind())
                && approval_decisions
                    .insert(entry.action_id().clone(), decision)
                    .is_some()
            {
                return Err(JournalError::new(
                    "action journal contains duplicate approval decisions",
                ));
            }
            if matches!(entry.kind(), JournalEntryKind::Terminal { .. })
                && !terminal_records.insert(entry.action_id().clone())
            {
                return Err(JournalError::new(
                    "action journal contains duplicate terminal records",
                ));
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            limits,
            state: Mutex::new(FileJournalState {
                file,
                records: entries.len(),
                file_bytes,
                last_action_sequence,
                dispatch_intents,
                approval_decisions,
                terminal_records,
                poisoned: false,
            }),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn limits(&self) -> ActionJournalLimits {
        self.limits
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, FileJournalState>, JournalError> {
        self.state
            .lock()
            .map_err(|_| JournalError::new("action journal lock is poisoned"))
    }
}

impl DurableActionJournal for FileActionJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        let payload = serde_json::to_vec(entry).map_err(|error| {
            JournalError::new(format!("action journal record encoding failed: {error}"))
        })?;
        if payload.is_empty() || payload.len() > self.limits.max_record_bytes {
            return Err(JournalError::new(
                "action journal record exceeds configured bound",
            ));
        }
        let payload_length = u32::try_from(payload.len())
            .map_err(|_| JournalError::new("action journal record exceeds format length bound"))?;
        let frame_bytes = LENGTH_BYTES
            .checked_add(u64::from(payload_length))
            .and_then(|length| length.checked_add(CHECKSUM_BYTES))
            .ok_or_else(|| JournalError::new("action journal frame length overflow"))?;
        let checksum = Sha256::digest(&payload);

        let mut state = self.lock_state()?;
        if state.poisoned {
            return Err(JournalError::new(
                "action journal is poisoned after a prior write failure",
            ));
        }
        if state.records >= self.limits.max_records {
            return Err(JournalError::new(
                "action journal record count exceeds configured bound",
            ));
        }
        let accepted_sequence = if matches!(entry.kind(), JournalEntryKind::Accepted { .. }) {
            let expected = state
                .last_action_sequence
                .checked_add(1)
                .ok_or_else(|| JournalError::new("action journal accepted sequence overflow"))?;
            if entry.action_sequence().get() != expected {
                return Err(JournalError::new(
                    "action journal recovery is required before appending",
                ));
            }
            Some(expected)
        } else {
            None
        };
        let dispatch_action_id = if matches!(entry.kind(), JournalEntryKind::DispatchIntent { .. })
        {
            if state.dispatch_intents.contains(entry.action_id()) {
                return Err(JournalError::new(
                    "action journal already contains a dispatch intent for this action",
                ));
            }
            Some(entry.action_id().clone())
        } else {
            None
        };
        let approval_decision = approval_decision(entry.kind()).map(|decision| {
            if decision == ApprovalDecision::Granted
                && state.terminal_records.contains(entry.action_id())
            {
                return Err(JournalError::new(
                    "action journal cannot grant approval after a terminal record",
                ));
            }
            if state.approval_decisions.contains_key(entry.action_id()) {
                return Err(JournalError::new(
                    "action journal already contains an approval decision for this action",
                ));
            }
            Ok((entry.action_id().clone(), decision))
        });
        let approval_decision = match approval_decision {
            Some(decision) => Some(decision?),
            None => None,
        };
        let terminal_action_id = if matches!(entry.kind(), JournalEntryKind::Terminal { .. }) {
            if state.terminal_records.contains(entry.action_id()) {
                return Err(JournalError::new(
                    "action journal already contains a terminal record for this action",
                ));
            }
            Some(entry.action_id().clone())
        } else {
            None
        };
        let next_file_bytes = state
            .file_bytes
            .checked_add(frame_bytes)
            .ok_or_else(|| JournalError::new("action journal size overflow"))?;
        if next_file_bytes > self.limits.max_file_bytes as u64 {
            return Err(JournalError::new(
                "action journal file exceeds configured bound",
            ));
        }

        let write_result = (|| -> std::io::Result<()> {
            state.file.write_all(&payload_length.to_be_bytes())?;
            state.file.write_all(&payload)?;
            state.file.write_all(&checksum)?;
            state.file.flush()?;
            state.file.sync_data()
        })();
        if let Err(error) = write_result {
            state.poisoned = true;
            return Err(JournalError::new(format!(
                "action journal durable append failed: {error}"
            )));
        }
        state.records += 1;
        state.file_bytes = next_file_bytes;
        if let Some(sequence) = accepted_sequence {
            state.last_action_sequence = sequence;
        }
        if let Some(action_id) = dispatch_action_id {
            state.dispatch_intents.insert(action_id);
        }
        if let Some((action_id, decision)) = approval_decision {
            state.approval_decisions.insert(action_id, decision);
        }
        if let Some(action_id) = terminal_action_id {
            state.terminal_records.insert(action_id);
        }
        Ok(())
    }
}

fn approval_decision(kind: &JournalEntryKind) -> Option<ApprovalDecision> {
    match kind {
        JournalEntryKind::ApprovalGranted => Some(ApprovalDecision::Granted),
        JournalEntryKind::Terminal {
            detail: TerminalDetail::FailedKnown(KnownFailureReason::ApprovalDenied),
        } => Some(ApprovalDecision::Denied),
        JournalEntryKind::Terminal {
            detail: TerminalDetail::FailedKnown(KnownFailureReason::ApprovalTimedOut),
        } => Some(ApprovalDecision::TimedOut),
        _ => None,
    }
}

impl ReplayableActionJournal for FileActionJournal {
    fn replay(&self) -> Result<Vec<JournalEntry>, JournalError> {
        let mut state = self.lock_state()?;
        if state.poisoned {
            return Err(JournalError::new(
                "action journal is poisoned after a prior write failure",
            ));
        }
        let (entries, file_bytes) = scan(&mut state.file, self.limits)?;
        if entries.len() != state.records || file_bytes != state.file_bytes {
            return Err(JournalError::new(
                "action journal changed outside its exclusive writer",
            ));
        }
        Ok(entries)
    }
}

fn scan(
    file: &mut File,
    limits: ActionJournalLimits,
) -> Result<(Vec<JournalEntry>, u64), JournalError> {
    let file_bytes = file
        .metadata()
        .map_err(|error| {
            JournalError::new(format!("action journal metadata is unavailable: {error}"))
        })?
        .len();
    if file_bytes > limits.max_file_bytes as u64 {
        return Err(JournalError::new(
            "action journal file exceeds configured bound",
        ));
    }
    if file_bytes < FILE_HEADER.len() as u64 {
        return Err(JournalError::new("truncated action journal header"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| JournalError::new(format!("action journal seek failed: {error}")))?;
    let mut header = [0_u8; FILE_HEADER.len()];
    file.read_exact(&mut header)
        .map_err(|error| JournalError::new(format!("truncated action journal header: {error}")))?;
    if &header != FILE_HEADER {
        return Err(JournalError::new(
            "action journal header or format version is invalid",
        ));
    }

    let mut offset = FILE_HEADER.len() as u64;
    let mut entries = Vec::new();
    while offset < file_bytes {
        if entries.len() >= limits.max_records {
            return Err(JournalError::new(
                "action journal record count exceeds configured bound",
            ));
        }
        let remaining = file_bytes - offset;
        if remaining < LENGTH_BYTES {
            return Err(JournalError::new("truncated action journal frame length"));
        }
        let mut length_bytes = [0_u8; LENGTH_BYTES as usize];
        file.read_exact(&mut length_bytes).map_err(|error| {
            JournalError::new(format!("truncated action journal frame length: {error}"))
        })?;
        let payload_length = u32::from_be_bytes(length_bytes) as usize;
        if payload_length == 0 || payload_length > limits.max_record_bytes {
            return Err(JournalError::new(
                "action journal record exceeds configured bound",
            ));
        }
        let frame_bytes = LENGTH_BYTES
            .checked_add(payload_length as u64)
            .and_then(|length| length.checked_add(CHECKSUM_BYTES))
            .ok_or_else(|| JournalError::new("action journal frame length overflow"))?;
        if remaining < frame_bytes {
            return Err(JournalError::new("truncated action journal frame"));
        }

        let mut payload = vec![0_u8; payload_length];
        file.read_exact(&mut payload).map_err(|error| {
            JournalError::new(format!("truncated action journal payload: {error}"))
        })?;
        let mut stored_checksum = [0_u8; CHECKSUM_BYTES as usize];
        file.read_exact(&mut stored_checksum).map_err(|error| {
            JournalError::new(format!("truncated action journal checksum: {error}"))
        })?;
        let computed_checksum = Sha256::digest(&payload);
        if computed_checksum.as_slice() != stored_checksum {
            return Err(JournalError::new("action journal checksum mismatch"));
        }
        let entry = serde_json::from_slice(&payload).map_err(|error| {
            JournalError::new(format!("action journal record is invalid: {error}"))
        })?;
        entries.push(entry);
        offset = offset
            .checked_add(frame_bytes)
            .ok_or_else(|| JournalError::new("action journal offset overflow"))?;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|error| JournalError::new(format!("action journal seek failed: {error}")))?;
    Ok((entries, file_bytes))
}
