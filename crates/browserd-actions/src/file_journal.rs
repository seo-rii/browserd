use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use browserd_core::ActionId;
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat, openat2};
use nix::sys::stat::{Mode, fstat};
use nix::unistd::Uid;
use sha2::{Digest, Sha256};

use crate::{
    ApprovalDecision, DurableActionJournal, JournalEntry, JournalEntryKind, JournalError,
    KnownFailureReason, OutcomeUnknownReason, ReplayableActionJournal, ResultDigest,
    TerminalDetail,
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
    terminal_reserves: HashMap<ActionId, u64>,
    reserved_terminal_bytes: u64,
    poisoned: bool,
}

#[derive(Debug)]
pub struct FileActionJournal {
    path: PathBuf,
    limits: ActionJournalLimits,
    state: Mutex<FileJournalState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileOpenMode {
    OpenOrCreate,
    CreateNew,
}

impl FileActionJournal {
    pub fn open(path: impl AsRef<Path>, limits: ActionJournalLimits) -> Result<Self, JournalError> {
        Self::open_with_mode(path.as_ref(), limits, FileOpenMode::OpenOrCreate)
    }

    pub fn create_new(
        path: impl AsRef<Path>,
        limits: ActionJournalLimits,
    ) -> Result<Self, JournalError> {
        Self::open_with_mode(path.as_ref(), limits, FileOpenMode::CreateNew)
    }

    fn open_with_mode(
        path: &Path,
        limits: ActionJournalLimits,
        mode: FileOpenMode,
    ) -> Result<Self, JournalError> {
        Self::open_with_mode_after_parent_validation(path, limits, mode, || {})
    }

    fn open_with_mode_after_parent_validation(
        path: &Path,
        limits: ActionJournalLimits,
        mode: FileOpenMode,
        after_parent_validation: impl FnOnce(),
    ) -> Result<Self, JournalError> {
        if limits.max_record_bytes == 0
            || limits.max_records == 0
            || limits.max_file_bytes < FILE_HEADER.len()
        {
            return Err(JournalError::new("action journal limits are invalid"));
        }
        if path.file_name().is_none() {
            return Err(JournalError::new("action journal path has no file name"));
        }
        let parent = path
            .parent()
            .filter(|candidate| !candidate.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let effective_uid = Uid::effective().as_raw();
        let mut parent_components: Vec<&OsStr> = Vec::new();
        for component in parent.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Prefix(_) => {
                    return Err(JournalError::new(
                        "action journal parent prefix is unsupported",
                    ));
                }
                Component::ParentDir => {
                    return Err(JournalError::new(
                        "action journal parent must not contain parent traversal",
                    ));
                }
                Component::Normal(component) => parent_components.push(component),
            }
        }
        let directory_flags =
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        let mut parent_fd = open(
            if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            directory_flags,
            Mode::empty(),
        )
        .map_err(|error| {
            JournalError::new(format!("action journal parent is unavailable: {error}"))
        })?;
        let validate_directory = |directory: &OwnedFd, final_parent: bool| {
            let metadata = fstat(directory).map_err(|error| {
                JournalError::new(format!(
                    "action journal parent metadata is unavailable: {error}"
                ))
            })?;
            if metadata.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR || metadata.st_nlink == 0
            {
                return Err(JournalError::new(
                    "action journal parent component is not a linked directory",
                ));
            }
            if metadata.st_uid != 0 && metadata.st_uid != effective_uid {
                return Err(JournalError::new(
                    "action journal parent component has an untrusted owner",
                ));
            }
            let writable_by_others = metadata.st_mode & 0o022 != 0;
            let sticky = metadata.st_mode & 0o1000 != 0;
            if writable_by_others && (final_parent || !sticky) {
                return Err(JournalError::new(
                    "action journal parent permissions allow path replacement",
                ));
            }
            Ok(())
        };
        validate_directory(&parent_fd, parent_components.is_empty())?;
        for (index, component) in parent_components.iter().enumerate() {
            let next = openat2(
                &parent_fd,
                Path::new(component),
                OpenHow::new().flags(directory_flags).resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_SYMLINKS
                        | ResolveFlag::RESOLVE_NO_MAGICLINKS,
                ),
            )
            .map_err(|error| {
                JournalError::new(format!(
                    "action journal parent component is unavailable: {error}"
                ))
            })?;
            validate_directory(&next, index + 1 == parent_components.len())?;
            parent_fd = next;
        }
        after_parent_validation();
        validate_directory(&parent_fd, true)?;

        let file_name = path
            .file_name()
            .ok_or_else(|| JournalError::new("action journal path has no file name"))?;
        let file_flags = OFlag::O_RDWR
            | OFlag::O_APPEND
            | OFlag::O_CLOEXEC
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK;
        let open_file = |create_new: bool| {
            let creation_flags = if create_new {
                OFlag::O_CREAT | OFlag::O_EXCL
            } else {
                OFlag::empty()
            };
            openat(
                &parent_fd,
                file_name,
                file_flags | creation_flags,
                Mode::from_bits_truncate(0o600),
            )
        };
        let (file_fd, created) = match open_file(true) {
            Ok(file) => (file, true),
            Err(Errno::EEXIST) => {
                if mode == FileOpenMode::CreateNew {
                    return Err(JournalError::new(format!(
                        "action journal already exists: {}",
                        Errno::EEXIST
                    )));
                }
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
        let metadata = fstat(&file_fd).map_err(|error| {
            JournalError::new(format!("action journal metadata is unavailable: {error}"))
        })?;
        if metadata.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG || metadata.st_nlink != 1 {
            return Err(JournalError::new(
                "action journal must be a regular, singly linked file",
            ));
        }
        if metadata.st_uid != 0 && metadata.st_uid != effective_uid {
            return Err(JournalError::new("action journal has an untrusted owner"));
        }
        if metadata.st_mode & 0o077 != 0 {
            return Err(JournalError::new(
                "action journal permissions must not grant group or other access",
            ));
        }
        let mut file = File::from(file_fd);
        file.try_lock().map_err(|error| {
            JournalError::new(format!("action journal already has a writer: {error}"))
        })?;

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
            let parent_file = File::from(parent_fd);
            parent_file.sync_all().map_err(|error| {
                JournalError::new(format!("action journal parent sync failed: {error}"))
            })?;
        }

        let (entries, file_bytes) = scan(&mut file, limits)?;
        let mut last_action_sequence = 0_u64;
        let mut dispatch_intents = HashSet::new();
        let mut approval_decisions = HashMap::new();
        let mut terminal_records = HashSet::new();
        let mut terminal_reserves = HashMap::new();
        let mut reserved_terminal_bytes = 0_u64;
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
                let reserve = terminal_reserve_frame_bytes(entry, limits)?;
                if terminal_reserves
                    .insert(entry.action_id().clone(), reserve)
                    .is_some()
                {
                    return Err(JournalError::new(
                        "action journal contains a duplicate accepted action",
                    ));
                }
                reserved_terminal_bytes = reserved_terminal_bytes
                    .checked_add(reserve)
                    .ok_or_else(|| JournalError::new("action journal terminal reserve overflow"))?;
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
            if matches!(entry.kind(), JournalEntryKind::Terminal { .. }) {
                let reserve = terminal_reserves.remove(entry.action_id()).ok_or_else(|| {
                    JournalError::new("action journal terminal record has no accepted action")
                })?;
                reserved_terminal_bytes =
                    reserved_terminal_bytes
                        .checked_sub(reserve)
                        .ok_or_else(|| {
                            JournalError::new("action journal terminal reserve underflow")
                        })?;
            }
        }
        if entries.len().saturating_add(terminal_reserves.len()) > limits.max_records
            || file_bytes
                .checked_add(reserved_terminal_bytes)
                .is_none_or(|required| required > limits.max_file_bytes as u64)
        {
            return Err(JournalError::new(
                "action journal cannot preserve terminal record reserves",
            ));
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
                terminal_reserves,
                reserved_terminal_bytes,
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
        let accepted_terminal_reserve = matches!(entry.kind(), JournalEntryKind::Accepted { .. })
            .then(|| terminal_reserve_frame_bytes(entry, self.limits))
            .transpose()?;
        let released_terminal_reserve = if matches!(entry.kind(), JournalEntryKind::Terminal { .. })
        {
            Some(
                *state
                    .terminal_reserves
                    .get(entry.action_id())
                    .ok_or_else(|| {
                        JournalError::new("action journal terminal record has no reserved capacity")
                    })?,
            )
        } else {
            None
        };
        let reserved_actions_after = state
            .terminal_reserves
            .len()
            .checked_add(usize::from(accepted_terminal_reserve.is_some()))
            .and_then(|count| count.checked_sub(usize::from(released_terminal_reserve.is_some())))
            .ok_or_else(|| JournalError::new("action journal terminal reserve count overflow"))?;
        let records_after = state
            .records
            .checked_add(1)
            .ok_or_else(|| JournalError::new("action journal record count overflow"))?;
        if records_after
            .checked_add(reserved_actions_after)
            .is_none_or(|required| required > self.limits.max_records)
        {
            return Err(JournalError::new(
                "action journal record count would consume terminal reserves",
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
        let reserved_terminal_bytes_after = state
            .reserved_terminal_bytes
            .checked_add(accepted_terminal_reserve.unwrap_or(0))
            .and_then(|bytes| bytes.checked_sub(released_terminal_reserve.unwrap_or(0)))
            .ok_or_else(|| JournalError::new("action journal terminal reserve size overflow"))?;
        if next_file_bytes
            .checked_add(reserved_terminal_bytes_after)
            .is_none_or(|required| required > self.limits.max_file_bytes as u64)
        {
            return Err(JournalError::new(
                "action journal file would consume terminal reserves",
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
        if let Some(reserve) = accepted_terminal_reserve {
            state
                .terminal_reserves
                .insert(entry.action_id().clone(), reserve);
        }
        if released_terminal_reserve.is_some() {
            state.terminal_reserves.remove(entry.action_id());
        }
        state.reserved_terminal_bytes = reserved_terminal_bytes_after;
        Ok(())
    }
}

fn terminal_reserve_frame_bytes(
    entry: &JournalEntry,
    limits: ActionJournalLimits,
) -> Result<u64, JournalError> {
    let candidates = [
        TerminalDetail::Succeeded(ResultDigest::new([u8::MAX; 32])),
        TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        TerminalDetail::FailedKnown(KnownFailureReason::PolicyDenied),
        TerminalDetail::FailedKnown(KnownFailureReason::ApprovalDenied),
        TerminalDetail::FailedKnown(KnownFailureReason::ApprovalTimedOut),
        TerminalDetail::CancelledBeforeDispatch,
        TerminalDetail::CancelledConfirmed,
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::AmbiguousTransportLoss),
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch),
    ];
    let mut largest_payload = 0_usize;
    for detail in candidates {
        let mut terminal = entry.clone();
        terminal.kind = JournalEntryKind::Terminal { detail };
        let payload = serde_json::to_vec(&terminal).map_err(|error| {
            JournalError::new(format!(
                "action journal terminal reserve encoding failed: {error}"
            ))
        })?;
        largest_payload = largest_payload.max(payload.len());
    }
    if largest_payload == 0 || largest_payload > limits.max_record_bytes {
        return Err(JournalError::new(
            "action journal cannot reserve a bounded terminal record",
        ));
    }
    LENGTH_BYTES
        .checked_add(largest_payload as u64)
        .and_then(|length| length.checked_add(CHECKSUM_BYTES))
        .ok_or_else(|| JournalError::new("action journal terminal reserve length overflow"))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs;
    use std::os::unix::fs::symlink;

    use super::{ActionJournalLimits, FILE_HEADER, FileActionJournal, FileOpenMode};

    #[test]
    fn concurrent_parent_swap_cannot_redirect_wal_creation() {
        let directory = tempfile::tempdir().expect("temporary root should be created");
        let original_parent = directory.path().join("journal-parent");
        let moved_parent = directory.path().join("pinned-parent");
        let outside_parent = directory.path().join("outside-parent");
        fs::create_dir(&original_parent).expect("original parent should be created");
        fs::create_dir(&outside_parent).expect("outside parent should be created");
        let requested_path = original_parent.join("actions.wal");

        let journal = FileActionJournal::open_with_mode_after_parent_validation(
            &requested_path,
            ActionJournalLimits::default(),
            FileOpenMode::OpenOrCreate,
            || {
                fs::rename(&original_parent, &moved_parent)
                    .expect("validated parent should be moved");
                symlink(&outside_parent, &original_parent)
                    .expect("requested parent name should be replaced by a symlink");
            },
        )
        .expect("the pinned original parent should remain usable");
        drop(journal);

        assert!(moved_parent.join("actions.wal").exists());
        assert!(!outside_parent.join("actions.wal").exists());
    }

    #[test]
    fn concurrent_parent_swap_cannot_redirect_existing_wal_open() {
        let directory = tempfile::tempdir().expect("temporary root should be created");
        let original_parent = directory.path().join("journal-parent");
        let moved_parent = directory.path().join("pinned-parent");
        let outside_parent = directory.path().join("outside-parent");
        fs::create_dir(&original_parent).expect("original parent should be created");
        fs::create_dir(&outside_parent).expect("outside parent should be created");
        let requested_path = original_parent.join("actions.wal");
        drop(
            FileActionJournal::create_new(&requested_path, ActionJournalLimits::default())
                .expect("original WAL should be initialized"),
        );
        fs::write(outside_parent.join("actions.wal"), b"attacker-controlled")
            .expect("outside decoy should be created");

        let journal = FileActionJournal::open_with_mode_after_parent_validation(
            &requested_path,
            ActionJournalLimits::default(),
            FileOpenMode::OpenOrCreate,
            || {
                fs::rename(&original_parent, &moved_parent)
                    .expect("validated parent should be moved");
                symlink(&outside_parent, &original_parent)
                    .expect("requested parent name should be replaced by a symlink");
            },
        )
        .expect("recovery must use the WAL below the pinned original parent");
        drop(journal);

        assert_eq!(
            fs::read(moved_parent.join("actions.wal"))
                .expect("original WAL should remain readable"),
            FILE_HEADER
        );
        assert_eq!(
            fs::read(outside_parent.join("actions.wal"))
                .expect("outside decoy should remain readable"),
            b"attacker-controlled"
        );
    }
}
