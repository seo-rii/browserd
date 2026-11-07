use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use browserd_core::{ActionId, ApprovalId, NotificationSourceFamily, NotificationSourceScope};
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
    approval_ids: HashMap<ActionId, ApprovalId>,
    last_notification_sequence: u64,
    terminal_records: HashSet<ActionId>,
    terminal_reserves: HashMap<ActionId, u64>,
    reserved_terminal_bytes: u64,
    poisoned: bool,
    #[cfg(test)]
    fail_after_write: bool,
}

pub(crate) trait JournalBudget: std::fmt::Debug + Send + Sync {
    fn reserve(&self, entry: &JournalEntry, total_bytes: u64) -> Result<(), JournalError>;
    fn committed(&self, total_bytes: u64);
}

#[derive(Debug)]
pub struct FileActionJournal {
    path: PathBuf,
    limits: ActionJournalLimits,
    state: Mutex<FileJournalState>,
    budget: Option<Arc<dyn JournalBudget>>,
    notification_source: Option<NotificationSourceScope>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileOpenMode {
    OpenOrCreate,
    CreateNew,
    Existing,
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

        Self::open_pinned(path, parent_fd, limits, mode)
    }

    pub(crate) fn create_at(
        path: &Path,
        parent: &File,
        limits: ActionJournalLimits,
    ) -> Result<Self, JournalError> {
        let fd: OwnedFd = parent
            .try_clone()
            .map_err(|_| JournalError::new("journal directory clone failed"))?
            .into();
        Self::open_pinned(path, fd, limits, FileOpenMode::CreateNew)
    }

    pub(crate) fn open_at(
        path: &Path,
        parent: &File,
        limits: ActionJournalLimits,
    ) -> Result<Self, JournalError> {
        let fd: OwnedFd = parent
            .try_clone()
            .map_err(|_| JournalError::new("journal directory clone failed"))?
            .into();
        Self::open_pinned(path, fd, limits, FileOpenMode::Existing)
    }

    fn open_pinned(
        path: &Path,
        parent_fd: OwnedFd,
        limits: ActionJournalLimits,
        mode: FileOpenMode,
    ) -> Result<Self, JournalError> {
        let effective_uid = Uid::effective().as_raw();
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
        let (file_fd, created) = match open_file(mode != FileOpenMode::Existing) {
            Ok(file) => (file, mode != FileOpenMode::Existing),
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
        let mut approval_ids = HashMap::new();
        let notification_source = entries
            .iter()
            .find_map(|e| e.notifications().map(|c| c.scope().clone()));
        let mut last_notification_sequence = 0_u64;
        let mut terminal_records = HashSet::new();
        let mut terminal_reserves = HashMap::new();
        let mut reserved_terminal_bytes = 0_u64;
        for entry in &entries {
            if matches!(entry.kind(), JournalEntryKind::ApprovalRequired)
                && let Some(id) = entry.approval_id()
                && (approval_ids.values().any(|known| known == id)
                    || approval_ids
                        .insert(entry.action_id().clone(), id.clone())
                        .is_some())
            {
                return Err(JournalError::new(
                    "action journal approval identity is duplicated",
                ));
            }
            if let Some(source) = &notification_source {
                let sequence = last_notification_sequence
                    .checked_add(1)
                    .ok_or_else(|| JournalError::new("action notification sequence overflow"))?;
                crate::notifications::validate_entry_notification(
                    entry,
                    source,
                    sequence,
                    approval_ids.get(entry.action_id()),
                    approval_decisions.contains_key(entry.action_id()),
                )?;
                if entry.notifications().is_some() {
                    last_notification_sequence = sequence;
                }
            }
            if matches!(entry.kind(), JournalEntryKind::Accepted { .. }) {
                let expected = last_action_sequence.checked_add(1).ok_or_else(|| {
                    JournalError::new("action journal accepted sequence overflow")
                })?;
                if entry.action_sequence().get() < expected {
                    return Err(JournalError::new(
                        "action journal accepted sequences are not monotonic",
                    ));
                }
                last_action_sequence = entry.action_sequence().get();
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
            budget: None,
            notification_source,
            state: Mutex::new(FileJournalState {
                file,
                records: entries.len(),
                file_bytes,
                last_action_sequence,
                dispatch_intents,
                approval_decisions,
                approval_ids,
                last_notification_sequence,
                terminal_records,
                terminal_reserves,
                reserved_terminal_bytes,
                poisoned: false,
                #[cfg(test)]
                fail_after_write: false,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn inject_post_write_failure(&self) -> Result<(), JournalError> {
        self.lock_state()?.fail_after_write = true;
        Ok(())
    }

    pub(crate) fn with_budget(mut self, budget: Arc<dyn JournalBudget>) -> Self {
        self.budget = Some(budget);
        self
    }

    pub fn with_notification_source(
        mut self,
        source: NotificationSourceScope,
    ) -> Result<Self, JournalError> {
        source
            .validate()
            .map_err(|_| JournalError::new("action notification source is invalid"))?;
        if source.family() != NotificationSourceFamily::ActionJournal {
            return Err(JournalError::new(
                "action journal notification family is invalid",
            ));
        }
        let state = self.lock_state()?;
        if self
            .notification_source
            .as_ref()
            .is_some_and(|known| known != &source)
            || (self.notification_source.is_none() && state.records != 0)
        {
            return Err(JournalError::new(
                "legacy action journal cannot acquire notification authority",
            ));
        }
        drop(state);
        self.notification_source = Some(source);
        Ok(self)
    }

    pub(crate) fn charged_bytes(&self) -> Result<u64, JournalError> {
        let state = self.lock_state()?;
        state
            .file_bytes
            .checked_add(state.reserved_terminal_bytes)
            .ok_or_else(|| JournalError::new("journal charge overflow"))
    }

    pub(crate) fn identity(&self) -> Result<(u64, u64), JournalError> {
        use std::os::unix::fs::MetadataExt;
        let state = self.lock_state()?;
        let metadata = state
            .file
            .metadata()
            .map_err(|_| JournalError::new("journal identity unavailable"))?;
        Ok((metadata.dev(), metadata.ino()))
    }

    pub(crate) fn with_replay<T>(
        &self,
        consume: impl FnOnce(&[JournalEntry]) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let mut state = self.lock_state()?;
        if state.poisoned {
            return Err(JournalError::new("action journal is poisoned"));
        }
        let (entries, file_bytes) = scan(&mut state.file, self.limits)?;
        if entries.len() != state.records || file_bytes != state.file_bytes {
            return Err(JournalError::new(
                "action journal changed outside its writer",
            ));
        }
        consume(&entries)
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
        if entry.notifications().is_some() {
            return Err(JournalError::new(
                "action notification metadata must be minted by the original append",
            ));
        }
        let mut state = self.lock_state()?;
        if state.poisoned {
            return Err(JournalError::new(
                "action journal is poisoned after a prior write failure",
            ));
        }
        let mut entry = entry.clone();
        let approval_identity = if matches!(entry.kind(), JournalEntryKind::ApprovalRequired) {
            if let Some(id) = entry.approval_id() {
                if state.approval_ids.contains_key(entry.action_id())
                    || state.approval_ids.values().any(|known| known == id)
                {
                    return Err(JournalError::new(
                        "action journal approval identity is duplicated",
                    ));
                }
                Some(id.clone())
            } else {
                None
            }
        } else {
            let known = state.approval_ids.get(entry.action_id()).cloned();
            if entry
                .approval_id()
                .is_some_and(|id| Some(id) != known.as_ref())
            {
                return Err(JournalError::new(
                    "action journal approval identity contradicts original requirement",
                ));
            }
            known
        };
        if let Some(source) = &self.notification_source {
            let next_sequence = state
                .last_notification_sequence
                .checked_add(1)
                .ok_or_else(|| JournalError::new("action notification sequence overflow"))?;
            let occurred = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| JournalError::new("action notification clock unavailable"))?;
            let occurred_ms = u64::try_from(occurred.as_millis())
                .map_err(|_| JournalError::new("action notification clock overflow"))?;
            entry.notifications = crate::notifications::commit_for_entry(
                source,
                next_sequence,
                occurred_ms,
                &entry,
                approval_identity.as_ref(),
                state.approval_decisions.contains_key(entry.action_id()),
            )?;
        }
        if self.notification_source.is_some()
            && matches!(
                entry.kind(),
                JournalEntryKind::ApprovalGranted
                    | JournalEntryKind::Terminal { .. }
                    | JournalEntryKind::Resolved { .. }
            )
        {
            entry.approval_id = approval_identity.clone();
        }
        let entry = &entry;
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
            if entry.action_sequence().get() < expected {
                return Err(JournalError::new(
                    "action journal recovery is required before appending",
                ));
            }
            Some(entry.action_sequence().get())
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

        let charged_after = next_file_bytes
            .checked_add(reserved_terminal_bytes_after)
            .ok_or_else(|| JournalError::new("journal charge overflow"))?;
        if let Some(budget) = &self.budget {
            budget.reserve(entry, charged_after)?;
        }

        let write_result = (|| -> std::io::Result<()> {
            state.file.write_all(&payload_length.to_be_bytes())?;
            state.file.write_all(&payload)?;
            state.file.write_all(&checksum)?;
            #[cfg(test)]
            if std::mem::take(&mut state.fail_after_write) {
                return Err(std::io::Error::other("injected post-write failure"));
            }
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
        if let Some(commit) = entry.notifications() {
            state.last_notification_sequence = commit.source_sequence();
        }
        if matches!(entry.kind(), JournalEntryKind::ApprovalRequired)
            && let Some(id) = approval_identity
        {
            state.approval_ids.insert(entry.action_id().clone(), id);
        }
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
        if let Some(budget) = &self.budget {
            budget.committed(charged_after);
        }
        Ok(())
    }

    fn notification_source(&self) -> Option<NotificationSourceScope> {
        self.notification_source.clone()
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
        TerminalDetail::FailedKnown(KnownFailureReason::ExecutionTimedOut),
        TerminalDetail::FailedKnown(KnownFailureReason::SnapshotTooLarge),
        TerminalDetail::FailedKnown(KnownFailureReason::DocumentChanged),
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
        if let Some(commit) = entry.notifications() {
            let approval_id = ApprovalId::from_uuid(*entry.action_id().as_uuid())
                .map_err(|_| JournalError::new("action reserve identity is invalid"))?;
            terminal.approval_id = Some(approval_id.clone());
            terminal.notifications = crate::notifications::commit_for_entry(
                commit.scope(),
                i64::MAX as u64,
                i64::MAX as u64,
                &terminal,
                Some(&approval_id),
                false,
            )?;
        }
        let mut wire = serde_json::to_value(&terminal)
            .map_err(|_| JournalError::new("action reserve encoding failed"))?;
        if let Some(commit) = wire.get_mut("notifications") {
            // SHA bytes occupy one to three decimal digits; reserve the largest exact wire shape.
            commit["digest"] = serde_json::to_value([u8::MAX; 32])
                .map_err(|_| JournalError::new("action reserve digest encoding failed"))?;
        }
        let payload = serde_json::to_vec(&wire).map_err(|error| {
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
