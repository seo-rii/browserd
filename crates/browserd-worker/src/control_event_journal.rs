//! Bounded, single-writer control-event outbox. ACK never resets a session sequence.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use browserd_core::{
    NotificationAck, NotificationCommit, NotificationControlState, NotificationDescriptor,
    NotificationSessionScope, NotificationSourceFamily, NotificationSourceScope, PageId,
    PlacementFence, WorkerId, WorkerNotificationEvent,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    MAX_CONTROL_EVENT_PAGE, SystemWorkerClock, WorkerClock, WorkerControlEvent, WorkerError,
    WorkerNotificationPage, WorkerSessionFence,
};

// A Human grant must retain the ability to durably return control even with a stalled relay.
// One finite Agent frame (including its longest valid worker ID and sequence/timestamp) is
// smaller than this fixed reserve. The pending-count reserve is independent of byte capacity.
const RETURN_CONTROL_FRAME_RESERVE: usize = 4096;
const MAX_JOURNAL_PENDING: usize = 65_536;
const MAX_JOURNAL_SCOPES: usize = 65_536;
const MAX_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    sequences: BTreeMap<String, u64>,
    pending: Vec<WorkerControlEvent>,
    /// Omission preserves byte-for-byte legacy snapshot checksums.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notifications: Option<NotificationState>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationState {
    worker_id: WorkerId,
    floor: u64,
    entries: BTreeMap<String, NotificationEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationEntry {
    scope: NotificationSourceScope,
    session: NotificationSessionScope,
    sequence: u64,
    control_epoch: u64,
    human: bool,
    page_id: Option<PageId>,
    acknowledged: Option<NotificationAck>,
    pending: Vec<NotificationCommit>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    snapshot: Snapshot,
    checksum: Vec<u8>,
}

struct Disk {
    directory: File,
    path: PathBuf,
    _lock: File,
}
struct State {
    snapshot: Snapshot,
    poisoned: bool,
}

pub struct ControlEventJournal {
    state: Mutex<State>,
    disk: Option<Disk>,
    max_pending: usize,
    max_scopes: usize,
    max_bytes: usize,
    clock: Arc<dyn WorkerClock>,
}

fn unavailable<E>(_: E) -> WorkerError {
    WorkerError::DurabilityUnavailable
}
fn scope(fence: &WorkerSessionFence) -> String {
    format!("{}/{}", fence.tenant_id, fence.session_id)
}

impl ControlEventJournal {
    pub(crate) fn memory() -> Self {
        Self {
            state: Mutex::new(State {
                snapshot: Snapshot::default(),
                poisoned: false,
            }),
            disk: None,
            max_pending: 1024,
            max_scopes: 65_536,
            max_bytes: 8 * 1024 * 1024,
            clock: Arc::new(SystemWorkerClock),
        }
    }

    pub fn open(
        path: &Path,
        max_pending: usize,
        max_scopes: usize,
        max_bytes: usize,
    ) -> Result<Self, WorkerError> {
        if !path.is_absolute()
            || !(1..=MAX_JOURNAL_PENDING).contains(&max_pending)
            || !(1..=MAX_JOURNAL_SCOPES).contains(&max_scopes)
            || !(1024..=MAX_JOURNAL_BYTES).contains(&max_bytes)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let parent = path.parent().ok_or(WorkerError::InvalidConfiguration)?;
        let name = path.file_name().ok_or(WorkerError::InvalidConfiguration)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(parent)
            .map_err(unavailable)?;
        let uid = std::fs::metadata("/proc/self").map_err(unavailable)?.uid();
        let metadata = directory.metadata().map_err(unavailable)?;
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        // Pin the checked directory for the lifetime of the writer, including rename/fsync.
        let base = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let pinned_path = base.join(name);
        let lock_path = base.join(format!("{}.lock", name.to_string_lossy()));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(unavailable)?;
        let metadata = lock.metadata().map_err(unavailable)?;
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        lock.try_lock().map_err(unavailable)?;
        let snapshot = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&pinned_path)
        {
            Ok(file) => {
                let metadata = file.metadata().map_err(unavailable)?;
                if !metadata.is_file()
                    || metadata.uid() != uid
                    || metadata.mode() & 0o077 != 0
                    || metadata.len() > max_bytes as u64
                {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                let mut bytes = Vec::new();
                file.take(max_bytes as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(unavailable)?;
                if bytes.len() > max_bytes {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                let envelope: Envelope = serde_json::from_slice(&bytes).map_err(unavailable)?;
                let encoded = serde_json::to_vec(&envelope.snapshot).map_err(unavailable)?;
                if envelope.version != 1 || Sha256::digest(encoded).as_slice() != envelope.checksum
                {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                envelope.snapshot
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Snapshot::default(),
            Err(error) => return Err(unavailable(error)),
        };
        let journal = Self {
            state: Mutex::new(State {
                snapshot,
                poisoned: false,
            }),
            disk: Some(Disk {
                directory,
                path: pinned_path,
                _lock: lock,
            }),
            max_pending,
            max_scopes,
            max_bytes,
            clock: Arc::new(SystemWorkerClock),
        };
        {
            let mut state = journal.state.lock().map_err(unavailable)?;
            journal.validate(&state.snapshot)?;
            // Establish an empty journal durably too, before the worker can accept requests.
            let snapshot = state.snapshot.clone();
            journal.commit(&mut state, snapshot)?;
        }
        Ok(journal)
    }

    /// Bind this journal's additive notification authority to one immutable original worker.
    /// Existing legacy events retain their original sequence and are drained through their
    /// existing ACK protocol; newly recorded changes only enter the notification lane.
    pub fn enable_notifications(&self, worker_id: &WorkerId) -> Result<(), WorkerError> {
        let mut state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        if let Some(notifications) = &state.snapshot.notifications {
            return if &notifications.worker_id == worker_id {
                Ok(())
            } else {
                Err(WorkerError::InvalidConfiguration)
            };
        }
        let mut snapshot = state.snapshot.clone();
        snapshot.notifications = Some(NotificationState {
            worker_id: worker_id.clone(),
            floor: 0,
            entries: BTreeMap::new(),
        });
        self.commit(&mut state, snapshot)
    }

    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn WorkerClock>) -> Self {
        self.clock = clock;
        self
    }

    fn validate(&self, snapshot: &Snapshot) -> Result<(), WorkerError> {
        if snapshot.pending.len() > self.max_pending
            || snapshot.sequences.len() > self.max_scopes
            || snapshot
                .sequences
                .values()
                .any(|value| *value == 0 || *value > i64::MAX as u64)
        {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut last = BTreeMap::new();
        for event in &snapshot.pending {
            if !event.fence.is_valid()
                || event.sequence == 0
                || event.control_epoch == 0
                || event.human != event.page_id.is_some()
            {
                return Err(WorkerError::DurabilityUnavailable);
            }
            let key = scope(&event.fence);
            if let Some(previous) = last.insert(key.clone(), event.sequence)
                && event.sequence != previous + 1
            {
                return Err(WorkerError::DurabilityUnavailable);
            }
            if snapshot
                .sequences
                .get(&key)
                .is_none_or(|high| event.sequence > *high)
            {
                return Err(WorkerError::DurabilityUnavailable);
            }
        }
        if last
            .iter()
            .any(|(key, value)| snapshot.sequences.get(key) != Some(value))
        {
            return Err(WorkerError::DurabilityUnavailable);
        }
        if let Some(notifications) = &snapshot.notifications {
            if notifications.floor > i64::MAX as u64
                || snapshot.sequences.len()
                    + notifications
                        .entries
                        .keys()
                        .filter(|key| !snapshot.sequences.contains_key(*key))
                        .count()
                    > self.max_scopes
            {
                return Err(WorkerError::DurabilityUnavailable);
            }
            let mut charged = snapshot.pending.len();
            for (key, entry) in &notifications.entries {
                entry.scope.validate().map_err(unavailable)?;
                entry.session.validate().map_err(unavailable)?;
                if entry.scope.original_worker_id() != &notifications.worker_id
                    || entry.scope.family() != NotificationSourceFamily::ControlJournal
                    || entry.scope.source_id() != *entry.session.session_id().as_uuid()
                    || *key != format!("{}/{}", entry.scope.tenant_id(), entry.session.session_id())
                    || entry.sequence == 0
                    || entry.sequence > i64::MAX as u64
                    || (entry.human && entry.sequence == i64::MAX as u64)
                    || entry.control_epoch == 0
                    || entry.human != entry.page_id.is_some()
                {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                let mut next = match &entry.acknowledged {
                    Some(ack) => {
                        ack.validate().map_err(unavailable)?;
                        if ack.scope() != &entry.scope || ack.source_sequence() > entry.sequence {
                            return Err(WorkerError::DurabilityUnavailable);
                        }
                        ack.source_sequence()
                    }
                    None => 0,
                };
                for commit in &entry.pending {
                    commit.validate().map_err(unavailable)?;
                    next = next
                        .checked_add(1)
                        .ok_or(WorkerError::DurabilityUnavailable)?;
                    if commit.scope() != &entry.scope
                        || commit.source_sequence() != next
                        || commit.occurred_at_unix_ms() > notifications.floor
                        || commit.descriptors().len() != 1
                        || commit.descriptors()[0].session_scope() != &entry.session
                        || !matches!(
                            commit.descriptors()[0].event(),
                            WorkerNotificationEvent::BrowserControlChanged { .. }
                        )
                    {
                        return Err(WorkerError::DurabilityUnavailable);
                    }
                }
                if next != entry.sequence {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                if let Some(last) = entry.pending.last()
                    && !matches!(last.descriptors()[0].event(), WorkerNotificationEvent::BrowserControlChanged { state }
                        if (*state == NotificationControlState::Human) == entry.human)
                {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                charged = charged
                    .checked_add(entry.pending.len())
                    .and_then(|value| value.checked_add(usize::from(entry.human)))
                    .ok_or(WorkerError::DurabilityUnavailable)?;
            }
            if charged > self.max_pending {
                return Err(WorkerError::DurabilityUnavailable);
            }
        }
        Ok(())
    }

    fn commit(&self, state: &mut State, snapshot: Snapshot) -> Result<(), WorkerError> {
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        self.validate(&snapshot)?;
        let checksum = Sha256::digest(serde_json::to_vec(&snapshot).map_err(unavailable)?).to_vec();
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            snapshot: snapshot.clone(),
            checksum,
        })
        .map_err(unavailable)?;
        let human_sources = snapshot.notifications.as_ref().map_or(0, |notifications| {
            notifications
                .entries
                .values()
                .filter(|entry| entry.human)
                .count()
        });
        if human_sources
            .checked_mul(RETURN_CONTROL_FRAME_RESERVE)
            .and_then(|reserve| bytes.len().checked_add(reserve))
            .is_none_or(|charged| charged > self.max_bytes)
        {
            return Err(WorkerError::DurabilityUnavailable);
        }
        if let Some(disk) = &self.disk {
            let temporary = disk
                .path
                .with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
            let result = (|| -> std::io::Result<()> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                std::fs::rename(&temporary, &disk.path)?;
                disk.directory.sync_all()
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(temporary);
                state.poisoned = true;
                return Err(WorkerError::DurabilityUnavailable);
            }
        }
        state.snapshot = snapshot;
        Ok(())
    }

    pub fn record(
        &self,
        fence: WorkerSessionFence,
        control_epoch: u64,
        human: bool,
        page_id: Option<PageId>,
    ) -> Result<WorkerControlEvent, WorkerError> {
        let mut state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut snapshot = state.snapshot.clone();
        if !fence.is_valid() || control_epoch == 0 || human != page_id.is_some() {
            return Err(WorkerError::InvalidActionTransition);
        }
        if let Some(notifications) = &mut snapshot.notifications {
            let source = NotificationSourceScope::new(
                fence.tenant_id.clone(),
                notifications.worker_id.clone(),
                *fence.session_id.as_uuid(),
                NotificationSourceFamily::ControlJournal,
            )
            .map_err(unavailable)?;
            let session = NotificationSessionScope::new(
                fence.session_id.clone(),
                PlacementFence::new(
                    fence.worker_epoch,
                    fence.placement_version,
                    fence.session_incarnation,
                ),
            )
            .map_err(unavailable)?;
            let key = scope(&fence);
            let existing = notifications.entries.get(&key);
            if existing.is_some_and(|entry| entry.scope != source || entry.session != session) {
                return Err(WorkerError::StaleFence);
            }
            if existing.is_some_and(|entry| entry.control_epoch > control_epoch) {
                return Err(WorkerError::InvalidActionTransition);
            }
            let sequence = existing
                .map_or(0, |entry| entry.sequence)
                .checked_add(1)
                .ok_or(WorkerError::DurabilityUnavailable)?;
            let occurred_at = self.clock.now()?.get().max(notifications.floor);
            let descriptor = NotificationDescriptor::fresh(
                session.clone(),
                WorkerNotificationEvent::BrowserControlChanged {
                    state: if human {
                        NotificationControlState::Human
                    } else {
                        NotificationControlState::Agent
                    },
                },
            )
            .map_err(unavailable)?;
            let commit =
                NotificationCommit::new(source.clone(), sequence, occurred_at, vec![descriptor])
                    .map_err(unavailable)?;
            let entry = notifications
                .entries
                .entry(key)
                .or_insert_with(|| NotificationEntry {
                    scope: source,
                    session,
                    sequence: 0,
                    control_epoch,
                    human,
                    page_id: page_id.clone(),
                    acknowledged: None,
                    pending: Vec::new(),
                });
            entry.sequence = sequence;
            entry.control_epoch = control_epoch;
            entry.human = human;
            entry.page_id = page_id.clone();
            entry.pending.push(commit);
            notifications.floor = occurred_at;
            let event = WorkerControlEvent {
                fence,
                sequence,
                control_epoch,
                human,
                page_id,
            };
            self.commit(&mut state, snapshot)?;
            return Ok(event);
        }
        if state.snapshot.pending.len() >= self.max_pending {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let sequence = snapshot
            .sequences
            .get(&scope(&fence))
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(WorkerError::DurabilityUnavailable)?;
        snapshot.sequences.insert(scope(&fence), sequence);
        let event = WorkerControlEvent {
            fence,
            sequence,
            control_epoch,
            human,
            page_id,
        };
        snapshot.pending.push(event.clone());
        self.commit(&mut state, snapshot)?;
        Ok(event)
    }

    pub fn pending(&self, limit: usize) -> Result<Vec<WorkerControlEvent>, WorkerError> {
        if !(1..=MAX_CONTROL_EVENT_PAGE).contains(&limit) {
            return Err(WorkerError::InvalidConfiguration);
        }
        let state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        Ok(state.snapshot.pending.iter().take(limit).cloned().collect())
    }

    pub fn ack(&self, event: &WorkerControlEvent) -> Result<(), WorkerError> {
        if !event.fence.is_valid() || event.sequence == 0 {
            return Err(WorkerError::InvalidActionTransition);
        }
        let mut state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let key = scope(&event.fence);
        let Some(index) = state
            .snapshot
            .pending
            .iter()
            .position(|pending| scope(&pending.fence) == key)
        else {
            return if event.sequence > 0
                && state
                    .snapshot
                    .sequences
                    .get(&key)
                    .is_some_and(|high| event.sequence <= *high)
            {
                Ok(())
            } else {
                Err(WorkerError::InvalidActionTransition)
            };
        };
        let first = &state.snapshot.pending[index];
        if event.sequence < first.sequence {
            return Ok(());
        }
        if first != event {
            return Err(WorkerError::InvalidActionTransition);
        }
        let mut snapshot = state.snapshot.clone();
        snapshot.pending.remove(index);
        self.commit(&mut state, snapshot)
    }

    /// At most one oldest commit per source, with a fixed total descriptor budget.
    pub fn pending_notifications(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<WorkerNotificationPage, WorkerError> {
        if !(1..=crate::MAX_NOTIFICATION_SCOPES_PER_PAGE).contains(&limit)
            || cursor.is_some_and(|cursor| {
                cursor.is_empty() || cursor.len() > 1024 || cursor.chars().any(char::is_control)
            })
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let Some(notifications) = &state.snapshot.notifications else {
            return Ok(WorkerNotificationPage::empty());
        };
        let mut entries = notifications
            .entries
            .iter()
            .filter(|(key, _)| cursor.is_none_or(|cursor| key.as_str() > cursor))
            .peekable();
        let mut page = WorkerNotificationPage::empty();
        while page.examined < limit {
            let Some((key, entry)) = entries.peek() else {
                break;
            };
            if !entry.pending.is_empty()
                && page.commits.len() == crate::MAX_NOTIFICATION_PAGE_DESCRIPTORS
            {
                break;
            }
            let key = (*key).clone();
            let entry = *entry;
            entries.next();
            page.examined += 1;
            page.cursor = Some(key);
            if let Some(commit) = entry.pending.first() {
                page.commits.push(commit.clone());
            }
        }
        page.is_complete = entries.peek().is_none();
        Ok(page)
    }

    pub fn ack_notification(&self, ack: &NotificationAck) -> Result<(), WorkerError> {
        ack.validate().map_err(unavailable)?;
        let mut state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut snapshot = state.snapshot.clone();
        let notifications = snapshot
            .notifications
            .as_mut()
            .ok_or(WorkerError::DurabilityUnavailable)?;
        if ack.scope().family() != NotificationSourceFamily::ControlJournal
            || ack.scope().original_worker_id() != &notifications.worker_id
        {
            return Err(WorkerError::StaleFence);
        }
        let key = format!("{}/{}", ack.scope().tenant_id(), ack.scope().source_id());
        let entry = notifications
            .entries
            .get_mut(&key)
            .ok_or(WorkerError::SessionNotFound)?;
        if entry.scope != *ack.scope() {
            return Err(WorkerError::StaleFence);
        }
        if entry.acknowledged.as_ref() == Some(ack) {
            return Ok(());
        }
        if entry
            .pending
            .first()
            .is_none_or(|commit| commit.ack() != *ack)
        {
            return Err(WorkerError::StaleFence);
        }
        entry.pending.remove(0);
        entry.acknowledged = Some(ack.clone());
        self.commit(&mut state, snapshot)
    }
}
