//! Durable lifecycle/execution authority and its pending notification commits.
//! The finite state and notification are installed by one private, synced snapshot.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use browserd_actions::JournalSessionScope;
use browserd_core::{
    ActionId, NotificationAck, NotificationCommit, NotificationDescriptor,
    NotificationSessionExecutionState as Execution, NotificationSessionLifecycleState as Lifecycle,
    NotificationSessionScope, NotificationSourceFamily, NotificationSourceScope, SessionExecution,
    WorkerNotificationEvent,
};
use browserd_session::{SessionLifecycle, SessionMachine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{SystemWorkerClock, WorkerClock, WorkerError, WorkerNotificationPage};

const CLEANUP_FRAME_RESERVE: usize = 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    scope: NotificationSourceScope,
    session: NotificationSessionScope,
    lifecycle: Lifecycle,
    execution: Execution,
    action_id: Option<ActionId>,
    sequence: u64,
    acknowledged: Option<NotificationAck>,
    pending: Vec<NotificationCommit>,
}
impl Entry {
    fn reserved(&self) -> usize {
        let lifecycle = match self.lifecycle {
            Lifecycle::Creating => 3,
            Lifecycle::Ready => 2,
            Lifecycle::Closing => 1,
            Lifecycle::Closed | Lifecycle::Failed => 0,
        };
        let execution = match self.execution {
            Execution::Idle => 0,
            Execution::Running | Execution::PendingApproval => 2,
            Execution::ReconciliationRequired => 1,
        };
        lifecycle + execution
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    floor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_id: Option<browserd_core::WorkerId>,
    entries: BTreeMap<String, Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    snapshot: Snapshot,
    checksum: [u8; 32],
}
struct State {
    snapshot: Snapshot,
    poisoned: bool,
}
struct Disk {
    directory: File,
    path: PathBuf,
    _lock: File,
}

pub struct SessionEventJournal {
    state: Mutex<State>,
    disk: Option<Disk>,
    clock: Arc<dyn WorkerClock>,
    max_pending: usize,
    max_scopes: usize,
    max_bytes: usize,
}
fn unavailable<E>(_: E) -> WorkerError {
    WorkerError::DurabilityUnavailable
}
fn key(scope: &NotificationSourceScope) -> String {
    format!(
        "{}/{}/{}",
        scope.tenant_id(),
        hex::encode(scope.original_worker_id().as_str()),
        scope.source_id()
    )
}

impl SessionEventJournal {
    #[must_use]
    pub fn qualify(&self) -> bool {
        self.state.lock().is_ok_and(|state| !state.poisoned)
    }

    pub fn bind_worker(&self, worker: &browserd_core::WorkerId) -> Result<(), WorkerError> {
        let mut state = self.state.lock().map_err(unavailable)?;
        let mut snapshot = state.snapshot.clone();
        if snapshot
            .worker_id
            .as_ref()
            .is_some_and(|original| original != worker)
            || snapshot
                .entries
                .values()
                .any(|entry| entry.scope.original_worker_id() != worker)
        {
            return Err(WorkerError::StaleFence);
        }
        snapshot.worker_id = Some(worker.clone());
        self.commit(&mut state, snapshot)
    }
    pub fn open(
        path: &Path,
        max_pending: usize,
        max_scopes: usize,
        max_bytes: usize,
    ) -> Result<Self, WorkerError> {
        if !path.is_absolute()
            || !(4..=4096).contains(&max_pending)
            || !(1..=65_536).contains(&max_scopes)
            || !(CLEANUP_FRAME_RESERVE * 4..=64 * 1024 * 1024).contains(&max_bytes)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let parent = path.parent().ok_or(WorkerError::InvalidConfiguration)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(parent)
            .map_err(unavailable)?;
        let uid = std::fs::metadata("/proc/self").map_err(unavailable)?.uid();
        let meta = directory.metadata().map_err(unavailable)?;
        if meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        let base = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let name = path.file_name().ok_or(WorkerError::InvalidConfiguration)?;
        let pinned_path = base.join(name);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(base.join(format!("{}.lock", name.to_string_lossy())))
            .map_err(unavailable)?;
        let meta = lock.metadata().map_err(unavailable)?;
        if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        lock.try_lock().map_err(unavailable)?;
        let snapshot = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&pinned_path)
        {
            Ok(file) => {
                let meta = file.metadata().map_err(unavailable)?;
                if !meta.is_file()
                    || meta.uid() != uid
                    || meta.nlink() != 1
                    || meta.mode() & 0o077 != 0
                    || meta.len() > max_bytes as u64
                {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                let mut bytes = Vec::new();
                let read_limit = u64::try_from(max_bytes)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(WorkerError::InvalidConfiguration)?;
                file.take(read_limit)
                    .read_to_end(&mut bytes)
                    .map_err(unavailable)?;
                if bytes.len() > max_bytes {
                    return Err(WorkerError::DurabilityUnavailable);
                }
                let envelope: Envelope = serde_json::from_slice(&bytes).map_err(unavailable)?;
                if envelope.version != 1
                    || <[u8; 32]>::from(Sha256::digest(
                        serde_json::to_vec(&envelope.snapshot).map_err(unavailable)?,
                    )) != envelope.checksum
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
            clock: Arc::new(SystemWorkerClock),
            max_pending,
            max_scopes,
            max_bytes,
        };
        {
            let mut state = journal.state.lock().map_err(unavailable)?;
            let snapshot = state.snapshot.clone();
            journal.commit(&mut state, snapshot)?;
        }
        Ok(journal)
    }

    fn validate(&self, snapshot: &Snapshot) -> Result<(), WorkerError> {
        if snapshot.floor > i64::MAX as u64 || snapshot.entries.len() > self.max_scopes {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut charged = 0_usize;
        for (stored_key, entry) in &snapshot.entries {
            entry.scope.validate().map_err(unavailable)?;
            entry.session.validate().map_err(unavailable)?;
            if *stored_key != key(&entry.scope)
                || snapshot
                    .worker_id
                    .as_ref()
                    .is_some_and(|worker| entry.scope.original_worker_id() != worker)
                || entry.scope.family() != NotificationSourceFamily::SessionLifecycle
                || entry.scope.source_id() != *entry.session.session_id().as_uuid()
                || entry.sequence == 0
                || entry.sequence > i64::MAX as u64
                || (entry.execution == Execution::Idle) != entry.action_id.is_none()
            {
                return Err(WorkerError::DurabilityUnavailable);
            }
            let acked = match &entry.acknowledged {
                Some(ack) => {
                    ack.validate().map_err(unavailable)?;
                    if ack.scope() != &entry.scope || ack.source_sequence() > entry.sequence {
                        return Err(WorkerError::DurabilityUnavailable);
                    }
                    ack.source_sequence()
                }
                None => 0,
            };
            let mut next = acked;
            for commit in &entry.pending {
                commit.validate().map_err(unavailable)?;
                next = next
                    .checked_add(1)
                    .ok_or(WorkerError::DurabilityUnavailable)?;
                if commit.scope() != &entry.scope
                    || commit.source_sequence() != next
                    || commit.occurred_at_unix_ms() > snapshot.floor
                    || commit
                        .descriptors()
                        .iter()
                        .any(|d| d.session_scope() != &entry.session)
                {
                    return Err(WorkerError::DurabilityUnavailable);
                }
            }
            if next != entry.sequence {
                return Err(WorkerError::DurabilityUnavailable);
            }
            charged = charged
                .checked_add(entry.pending.len())
                .and_then(|v| v.checked_add(entry.reserved()))
                .ok_or(WorkerError::DurabilityUnavailable)?;
        }
        if charged > self.max_pending {
            return Err(WorkerError::DurabilityUnavailable);
        }
        Ok(())
    }

    fn commit(&self, state: &mut State, snapshot: Snapshot) -> Result<(), WorkerError> {
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        self.validate(&snapshot)?;
        let reserve = snapshot
            .entries
            .values()
            .try_fold(0_usize, |count, entry| {
                count.checked_add(entry.reserved().checked_mul(CLEANUP_FRAME_RESERVE)?)
            })
            .ok_or(WorkerError::DurabilityUnavailable)?;
        let checksum = Sha256::digest(serde_json::to_vec(&snapshot).map_err(unavailable)?).into();
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            snapshot: snapshot.clone(),
            checksum,
        })
        .map_err(unavailable)?;
        if bytes
            .len()
            .checked_add(reserve)
            .is_none_or(|size| size > self.max_bytes)
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

    pub(crate) fn record(
        &self,
        scope: &JournalSessionScope,
        lifecycle: Lifecycle,
        execution: Execution,
        action_id: Option<ActionId>,
    ) -> Result<(), WorkerError> {
        let source = NotificationSourceScope::new(
            scope.tenant_id().clone(),
            scope.original_worker_id().clone(),
            *scope.session_id().as_uuid(),
            NotificationSourceFamily::SessionLifecycle,
        )
        .map_err(unavailable)?;
        let session = NotificationSessionScope::new(scope.session_id().clone(), scope.fence())
            .map_err(unavailable)?;
        let mut state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut snapshot = state.snapshot.clone();
        if snapshot
            .worker_id
            .as_ref()
            .is_some_and(|worker| worker != scope.original_worker_id())
        {
            return Err(WorkerError::StaleFence);
        }
        snapshot.worker_id = Some(scope.original_worker_id().clone());
        let at = self.clock.now()?.get().max(snapshot.floor);
        snapshot.floor = at;
        let source_key = key(&source);
        let existing = snapshot.entries.get(&source_key);
        if existing.is_some_and(|entry| entry.scope != source || entry.session != session) {
            return Err(WorkerError::StaleFence);
        }
        if existing.is_none() && lifecycle != Lifecycle::Creating {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut descriptors = Vec::new();
        if existing.is_none_or(|entry| entry.lifecycle != lifecycle) {
            descriptors.push(
                NotificationDescriptor::fresh(
                    session.clone(),
                    WorkerNotificationEvent::SessionLifecycleChanged { state: lifecycle },
                )
                .map_err(unavailable)?,
            );
        }
        if existing
            .is_some_and(|entry| entry.execution != execution || entry.action_id != action_id)
        {
            descriptors.push(
                NotificationDescriptor::fresh(
                    session.clone(),
                    WorkerNotificationEvent::SessionExecutionChanged {
                        state: execution,
                        action_id: action_id.clone(),
                    },
                )
                .map_err(unavailable)?,
            );
        }
        if descriptors.is_empty() {
            return Ok(());
        }
        let sequence = existing
            .map_or(0, |entry| entry.sequence)
            .checked_add(1)
            .ok_or(WorkerError::DurabilityUnavailable)?;
        let commit = NotificationCommit::new(source.clone(), sequence, at, descriptors)
            .map_err(unavailable)?;
        let entry = snapshot.entries.entry(source_key).or_insert_with(|| Entry {
            scope: source,
            session,
            lifecycle,
            execution,
            action_id: action_id.clone(),
            sequence: 0,
            acknowledged: None,
            pending: Vec::new(),
        });
        entry.lifecycle = lifecycle;
        entry.execution = execution;
        entry.action_id = action_id;
        entry.sequence = sequence;
        entry.pending.push(commit);
        self.commit(&mut state, snapshot)
    }

    pub(crate) fn record_machine(
        &self,
        scope: &JournalSessionScope,
        machine: &SessionMachine,
    ) -> Result<(), WorkerError> {
        let snapshot = machine.snapshot();
        if snapshot.owner_fence.as_placement_fence() != scope.fence()
            || snapshot.owner_fence.worker_id() != scope.original_worker_id()
            || machine.session_id() != scope.session_id()
        {
            return Err(WorkerError::StaleFence);
        }
        let lifecycle = match snapshot.lifecycle {
            SessionLifecycle::Creating => Lifecycle::Creating,
            SessionLifecycle::Ready => Lifecycle::Ready,
            SessionLifecycle::Closing => Lifecycle::Closing,
            SessionLifecycle::Closed => Lifecycle::Closed,
            SessionLifecycle::Failed => Lifecycle::Failed,
        };
        let (execution, action_id) = match snapshot.execution {
            SessionExecution::Idle => (Execution::Idle, None),
            SessionExecution::Running(id) => (Execution::Running, Some(id)),
            SessionExecution::PendingApproval(id) => (Execution::PendingApproval, Some(id)),
            SessionExecution::ReconciliationRequired(id) => {
                (Execution::ReconciliationRequired, Some(id))
            }
        };
        self.record(scope, lifecycle, execution, action_id)
    }

    pub fn pending(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<WorkerNotificationPage, WorkerError> {
        if !(1..=crate::MAX_NOTIFICATION_SCOPES_PER_PAGE).contains(&limit)
            || cursor
                .is_some_and(|c| c.is_empty() || c.len() > 1024 || c.chars().any(char::is_control))
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut page = WorkerNotificationPage::empty();
        let mut count = 0;
        let mut entries = state
            .snapshot
            .entries
            .iter()
            .filter(|(key, _)| cursor.is_none_or(|cursor| key.as_str() > cursor))
            .peekable();
        while page.examined < limit {
            let Some((key, entry)) = entries.peek() else {
                break;
            };
            if entry.pending.first().is_some_and(|c| {
                count + c.descriptors().len() > crate::MAX_NOTIFICATION_PAGE_DESCRIPTORS
            }) {
                break;
            }
            let key = (*key).clone();
            let entry = *entry;
            entries.next();
            page.examined += 1;
            page.cursor = Some(key);
            if let Some(commit) = entry.pending.first() {
                count += commit.descriptors().len();
                page.commits.push(commit.clone());
            }
        }
        page.is_complete = entries.peek().is_none();
        Ok(page)
    }

    pub fn ack(&self, ack: &NotificationAck) -> Result<(), WorkerError> {
        ack.validate().map_err(unavailable)?;
        let mut state = self.state.lock().map_err(unavailable)?;
        if state.poisoned {
            return Err(WorkerError::DurabilityUnavailable);
        }
        let mut snapshot = state.snapshot.clone();
        let entry = snapshot
            .entries
            .get_mut(&key(ack.scope()))
            .ok_or(WorkerError::SessionNotFound)?;
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

#[cfg(test)]
mod tests;
