//! Bounded worker-owned WAL custody. Historical reads never construct a browser session.
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use browserd_core::{
    ActionId, MAX_NOTIFICATION_DESCRIPTORS, NotificationAck, NotificationSourceFamily,
    NotificationSourceScope, SessionId, TenantId, WorkerId,
};
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{Uid, UnlinkatFlags, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::file_journal::JournalBudget;
use crate::{
    ActionJournalLimits, ActionLedger, ActionNotificationPage, DurableActionJournal,
    FileActionJournal, JournalEntry, JournalEntryKind, JournalError, JournalSessionScope,
    ReplayableActionJournal, TerminalCustodyReceipt,
};

const MANIFEST_BYTES: u64 = 256 * 1024;
const METADATA_RESERVATION: u64 = 2 * MANIFEST_BYTES;
const MAX_ACTIONS: usize = 1024;
const SESSION_INODES: usize = 3;
const RETENTION_DEFAULT: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionJournalPoolLimits {
    worker_bytes: u64,
    tenant_bytes: u64,
    worker_inodes: usize,
    tenant_inodes: usize,
    retention_millis: u64,
}
impl Default for ActionJournalPoolLimits {
    fn default() -> Self {
        Self {
            worker_bytes: 1024 * 1024 * 1024,
            tenant_bytes: 256 * 1024 * 1024,
            worker_inodes: 3072,
            tenant_inodes: 384,
            retention_millis: RETENTION_DEFAULT,
        }
    }
}
impl ActionJournalPoolLimits {
    pub fn new(
        worker_bytes: u64,
        tenant_bytes: u64,
        worker_inodes: usize,
        tenant_inodes: usize,
        retention_millis: u64,
    ) -> Result<Self, JournalError> {
        let limits = Self {
            worker_bytes,
            tenant_bytes,
            worker_inodes,
            tenant_inodes,
            retention_millis,
        };
        limits.validate()?;
        Ok(limits)
    }
    fn validate(self) -> Result<(), JournalError> {
        if self.worker_bytes < METADATA_RESERVATION + 8
            || self.tenant_bytes < METADATA_RESERVATION + 8
            || self.tenant_bytes > self.worker_bytes
            || self.worker_inodes < SESSION_INODES
            || self.tenant_inodes < SESSION_INODES
            || self.tenant_inodes > self.worker_inodes
            || self.worker_inodes > 65_536
            || self.retention_millis < RETENTION_DEFAULT
        {
            return Err(err("journal pool limits are invalid"));
        }
        Ok(())
    }
    #[must_use]
    pub const fn worker_bytes(self) -> u64 {
        self.worker_bytes
    }
    #[must_use]
    pub const fn tenant_bytes(self) -> u64 {
        self.tenant_bytes
    }
    #[must_use]
    pub const fn worker_inodes(self) -> usize {
        self.worker_inodes
    }
    #[must_use]
    pub const fn tenant_inodes(self) -> usize {
        self.tenant_inodes
    }
    #[must_use]
    pub const fn retention_millis(self) -> u64 {
        self.retention_millis
    }
}
#[derive(Clone, Debug)]
pub struct ActionJournalPoolConfig {
    directory: PathBuf,
    journal_limits: ActionJournalLimits,
    limits: ActionJournalPoolLimits,
}
impl ActionJournalPoolConfig {
    pub fn new(
        directory: PathBuf,
        journal_limits: ActionJournalLimits,
    ) -> Result<Self, JournalError> {
        let config = Self {
            directory,
            journal_limits,
            limits: ActionJournalPoolLimits::default(),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn with_limits(mut self, limits: ActionJournalPoolLimits) -> Result<Self, JournalError> {
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }
    fn validate(&self) -> Result<(), JournalError> {
        self.limits.validate()?;
        if !self.directory.is_absolute()
            || self.journal_limits.max_record_bytes() == 0
            || self.journal_limits.max_records() == 0
            || self.journal_limits.max_file_bytes() < 8
        {
            return Err(err("journal pool configuration is invalid"));
        }
        Ok(())
    }
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    #[must_use]
    pub const fn journal_limits(&self) -> ActionJournalLimits {
        self.journal_limits
    }
    #[must_use]
    pub const fn limits(&self) -> ActionJournalPoolLimits {
        self.limits
    }
}

#[derive(Debug)]
pub struct ManagedActionJournal {
    journal: FileActionJournal,
    // Fields drop in declaration order: the real WAL FD closes before this pin.
    _pin: Option<WalPin>,
}
impl ManagedActionJournal {
    #[must_use]
    pub const fn unmanaged(journal: FileActionJournal) -> Self {
        Self {
            journal,
            _pin: None,
        }
    }
}
#[derive(Debug)]
struct WalPin(Arc<AtomicUsize>);
impl Drop for WalPin {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl DurableActionJournal for ManagedActionJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        self.journal.append(entry)
    }
    fn notification_source(&self) -> Option<NotificationSourceScope> {
        self.journal.notification_source()
    }
}
impl ReplayableActionJournal for ManagedActionJournal {
    fn replay(&self) -> Result<Vec<JournalEntry>, JournalError> {
        self.journal.replay()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u8,
    scope: JournalSessionScope,
    device: u64,
    inode: u64,
    sealed_at: Option<u64>,
    #[serde(default)]
    last_ack_at: Option<u64>,
    #[serde(default)]
    last_release_at: Option<u64>,
    delete_intent: bool,
    delete_charge: Option<u64>,
    acks: Vec<CustodyAck>,
    #[serde(default, skip_serializing_if = "is_false")]
    notifications_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notification_ack: Option<NotificationAck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_notification_ack_at: Option<u64>,
}
fn is_false(value: &bool) -> bool {
    !value
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CustodyAck {
    action_id: ActionId,
    digest: [u8; 32],
    #[serde(default)]
    released: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestEnvelope {
    record: Manifest,
    checksum: [u8; 32],
}
#[derive(Debug)]
struct Record {
    manifest: Option<Manifest>,
    tenant: Option<TenantId>,
    wal_charge: u64,
    metadata_charge: u64,
    inodes: usize,
    accepted: HashSet<ActionId>,
    live: Weak<ManagedActionJournal>,
    pins: Arc<AtomicUsize>,
}
#[derive(Debug, Default)]
struct PoolState {
    records: BTreeMap<SessionId, Record>,
    poisoned: bool,
    cursor: Option<SessionId>,
}
#[derive(Debug)]
pub struct ActionJournalPool {
    config: ActionJournalPoolConfig,
    worker_id: WorkerId,
    root: File,
    state: Mutex<PoolState>,
    operations: Mutex<()>,
    #[cfg(test)]
    fault: AtomicUsize,
}
#[derive(Debug)]
struct PoolBudget {
    pool: Arc<ActionJournalPool>,
    scope: JournalSessionScope,
}
impl JournalBudget for PoolBudget {
    fn reserve(&self, entry: &JournalEntry, total_bytes: u64) -> Result<(), JournalError> {
        if entry.tenant_id() != self.scope.tenant_id()
            || entry.session_id() != self.scope.session_id()
            || entry.fence() != self.scope.fence()
        {
            return Err(err("managed journal entry scope mismatch"));
        }
        let mut state = self.pool.state()?;
        if state.poisoned {
            return Err(err("journal pool admission is closed"));
        }
        let record = state
            .records
            .get(self.scope.session_id())
            .ok_or_else(|| err("managed journal record is missing"))?;
        let manifest = record
            .manifest
            .as_ref()
            .ok_or_else(|| err("managed journal manifest is missing"))?;
        if manifest.scope != self.scope
            || manifest.delete_intent
            || (manifest.sealed_at.is_some()
                && !matches!(entry.kind(), JournalEntryKind::Resolved { .. }))
        {
            return Err(err("managed journal is sealed for new work"));
        }
        let accepted = matches!(entry.kind(), JournalEntryKind::Accepted { .. });
        if accepted
            && (record.accepted.len() >= MAX_ACTIONS || record.accepted.contains(entry.action_id()))
        {
            return Err(err("managed journal accepted-action bound exceeded"));
        }
        let growth = total_bytes.saturating_sub(record.wal_charge);
        self.pool
            .check_growth(&state, Some(self.scope.tenant_id()), growth, 0)?;
        let record = state
            .records
            .get_mut(self.scope.session_id())
            .ok_or_else(|| err("managed journal record is missing"))?;
        record.wal_charge = record.wal_charge.max(total_bytes);
        if accepted {
            record.accepted.insert(entry.action_id().clone());
        }
        Ok(())
    }
    fn committed(&self, total_bytes: u64) {
        // File lock -> pool lock; no pool lock survives disk IO. Poison preserves conservative charge.
        match self.pool.state.lock() {
            Ok(mut state) => {
                if let Some(record) = state.records.get_mut(self.scope.session_id()) {
                    record.wal_charge = total_bytes;
                } else {
                    state.poisoned = true;
                }
            }
            Err(poison) => {
                poison.into_inner().poisoned = true;
            }
        }
    }
}

impl ActionJournalPool {
    pub fn open(
        config: ActionJournalPoolConfig,
        worker_id: WorkerId,
    ) -> Result<Arc<Self>, JournalError> {
        config.validate()?;
        let root = open_root(&config.directory)?;
        root.try_lock()
            .map_err(|_| err("journal pool already has a writer"))?;
        let pool = Arc::new(Self {
            config,
            worker_id,
            root,
            state: Mutex::new(PoolState::default()),
            operations: Mutex::new(()),
            #[cfg(test)]
            fault: AtomicUsize::new(0),
        });
        pool.inventory()?;
        Ok(pool)
    }
    fn state(&self) -> Result<MutexGuard<'_, PoolState>, JournalError> {
        self.state
            .lock()
            .map_err(|_| err("journal pool lock poisoned"))
    }
    fn operation(&self) -> Result<MutexGuard<'_, ()>, JournalError> {
        self.operations
            .lock()
            .map_err(|_| err("journal pool operation lock poisoned"))
    }
    fn poison(&self) {
        match self.state.lock() {
            Ok(mut state) => state.poisoned = true,
            Err(poison) => poison.into_inner().poisoned = true,
        }
    }
    fn check_growth(
        &self,
        state: &PoolState,
        tenant: Option<&TenantId>,
        bytes: u64,
        inodes: usize,
    ) -> Result<(), JournalError> {
        let mut worker_bytes = bytes;
        let mut worker_inodes = inodes;
        let mut tenant_bytes = bytes;
        let mut tenant_inodes = inodes;
        for record in state.records.values() {
            let charge = record
                .wal_charge
                .checked_add(record.metadata_charge)
                .ok_or_else(|| err("journal pool accounting overflow"))?;
            worker_bytes = worker_bytes
                .checked_add(charge)
                .ok_or_else(|| err("journal pool accounting overflow"))?;
            worker_inodes = worker_inodes
                .checked_add(record.inodes)
                .ok_or_else(|| err("journal pool accounting overflow"))?;
            // Unattributed legacy bytes consume every tenant's admission budget, never a free bucket.
            if tenant.is_none() || record.tenant.is_none() || record.tenant.as_ref() == tenant {
                tenant_bytes = tenant_bytes
                    .checked_add(charge)
                    .ok_or_else(|| err("journal pool accounting overflow"))?;
                tenant_inodes = tenant_inodes
                    .checked_add(record.inodes)
                    .ok_or_else(|| err("journal pool accounting overflow"))?;
            }
        }
        let limits = self.config.limits;
        if worker_bytes > limits.worker_bytes
            || worker_inodes > limits.worker_inodes
            || (tenant.is_some()
                && (tenant_bytes > limits.tenant_bytes || tenant_inodes > limits.tenant_inodes))
        {
            return Err(err("journal pool quota exceeded"));
        }
        Ok(())
    }
    pub fn create_session(
        self: &Arc<Self>,
        scope: &JournalSessionScope,
    ) -> Result<Arc<ManagedActionJournal>, JournalError> {
        self.create_session_internal(scope, false)
    }

    pub fn create_notifying_session(
        self: &Arc<Self>,
        scope: &JournalSessionScope,
    ) -> Result<Arc<ManagedActionJournal>, JournalError> {
        self.create_session_internal(scope, true)
    }

    fn create_session_internal(
        self: &Arc<Self>,
        scope: &JournalSessionScope,
        notifications_enabled: bool,
    ) -> Result<Arc<ManagedActionJournal>, JournalError> {
        scope.validate()?;
        if scope.original_worker_id() != &self.worker_id {
            return Err(err("journal pool worker identity mismatch"));
        }
        let _operation = self.operation()?;
        {
            let mut state = self.state()?;
            if state.poisoned || state.records.contains_key(scope.session_id()) {
                return Err(err("journal session cannot be created"));
            }
            self.check_growth(
                &state,
                Some(scope.tenant_id()),
                METADATA_RESERVATION + 8,
                SESSION_INODES,
            )?;
            state.records.insert(
                scope.session_id().clone(),
                Record {
                    manifest: None,
                    tenant: Some(scope.tenant_id().clone()),
                    wal_charge: 8,
                    metadata_charge: METADATA_RESERVATION,
                    inodes: SESSION_INODES,
                    accepted: HashSet::new(),
                    live: Weak::new(),
                    pins: Arc::new(AtomicUsize::new(0)),
                },
            );
        }
        let result = (|| {
            let mut journal = FileActionJournal::create_at(
                &self.wal_path(scope.session_id()),
                &self.root,
                self.config.journal_limits,
            )?;
            if notifications_enabled {
                journal =
                    journal.with_notification_source(crate::notifications::source_scope(scope)?)?;
            }
            let (device, inode) = journal.identity()?;
            let manifest = Manifest {
                schema_version: 1,
                scope: scope.clone(),
                device,
                inode,
                sealed_at: None,
                last_ack_at: None,
                last_release_at: None,
                delete_intent: false,
                delete_charge: None,
                acks: Vec::new(),
                notifications_enabled,
                notification_ack: None,
                last_notification_ack_at: None,
            };
            self.write_manifest(&manifest)?;
            let pins = Arc::clone(
                &self
                    .state()?
                    .records
                    .get(scope.session_id())
                    .ok_or_else(|| err("journal pin inventory missing"))?
                    .pins,
            );
            pins.fetch_add(1, Ordering::AcqRel);
            let journal = Arc::new(ManagedActionJournal {
                _pin: Some(WalPin(pins)),
                journal: journal.with_budget(Arc::new(PoolBudget {
                    pool: Arc::clone(self),
                    scope: scope.clone(),
                })),
            });
            let mut state = self.state()?;
            let record = state
                .records
                .get_mut(scope.session_id())
                .ok_or_else(|| err("created journal inventory is missing"))?;
            record.manifest = Some(manifest);
            record.live = Arc::downgrade(&journal);
            Ok(journal)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn wal_path(&self, session: &SessionId) -> PathBuf {
        self.config.directory.join(format!("{session}.wal"))
    }
    fn manifest_name(session: &SessionId) -> String {
        format!("{session}.meta")
    }
    fn pending_name(session: &SessionId) -> String {
        format!("{session}.pending")
    }
    fn exact_record(
        &self,
        scope: &JournalSessionScope,
    ) -> Result<(Manifest, Option<Arc<ManagedActionJournal>>), JournalError> {
        scope.validate()?;
        let state = self.state()?;
        if state.poisoned {
            return Err(err("journal pool admission is closed"));
        }
        let record = state
            .records
            .get(scope.session_id())
            .ok_or_else(|| err("journal session not found"))?;
        let manifest = record
            .manifest
            .as_ref()
            .ok_or_else(|| err("legacy journal has no custody authority"))?;
        if &manifest.scope != scope || scope.original_worker_id() != &self.worker_id {
            return Err(err("journal custody scope mismatch"));
        }
        Ok((manifest.clone(), record.live.upgrade()))
    }
    fn with_entries<T>(
        &self,
        scope: &JournalSessionScope,
        consume: impl FnOnce(&[JournalEntry]) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let (manifest, live) = self.exact_record(scope)?;
        if manifest.delete_intent {
            return Err(err("journal deletion is pending"));
        }
        if let Some(live) = live {
            return live.journal.with_replay(consume);
        }
        let journal = FileActionJournal::open_at(
            &self.wal_path(scope.session_id()),
            &self.root,
            self.config.journal_limits,
        )?;
        if journal.identity()? != (manifest.device, manifest.inode) {
            return Err(err("journal file identity mismatch"));
        }
        journal.with_replay(consume)
    }
    pub fn receipt(
        &self,
        scope: &JournalSessionScope,
        action: &ActionId,
    ) -> Result<Option<TerminalCustodyReceipt>, JournalError> {
        let _operation = self.operation()?;
        self.with_entries(scope, |entries| {
            let receipts = receipts_from_entries(scope, entries)?;
            Ok(receipts
                .into_iter()
                .find(|receipt| receipt.action_id() == action))
        })
    }

    pub fn pending_notifications_all(
        &self,
        cursor: Option<&SessionId>,
        max_sessions: usize,
        deadline: Instant,
    ) -> Result<ActionNotificationPage, JournalError> {
        self.pending_notifications_internal(None, cursor, max_sessions, deadline)
    }

    pub fn pending_notifications(
        &self,
        tenant: &TenantId,
        cursor: Option<&SessionId>,
        max_sessions: usize,
        deadline: Instant,
    ) -> Result<ActionNotificationPage, JournalError> {
        self.pending_notifications_internal(Some(tenant), cursor, max_sessions, deadline)
    }

    fn pending_notifications_internal(
        &self,
        tenant: Option<&TenantId>,
        cursor: Option<&SessionId>,
        max_sessions: usize,
        deadline: Instant,
    ) -> Result<ActionNotificationPage, JournalError> {
        if !(1..=32).contains(&max_sessions) || Instant::now() >= deadline {
            return Err(err("notification scan bounds are invalid"));
        }
        let _operation = self.operation()?;
        let candidates = {
            let state = self.state()?;
            if state.poisoned {
                return Err(err("journal pool admission is closed"));
            }
            state
                .records
                .iter()
                .filter(|(id, _)| cursor.is_none_or(|c| *id > c))
                .take(max_sessions)
                .map(|(id, record)| (id.clone(), record.manifest.clone()))
                .collect::<Vec<_>>()
        };
        let mut page = ActionNotificationPage {
            commits: Vec::new(),
            cursor: cursor.cloned(),
            examined: 0,
            is_complete: false,
        };
        let mut descriptors = 0;
        for (session, manifest) in candidates {
            if Instant::now() >= deadline {
                break;
            }
            page.cursor = Some(session);
            page.examined += 1;
            let Some(manifest) = manifest else {
                continue;
            };
            if !manifest.notifications_enabled
                || manifest.delete_intent
                || tenant.is_some_and(|t| manifest.scope.tenant_id() != t)
            {
                continue;
            }
            self.with_entries(&manifest.scope, |entries| {
                validate_notification_manifest(&manifest, entries)?;
                let after = manifest
                    .notification_ack
                    .as_ref()
                    .map_or(0, NotificationAck::source_sequence);
                if let Some(commit) = entries
                    .iter()
                    .filter_map(JournalEntry::notifications)
                    .find(|c| c.source_sequence() > after)
                {
                    if descriptors + commit.descriptors().len() > MAX_NOTIFICATION_DESCRIPTORS {
                        return Ok(());
                    }
                    descriptors += commit.descriptors().len();
                    page.commits.push(commit.clone());
                }
                Ok(())
            })?;
            if descriptors == MAX_NOTIFICATION_DESCRIPTORS {
                break;
            }
        }
        page.is_complete = self
            .state()?
            .records
            .keys()
            .all(|key| page.cursor.as_ref().is_some_and(|c| key <= c));
        Ok(page)
    }

    pub fn ack_notification(
        &self,
        ack: &NotificationAck,
        trusted_now_ms: u64,
    ) -> Result<(), JournalError> {
        ack.validate()
            .map_err(|_| err("notification acknowledgement is invalid"))?;
        if ack.scope().family() != NotificationSourceFamily::ActionJournal
            || ack.scope().original_worker_id() != &self.worker_id
        {
            return Err(err("notification acknowledgement source mismatch"));
        }
        let session = SessionId::from_uuid(ack.scope().source_id())
            .map_err(|_| err("notification acknowledgement journal identity is invalid"))?;
        let _operation = self.operation()?;
        let manifest = self
            .state()?
            .records
            .get(&session)
            .and_then(|r| r.manifest.clone())
            .ok_or_else(|| err("notification source journal is missing"))?;
        if !manifest.notifications_enabled
            || crate::notifications::source_scope(&manifest.scope)? != *ack.scope()
        {
            return Err(err("notification acknowledgement scope mismatch"));
        }
        self.with_entries(&manifest.scope, |entries| {
            validate_notification_manifest(&manifest, entries)?;
            let canonical = entries
                .iter()
                .filter_map(JournalEntry::notifications)
                .find(|c| c.source_sequence() == ack.source_sequence())
                .ok_or_else(|| err("notification acknowledgement original commit is missing"))?;
            if canonical.ack() != *ack {
                return Err(err("notification acknowledgement digest mismatch"));
            }
            let current = manifest
                .notification_ack
                .as_ref()
                .map_or(0, NotificationAck::source_sequence);
            if ack.source_sequence() > current.saturating_add(1) {
                return Err(err("notification acknowledgement skips a pending commit"));
            }
            let mut updated = manifest.clone();
            if ack.source_sequence() > current {
                updated.notification_ack = Some(ack.clone());
            }
            updated.last_notification_ack_at = Some(
                updated
                    .last_notification_ack_at
                    .map_or(trusted_now_ms, |last| last.max(trusted_now_ms)),
            );
            self.commit_manifest(updated)
        })
    }
    pub fn ack(&self, receipt: &TerminalCustodyReceipt) -> Result<(), JournalError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| err("custody acknowledgement clock unavailable"))?;
        let now_ms = u64::try_from(now.as_millis())
            .map_err(|_| err("custody acknowledgement clock overflow"))?;
        self.ack_at(receipt, now_ms)
    }
    /// Refresh the retry horizon only after validating the exact current durable receipt.
    /// Callers provide the worker's trusted absolute clock, never an RPC-supplied timestamp.
    pub fn ack_at(
        &self,
        receipt: &TerminalCustodyReceipt,
        trusted_now_ms: u64,
    ) -> Result<(), JournalError> {
        receipt.validate()?;
        let _operation = self.operation()?;
        self.with_entries(receipt.scope(), |entries| {
            let canonical = receipts_from_entries(receipt.scope(), entries)?
                .into_iter()
                .find(|r| r.action_id() == receipt.action_id())
                .ok_or_else(|| err("custody terminal evidence is missing"))?;
            if &canonical != receipt {
                return Err(err(
                    "custody acknowledgement does not match current evidence",
                ));
            }
            let (mut manifest, _) = self.exact_record(receipt.scope())?;
            let exact_duplicate = manifest
                .acks
                .iter()
                .any(|ack| &ack.action_id == receipt.action_id() && ack.digest == receipt.digest());
            let latest_ack = manifest
                .last_ack_at
                .map_or(trusted_now_ms, |last| last.max(trusted_now_ms));
            if exact_duplicate && manifest.last_ack_at == Some(latest_ack) {
                return Ok(());
            }
            manifest.last_ack_at = Some(latest_ack);
            if exact_duplicate {
                return self.commit_manifest(manifest);
            }
            manifest
                .acks
                .retain(|ack| &ack.action_id != receipt.action_id());
            manifest.acks.push(CustodyAck {
                action_id: receipt.action_id().clone(),
                digest: receipt.digest(),
                released: false,
            });
            manifest.acks.sort_by(|a, b| a.action_id.cmp(&b.action_id));
            self.commit_manifest(manifest)
        })
    }
    /// Final release is separate from copied custody. A lost copy-ACK response cannot
    /// authorize deletion. After confirmed deletion an exact-scope absent inventory plus
    /// absent private filenames is an idempotent positive release result, not custody evidence.
    pub fn release_at(
        &self,
        receipt: &TerminalCustodyReceipt,
        trusted_now_ms: u64,
    ) -> Result<(), JournalError> {
        receipt.validate()?;
        if receipt.original_worker_id() != &self.worker_id {
            return Err(err("journal release worker mismatch"));
        }
        let _operation = self.operation()?;
        let absent = {
            let state = self.state()?;
            if state.poisoned {
                return Err(err("journal pool admission is closed"));
            }
            !state.records.contains_key(receipt.session_id())
        };
        if absent {
            for name in [
                format!("{}.wal", receipt.session_id()),
                Self::manifest_name(receipt.session_id()),
                Self::pending_name(receipt.session_id()),
            ] {
                if read_private(&self.root, &name)?.is_some() {
                    return Err(err(
                        "journal release absent inventory conflicts with filesystem",
                    ));
                }
            }
            self.root
                .sync_all()
                .map_err(|_| err("journal release absence sync failed"))?;
            return Ok(());
        }
        let (intent, _) = self.exact_record(receipt.scope())?;
        if intent.delete_intent {
            // The irreversible deletion intent was written only after current ACK+release
            // validation with no WAL pins. It remains an exact idempotent release authority.
            let file = read_private(&self.root, &Self::manifest_name(receipt.session_id()))?
                .ok_or_else(|| err("journal release intent manifest disappeared"))?;
            let canonical = decode_manifest(&file, &self.worker_id)?;
            if canonical.scope != *receipt.scope()
                || canonical.device != intent.device
                || canonical.inode != intent.inode
                || !canonical.delete_intent
                || !canonical.acks.iter().any(|ack| {
                    &ack.action_id == receipt.action_id()
                        && ack.digest == receipt.digest()
                        && ack.released
                })
            {
                return Err(err("journal release intent authority mismatch"));
            }
            if let Some(wal) = read_private(&self.root, &format!("{}.wal", receipt.session_id()))? {
                let md = wal
                    .metadata()
                    .map_err(|_| err("journal release intent identity unavailable"))?;
                if (md.dev(), md.ino()) != (intent.device, intent.inode) {
                    return Err(err("journal release intent file identity mismatch"));
                }
            }
            self.root
                .sync_all()
                .map_err(|_| err("journal release intent sync failed"))?;
            return Ok(());
        }
        self.with_entries(receipt.scope(), |entries| {
            let canonical = receipts_from_entries(receipt.scope(), entries)?
                .into_iter()
                .find(|r| r.action_id() == receipt.action_id())
                .ok_or_else(|| err("journal release terminal is missing"))?;
            if &canonical != receipt {
                return Err(err("journal release does not match current evidence"));
            }
            let (mut manifest, _) = self.exact_record(receipt.scope())?;
            let ack = manifest
                .acks
                .iter_mut()
                .find(|ack| &ack.action_id == receipt.action_id() && ack.digest == receipt.digest())
                .ok_or_else(|| err("journal release has no confirmed copy ACK"))?;
            let latest_release = manifest
                .last_release_at
                .map_or(trusted_now_ms, |last| last.max(trusted_now_ms));
            if ack.released && manifest.last_release_at == Some(latest_release) {
                return Ok(());
            }
            ack.released = true;
            manifest.last_release_at = Some(latest_release);
            self.commit_manifest(manifest)
        })
    }
    /// Caller holds its exact session cleanup authority and has positively completed cleanup,
    /// with no active action owner or download rollback. This proof does not come from Closed alone.
    pub fn seal(
        &self,
        scope: &JournalSessionScope,
        trusted_now_ms: u64,
    ) -> Result<(), JournalError> {
        let _operation = self.operation()?;
        self.with_entries(scope, |entries| {
            let accepted = accepted_ids(entries);
            let receipts = receipts_from_entries(scope, entries)?;
            if accepted.len() != receipts.len() {
                return Err(err("journal still has nonterminal actions"));
            }
            let (mut manifest, _) = self.exact_record(scope)?;
            if manifest.sealed_at.is_some() {
                return Ok(());
            }
            manifest.sealed_at = Some(trusted_now_ms);
            self.commit_manifest(manifest)
        })
    }
    /// Used only after failed provisioning has dropped every ledger pin. An empty WAL carries
    /// no accepted action evidence, so it needs no terminal custody transfer or retention delay.
    pub fn discard_unadmitted(&self, scope: &JournalSessionScope) -> Result<(), JournalError> {
        let _operation = self.operation()?;
        let (manifest, live) = self.exact_record(scope)?;
        if live.is_some()
            || self
                .state()?
                .records
                .get(scope.session_id())
                .is_none_or(|record| record.pins.load(Ordering::Acquire) != 0)
        {
            return Err(err("journal is still pinned"));
        }
        if !manifest.delete_intent {
            self.with_entries(scope, |entries| {
                if !entries.is_empty() {
                    return Err(err("journal has admitted actions"));
                }
                Ok(())
            })?;
        }
        self.delete_session(manifest)
    }
    pub fn maintain(
        &self,
        now_ms: u64,
        limit: usize,
        deadline: Instant,
    ) -> Result<usize, JournalError> {
        if limit == 0 || limit > 256 {
            return Err(err("journal maintenance limit is invalid"));
        }
        let _operation = match self.operations.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(0),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(err("journal pool operation lock poisoned"));
            }
        };
        let candidates = {
            let state = self.state()?;
            if state.poisoned {
                return Err(err("journal pool admission is closed"));
            }
            let mut keys = state
                .records
                .keys()
                .filter(|key| state.cursor.as_ref().is_none_or(|cursor| *key > cursor))
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            if keys.is_empty() {
                keys = state.records.keys().take(limit).cloned().collect();
            }
            keys
        };
        let mut removed = 0;
        for session in candidates {
            if Instant::now() >= deadline {
                break;
            }
            let candidate = {
                let state = self.state()?;
                let record = state
                    .records
                    .get(&session)
                    .ok_or_else(|| err("journal inventory changed"))?;
                if record.pins.load(Ordering::Acquire) != 0 {
                    None
                } else {
                    record.manifest.clone()
                }
            };
            if let Some(manifest) = candidate {
                let eligible = manifest.delete_intent
                    || manifest.sealed_at.is_some_and(|sealed| {
                        // Timestamp-less historical ACK metadata cannot grant TTL deletion.
                        if !manifest.acks.is_empty() && manifest.last_ack_at.is_none() {
                            return false;
                        }
                        let horizon = sealed
                            .max(manifest.last_ack_at.unwrap_or(sealed))
                            .max(manifest.last_release_at.unwrap_or(sealed))
                            .max(manifest.last_notification_ack_at.unwrap_or(sealed));
                        now_ms
                            .checked_sub(horizon)
                            .is_some_and(|age| age >= self.config.limits.retention_millis)
                    });
                if eligible {
                    let confirmed = if manifest.delete_intent {
                        true
                    } else {
                        self.with_entries(&manifest.scope, |entries| {
                            validate_notification_manifest(&manifest, entries)?;
                            let receipts = receipts_from_entries(&manifest.scope, entries)?;
                            Ok(accepted_ids(entries).len() == receipts.len()
                                && entries
                                    .iter()
                                    .filter_map(JournalEntry::notifications)
                                    .next_back()
                                    .is_none_or(|c| {
                                        manifest
                                            .notification_ack
                                            .as_ref()
                                            .is_some_and(|ack| c.ack() == *ack)
                                    })
                                && receipts.iter().all(|r| {
                                    manifest.acks.iter().any(|ack| {
                                        &ack.action_id == r.action_id()
                                            && ack.digest == r.digest()
                                            && ack.released
                                    })
                                }))
                        })?
                    };
                    if confirmed {
                        self.delete_session(manifest)?;
                        removed += 1;
                    }
                }
            }
            self.state()?.cursor = Some(session);
        }
        Ok(removed)
    }
    fn commit_manifest(&self, manifest: Manifest) -> Result<(), JournalError> {
        if let Err(error) = self.write_manifest(&manifest) {
            self.poison();
            return Err(error);
        }
        let mut state = self.state()?;
        let record = state
            .records
            .get_mut(manifest.scope.session_id())
            .ok_or_else(|| err("journal manifest inventory missing"))?;
        record.manifest = Some(manifest);
        Ok(())
    }
    fn write_manifest(&self, manifest: &Manifest) -> Result<(), JournalError> {
        validate_manifest(manifest, &self.worker_id)?;
        let bytes = manifest_bytes(manifest)?;
        let pending = Self::pending_name(manifest.scope.session_id());
        let mut file = create_private(&self.root, &pending)?;
        file.write_all(&bytes)
            .map_err(|_| err("journal manifest write failed"))?;
        file.sync_all()
            .map_err(|_| err("journal manifest sync failed"))?;
        #[cfg(test)]
        self.failpoint(3)?;
        renameat(
            &self.root,
            pending.as_str(),
            &self.root,
            Self::manifest_name(manifest.scope.session_id()).as_str(),
        )
        .map_err(|_| err("journal manifest replacement failed"))?;
        self.root
            .sync_all()
            .map_err(|_| err("journal manifest directory sync failed"))?;
        #[cfg(test)]
        self.failpoint(1)?;
        Ok(())
    }
    fn delete_session(&self, mut manifest: Manifest) -> Result<(), JournalError> {
        if !manifest.delete_intent {
            manifest.delete_intent = true;
            manifest.delete_charge = Some(
                self.state()?
                    .records
                    .get(manifest.scope.session_id())
                    .ok_or_else(|| err("journal deletion charge missing"))?
                    .wal_charge,
            );
            self.commit_manifest(manifest.clone())?;
        }
        let name = format!("{}.wal", manifest.scope.session_id());
        let result = (|| {
            if let Some(file) = read_private(&self.root, &name)? {
                let md = file
                    .metadata()
                    .map_err(|_| err("journal deletion metadata unavailable"))?;
                if (md.dev(), md.ino()) != (manifest.device, manifest.inode) {
                    return Err(err("journal deletion identity mismatch"));
                }
                unlinkat(&self.root, name.as_str(), UnlinkatFlags::NoRemoveDir)
                    .map_err(|_| err("journal deletion failed"))?;
                #[cfg(test)]
                self.failpoint(2)?;
                self.root
                    .sync_all()
                    .map_err(|_| err("journal deletion directory sync failed"))?;
                drop(file); // Physical FD closure precedes quota release, even after unlink.
            } else {
                self.root
                    .sync_all()
                    .map_err(|_| err("journal absence sync failed"))?;
            }
            let meta = Self::manifest_name(manifest.scope.session_id());
            let file = read_private(&self.root, &meta)?
                .ok_or_else(|| err("journal deletion manifest disappeared"))?;
            let current = decode_manifest(&file, &self.worker_id)?;
            if current.scope != manifest.scope
                || current.device != manifest.device
                || current.inode != manifest.inode
                || !current.delete_intent
            {
                return Err(err("journal deletion manifest identity mismatch"));
            }
            unlinkat(&self.root, meta.as_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(|_| err("journal manifest deletion failed"))?;
            self.root
                .sync_all()
                .map_err(|_| err("journal final deletion sync failed"))?;
            drop(file);
            self.state()?.records.remove(manifest.scope.session_id());
            Ok(())
        })();
        // Any ambiguous final removal closes admission until bounded startup reconciles disk.
        if result.is_err() {
            self.poison();
        }
        result
    }
    #[cfg(test)]
    fn failpoint(&self, phase: usize) -> Result<(), JournalError> {
        if self
            .fault
            .compare_exchange(phase, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Err(err("injected durable pool operation failure"))
        } else {
            Ok(())
        }
    }
    fn inventory(&self) -> Result<(), JournalError> {
        let names = list_names(&self.root, self.config.limits.worker_inodes)?;
        let mut sessions = HashSet::new();
        for name in &names {
            let (stem, suffix) = name
                .rsplit_once('.')
                .ok_or_else(|| err("journal pool contains an unknown entry"))?;
            if !matches!(suffix, "wal" | "meta" | "pending") {
                return Err(err("journal pool contains an unknown entry"));
            }
            let session: SessionId = stem
                .parse()
                .map_err(|_| err("journal pool filename is invalid"))?;
            if stem != session.to_string() {
                return Err(err("journal pool filename is noncanonical"));
            }
            sessions.insert(session);
        }
        for session in sessions {
            // A fully encoded interrupted atomic replacement can safely be completed. A partial
            // replacement fails closed without rewriting or silently accepting a stale ACK.
            if let Some(pending) = read_private(&self.root, &Self::pending_name(&session))? {
                let manifest = decode_manifest(&pending, &self.worker_id)?;
                if manifest.scope.session_id() != &session {
                    return Err(err("pending manifest scope mismatch"));
                }
                if let Some(existing) = read_private(&self.root, &Self::manifest_name(&session))? {
                    let old = decode_manifest(&existing, &self.worker_id)?;
                    if old.scope != manifest.scope
                        || old.device != manifest.device
                        || old.inode != manifest.inode
                    {
                        return Err(err("pending manifest conflicts with existing identity"));
                    }
                }
                pending
                    .sync_all()
                    .map_err(|_| err("pending manifest sync failed"))?;
                renameat(
                    &self.root,
                    Self::pending_name(&session).as_str(),
                    &self.root,
                    Self::manifest_name(&session).as_str(),
                )
                .map_err(|_| err("pending manifest recovery failed"))?;
                self.root
                    .sync_all()
                    .map_err(|_| err("pending manifest recovery sync failed"))?;
            }
            let manifest = read_private(&self.root, &Self::manifest_name(&session))?
                .map(|file| decode_manifest(&file, &self.worker_id))
                .transpose()?;
            if let Some(manifest) = &manifest
                && manifest.scope.session_id() != &session
            {
                return Err(err("journal manifest filename mismatch"));
            }
            let wal = read_private(&self.root, &format!("{session}.wal"))?;
            let (tenant, charge, accepted) = if let Some(wal) = wal {
                let md = wal
                    .metadata()
                    .map_err(|_| err("journal startup identity unavailable"))?;
                if let Some(manifest) = &manifest
                    && (md.dev(), md.ino()) != (manifest.device, manifest.inode)
                {
                    return Err(err("journal startup identity mismatch"));
                }
                drop(wal);
                let journal = FileActionJournal::open_at(
                    &self.wal_path(&session),
                    &self.root,
                    self.config.journal_limits,
                )?;
                let entries = journal.replay()?;
                let tenant = entries
                    .first()
                    .map(|entry| entry.tenant_id().clone())
                    .or_else(|| manifest.as_ref().map(|m| m.scope.tenant_id().clone()));
                if let Some(manifest) = &manifest {
                    validate_entry_scope(&manifest.scope, &entries)?;
                    validate_notification_manifest(manifest, &entries)?;
                    if accepted_ids(&entries).len() > MAX_ACTIONS {
                        return Err(err("journal startup accepted-action bound exceeded"));
                    }
                    let terminal_count = receipts_from_entries(&manifest.scope, &entries)?.len();
                    if manifest.sealed_at.is_some()
                        && accepted_ids(&entries).len() != terminal_count
                    {
                        return Err(err("sealed journal contains nonterminal actions"));
                    }
                } else if let Some(first) = entries.first()
                    && (first.session_id() != &session
                        || entries.iter().any(|entry| {
                            entry.tenant_id() != first.tenant_id()
                                || entry.session_id() != &session
                                || entry.fence() != first.fence()
                        }))
                {
                    return Err(err("legacy journal has inconsistent scope"));
                }
                (tenant, journal.charged_bytes()?, accepted_ids(&entries))
            } else if let Some(manifest) = &manifest
                && manifest.delete_intent
            {
                (
                    Some(manifest.scope.tenant_id().clone()),
                    manifest
                        .delete_charge
                        .ok_or_else(|| err("journal deletion charge missing"))?,
                    HashSet::new(),
                )
            } else {
                return Err(err("journal manifest has no committed WAL"));
            };
            let metadata_charge = if manifest.is_some() {
                METADATA_RESERVATION
            } else {
                0
            };
            let inodes = if manifest.is_some() {
                SESSION_INODES
            } else {
                1
            };
            let mut state = self.state()?;
            self.check_growth(&state, tenant.as_ref(), charge + metadata_charge, inodes)?;
            state.records.insert(
                session,
                Record {
                    manifest,
                    tenant,
                    wal_charge: charge,
                    metadata_charge,
                    inodes,
                    accepted,
                    live: Weak::new(),
                    pins: Arc::new(AtomicUsize::new(0)),
                },
            );
        }
        let state = self.state()?;
        let tenants = state
            .records
            .values()
            .filter_map(|record| record.tenant.as_ref())
            .collect::<HashSet<_>>();
        for tenant in tenants {
            self.check_growth(&state, Some(tenant), 0, 0)?;
        }
        Ok(())
    }
}

// Recover against an immutable in-memory prefix. Synthetic recovery writes are discarded;
// custody generation can never append a fabricated terminal record to disk.
#[derive(Debug)]
struct ReadOnlyReplay(Vec<JournalEntry>);
impl DurableActionJournal for ReadOnlyReplay {
    fn append(&self, _: &JournalEntry) -> Result<(), JournalError> {
        Ok(())
    }
}
impl ReplayableActionJournal for ReadOnlyReplay {
    fn replay(&self) -> Result<Vec<JournalEntry>, JournalError> {
        Ok(self.0.clone())
    }
}
fn receipts_from_entries(
    scope: &JournalSessionScope,
    entries: &[JournalEntry],
) -> Result<Vec<TerminalCustodyReceipt>, JournalError> {
    validate_entry_scope(scope, entries)?;
    // Recovery validates every transition, including nonterminal actions. Any synthetic
    // WorkerLost annotation is confined to this disposable in-memory ledger; only explicit
    // terminal IDs from the original durable prefix can produce a receipt.
    let terminal_ids = entries
        .iter()
        .filter_map(|entry| {
            matches!(entry.kind(), JournalEntryKind::Terminal { .. })
                .then_some(entry.action_id().clone())
        })
        .collect::<HashSet<_>>();
    let ledger = ActionLedger::recover(
        scope.ledger_session(),
        Arc::new(ReadOnlyReplay(entries.to_vec())),
    )
    .map_err(|_| err("terminal journal replay is invalid"))?;
    let mut receipts = Vec::new();
    for action in terminal_ids {
        let snapshot = ledger
            .snapshot(scope.fence(), &action)
            .map_err(|_| err("terminal replay snapshot unavailable"))?;
        let terminal = snapshot
            .terminal_detail()
            .ok_or_else(|| err("terminal replay has no outcome"))?;
        let source = entries
            .iter()
            .find(|entry| {
                entry.action_id() == &action
                    && matches!(entry.kind(), JournalEntryKind::Terminal { .. })
            })
            .and_then(JournalEntry::notifications)
            .map(|commit| commit.scope().clone());
        let mut receipt = TerminalCustodyReceipt::new(
            scope.clone(),
            action,
            snapshot.action_sequence(),
            snapshot.request().kind(),
            snapshot.request().canonical_request_hash(),
            snapshot
                .dispatch_permit()
                .map(|permit| permit.dispatch_id().clone()),
            terminal,
            snapshot.resolution().cloned(),
        )?;
        if let Some(source) = source {
            receipt = receipt.with_notification_source(source)?;
        }
        receipts.push(receipt);
    }
    receipts.sort_by_key(|receipt| receipt.action_sequence().get());
    Ok(receipts)
}
fn accepted_ids(entries: &[JournalEntry]) -> HashSet<ActionId> {
    entries
        .iter()
        .filter_map(|entry| {
            matches!(entry.kind(), JournalEntryKind::Accepted { .. })
                .then_some(entry.action_id().clone())
        })
        .collect()
}
fn validate_entry_scope(
    scope: &JournalSessionScope,
    entries: &[JournalEntry],
) -> Result<(), JournalError> {
    if entries.iter().any(|entry| {
        entry.tenant_id() != scope.tenant_id()
            || entry.session_id() != scope.session_id()
            || entry.fence() != scope.fence()
    }) {
        return Err(err("journal replay scope mismatch"));
    }
    Ok(())
}
fn validate_manifest(manifest: &Manifest, worker: &WorkerId) -> Result<(), JournalError> {
    manifest.scope.validate()?;
    if manifest.schema_version != 1
        || manifest.scope.original_worker_id() != worker
        || manifest.inode == 0
        || manifest.acks.len() > MAX_ACTIONS
        || (manifest.delete_intent && manifest.delete_charge.is_none_or(|charge| charge < 8))
        || (!manifest.delete_intent && manifest.delete_charge.is_some())
        || (manifest.acks.is_empty()
            && (manifest.last_ack_at.is_some() || manifest.last_release_at.is_some()))
    {
        return Err(err("journal manifest identity is invalid"));
    }
    if !manifest.notifications_enabled
        && (manifest.notification_ack.is_some() || manifest.last_notification_ack_at.is_some())
        || manifest.notification_ack.is_none() != manifest.last_notification_ack_at.is_none()
    {
        return Err(err(
            "journal notification acknowledgement capability is invalid",
        ));
    }
    if let Some(ack) = &manifest.notification_ack {
        ack.validate()
            .map_err(|_| err("journal notification acknowledgement is invalid"))?;
        if *ack.scope() != crate::notifications::source_scope(&manifest.scope)? {
            return Err(err(
                "journal notification acknowledgement source is invalid",
            ));
        }
    }
    let mut ids = HashSet::new();
    if manifest.acks.iter().any(|ack| {
        !ids.insert(&ack.action_id)
            || ack.digest == [0; 32]
            || (ack.released && manifest.last_release_at.is_none())
            || (manifest.delete_intent && !ack.released)
    }) {
        return Err(err("journal manifest acknowledgement is invalid"));
    }
    Ok(())
}

fn validate_notification_manifest(
    manifest: &Manifest,
    entries: &[JournalEntry],
) -> Result<(), JournalError> {
    let source = crate::notifications::source_scope(&manifest.scope)?;
    let mut sequence = 0;
    for commit in entries.iter().filter_map(JournalEntry::notifications) {
        if !manifest.notifications_enabled
            || commit.scope() != &source
            || commit.source_sequence() != sequence + 1
        {
            return Err(err(
                "journal notification manifest contradicts original commits",
            ));
        }
        sequence = commit.source_sequence();
    }
    if let Some(ack) = &manifest.notification_ack
        && !entries
            .iter()
            .filter_map(JournalEntry::notifications)
            .any(|commit| commit.ack() == *ack)
    {
        return Err(err(
            "journal notification acknowledgement has no original commit",
        ));
    }
    Ok(())
}
fn manifest_bytes(manifest: &Manifest) -> Result<Vec<u8>, JournalError> {
    let payload =
        serde_json::to_vec(manifest).map_err(|_| err("journal manifest encoding failed"))?;
    let checksum = Sha256::digest(&payload).into();
    let bytes = serde_json::to_vec(&ManifestEnvelope {
        record: manifest.clone(),
        checksum,
    })
    .map_err(|_| err("journal manifest encoding failed"))?;
    if bytes.len() > MANIFEST_BYTES as usize {
        return Err(err("journal manifest exceeds bound"));
    }
    Ok(bytes)
}
fn decode_manifest(mut file: &File, worker: &WorkerId) -> Result<Manifest, JournalError> {
    let size = file
        .metadata()
        .map_err(|_| err("journal manifest metadata unavailable"))?
        .len();
    if size == 0 || size > MANIFEST_BYTES {
        return Err(err("journal manifest exceeds bound"));
    }
    let mut bytes = Vec::with_capacity(size as usize + 1);
    Read::by_ref(&mut file)
        .take(MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| err("journal manifest read failed"))?;
    if bytes.len() > MANIFEST_BYTES as usize {
        return Err(err("journal manifest exceeds bound"));
    }
    let envelope: ManifestEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| err("journal manifest is invalid"))?;
    let payload = serde_json::to_vec(&envelope.record)
        .map_err(|_| err("journal manifest encoding failed"))?;
    if <[u8; 32]>::from(Sha256::digest(payload)) != envelope.checksum {
        return Err(err("journal manifest checksum mismatch"));
    }
    validate_manifest(&envelope.record, worker)?;
    Ok(envelope.record)
}
fn file_flags() -> OFlag {
    OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK
}
fn validate_file(file: &File) -> Result<(), JournalError> {
    let md = file
        .metadata()
        .map_err(|_| err("journal pool file metadata unavailable"))?;
    if !md.is_file()
        || md.nlink() != 1
        || md.uid() != Uid::effective().as_raw()
        || md.mode() & 0o777 != 0o600
    {
        return Err(err("journal pool file must be private and singly linked"));
    }
    Ok(())
}
fn read_private(root: &File, name: &str) -> Result<Option<File>, JournalError> {
    match openat(root, name, file_flags(), Mode::empty()) {
        Ok(fd) => {
            let file = File::from(fd);
            validate_file(&file)?;
            Ok(Some(file))
        }
        Err(Errno::ENOENT) => Ok(None),
        Err(_) => Err(err("journal pool file cannot be opened safely")),
    }
}
fn create_private(root: &File, name: &str) -> Result<File, JournalError> {
    let fd = openat(
        root,
        name,
        file_flags() | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| err("journal pool private file creation failed"))?;
    let file = File::from(fd);
    validate_file(&file)?;
    Ok(file)
}
fn open_root(path: &Path) -> Result<File, JournalError> {
    let flags = OFlag::O_RDONLY
        | OFlag::O_DIRECTORY
        | OFlag::O_CLOEXEC
        | OFlag::O_NOFOLLOW
        | OFlag::O_NONBLOCK;
    let mut fd =
        open("/", flags, Mode::empty()).map_err(|_| err("journal pool root unavailable"))?;
    let components = path
        .components()
        .filter(|component| !matches!(component, Component::RootDir))
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(err("journal pool root path is invalid"));
        };
        fd = openat(&fd, Path::new(name), flags, Mode::empty())
            .map_err(|_| err("journal pool root component unavailable"))?;
        let file = File::from(fd);
        let md = file
            .metadata()
            .map_err(|_| err("journal pool root metadata unavailable"))?;
        let last = index + 1 == components.len();
        if !md.is_dir()
            || md.nlink() == 0
            || (md.uid() != 0 && md.uid() != Uid::effective().as_raw())
            || (last && (md.uid() != Uid::effective().as_raw() || md.mode() & 0o777 != 0o700))
            || (!last && md.mode() & 0o022 != 0 && md.mode() & 0o1000 == 0)
        {
            return Err(err("journal pool root permissions are invalid"));
        }
        fd = file.into();
    }
    if components.is_empty() {
        return Err(err("journal pool root must be private"));
    }
    Ok(File::from(fd))
}
fn list_names(root: &File, limit: usize) -> Result<Vec<String>, JournalError> {
    let fd = openat(
        root,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| err("journal pool inventory unavailable"))?;
    let mut dir = Dir::from_fd(fd).map_err(|_| err("journal pool inventory unavailable"))?;
    let mut names = Vec::new();
    for entry in dir.iter() {
        let entry = entry.map_err(|_| err("journal pool inventory failed"))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| err("journal pool filename is invalid"))?;
        if name == "." || name == ".." {
            continue;
        }
        if names.len() >= limit {
            return Err(err("journal pool inventory bound exceeded"));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}
fn err(message: &str) -> JournalError {
    JournalError::new(message)
}

#[cfg(test)]
#[path = "journal_pool_tests.rs"]
mod tests;
