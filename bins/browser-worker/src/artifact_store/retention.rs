//! Bounded durable cleanup authority. Absence never proves that an object was deleted.
use super::*;
use browserd_artifacts::{ArtifactObjectGeneration, DeleteReceiptPruneOutcome};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};

const NAME: &str = "retention.journal";
const TEMP: &str = "retention.tmp";
const HEADER: &[u8] = b"browserd-artifact-retention-v1\n";
const MAX_BYTES: usize = 16 * 1024 * 1024;
pub(super) type Key = (TenantId, SessionId, ArtifactId);
fn index(key: &ArtifactKey) -> Key {
    (
        key.tenant_id().clone(),
        key.session_id().clone(),
        key.artifact_id().clone(),
    )
}

#[derive(Clone, Debug)]
pub struct ArtifactRetentionConfig {
    pub orphan_grace: Duration,
    pub cleaned_retry: Duration,
    pub compact_at_bytes: u64,
}
impl Default for ArtifactRetentionConfig {
    fn default() -> Self {
        Self {
            orphan_grace: Duration::from_secs(3600),
            cleaned_retry: Duration::from_secs(86400),
            compact_at_bytes: 4 * 1024 * 1024,
        }
    }
}
impl ArtifactRetentionConfig {
    fn validate(&self) -> Result<(), DependencyError> {
        if self.orphan_grace.is_zero()
            || self.orphan_grace > Duration::from_secs(86400)
            || self.cleaned_retry < Duration::from_secs(86400)
            || self.cleaned_retry > Duration::from_secs(86400)
            || self.compact_at_bytes == 0
            || self.compact_at_bytes > 8 * 1024 * 1024
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArtifactMaintenanceReport {
    pub scanned: usize,
    pub cleaned: usize,
    pub retired: usize,
    pub deferred: usize,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub(super) enum Phase {
    Observed,
    Intent,
    Cleaned { at: u64 },
    Retired,
    Vacant,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    tenant: TenantId,
    session: SessionId,
    artifact: ArtifactId,
    generation: [u8; 32],
    size: u64,
    checksum: [u8; 32],
    first_seen: u64,
    pub(super) due: u64,
    pub(super) phase: Phase,
    #[serde(default, skip_serializing_if = "not_quarantine")]
    pub(super) quarantine: bool,
}
fn not_quarantine(value: &bool) -> bool {
    !*value
}
impl Entry {
    pub(super) fn key(&self) -> ArtifactKey {
        ArtifactKey::new(
            self.tenant.clone(),
            self.session.clone(),
            self.artifact.clone(),
        )
    }
    pub(super) fn generation(&self) -> ArtifactObjectGeneration {
        ArtifactObjectGeneration::new(self.generation)
    }
    pub(super) fn matches(&self, receipt: &ArtifactWriteReceipt) -> bool {
        self.key() == *receipt.key()
            && self.generation() == receipt.object_generation()
            && self.size == receipt.size_bytes()
            && self.checksum == *receipt.checksum().as_bytes()
    }
    fn from_receipt(receipt: &ArtifactWriteReceipt, now: u64, due: u64) -> Self {
        Self {
            tenant: receipt.key().tenant_id().clone(),
            session: receipt.key().session_id().clone(),
            artifact: receipt.key().artifact_id().clone(),
            generation: *receipt.object_generation().as_bytes(),
            size: receipt.size_bytes(),
            checksum: *receipt.checksum().as_bytes(),
            first_seen: now,
            due,
            phase: Phase::Observed,
            quarantine: false,
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    retired_before: u64,
    entries: Vec<Entry>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    snapshot: Snapshot,
    digest: [u8; 32],
}
pub(super) struct Retention {
    root: Arc<File>,
    file: File,
    bytes: u64,
    healthy: bool,
    maximum: usize,
    entries: BTreeMap<Key, Entry>,
    due: BTreeSet<(u64, Key)>,
    cursor: Option<(u64, Key)>,
    retired_before: u64,
    pub config: ArtifactRetentionConfig,
}
fn millis(duration: Duration) -> Result<u64, DependencyError> {
    u64::try_from(duration.as_millis()).map_err(|_| DependencyError::Rejected)
}
pub(super) fn now(shared: &SharedStore) -> Result<u64, DependencyError> {
    shared
        .clock
        .now()
        .map(|value| value.get())
        .map_err(|_| DependencyError::Unavailable)
}

/// Fixed private temporary files are recoverable only under the adapter's root lock.
pub(super) fn replace_file(
    root: &File,
    name: &str,
    temp: &str,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<File, DependencyError> {
    if bytes.len() as u64 > max_bytes {
        return Err(DependencyError::Rejected);
    }
    let flags =
        OFlag::O_RDWR | OFlag::O_APPEND | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    let fd = openat(
        root.as_fd(),
        temp,
        flags | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|_| DependencyError::OutcomeUncertain)?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| DependencyError::OutcomeUncertain)?;
    renameat(root.as_fd(), temp, root.as_fd(), name)
        .map_err(|_| DependencyError::OutcomeUncertain)?;
    root.sync_all()
        .map_err(|_| DependencyError::OutcomeUncertain)?;
    Ok(file)
}
pub(super) fn clear_temp(root: &File, name: &str) -> Result<(), DependencyError> {
    let file = match openat(
        root.as_fd(),
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(()),
        Err(_) => return Err(DependencyError::Rejected),
    };
    check_private(&file)?;
    unlinkat(root.as_fd(), name, UnlinkatFlags::NoRemoveDir)
        .map_err(|_| DependencyError::Unavailable)?;
    root.sync_all()
        .map_err(|_| DependencyError::OutcomeUncertain)
}
fn check_private(file: &File) -> Result<(), DependencyError> {
    let m = file.metadata().map_err(|_| DependencyError::Unavailable)?;
    if !m.is_file()
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.uid() != nix::unistd::Uid::effective().as_raw()
        || m.len() > MAX_BYTES as u64
    {
        return Err(DependencyError::Rejected);
    }
    Ok(())
}
impl Retention {
    pub fn open(
        root: Arc<File>,
        maximum: usize,
        config: ArtifactRetentionConfig,
    ) -> Result<Self, DependencyError> {
        config.validate()?;
        let fd = match openat(
            root.as_fd(),
            NAME,
            OFlag::O_RDWR
                | OFlag::O_APPEND
                | OFlag::O_CLOEXEC
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(nix::errno::Errno::ENOENT) => {
                clear_temp(&root, TEMP)?;
                let snapshot = Snapshot {
                    retired_before: 0,
                    entries: vec![],
                };
                replace_file(&root, NAME, TEMP, &encode(snapshot)?, MAX_BYTES as u64)?
            }
            Err(_) => return Err(DependencyError::Rejected),
        };
        check_private(&fd)?;
        let mut file = fd;
        let bytes = file
            .metadata()
            .map_err(|_| DependencyError::Unavailable)?
            .len();
        file.seek(SeekFrom::Start(0))
            .map_err(|_| DependencyError::Unavailable)?;
        let mut raw = Vec::with_capacity(bytes as usize);
        Read::by_ref(&mut file)
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|_| DependencyError::Unavailable)?;
        let payload = raw.strip_prefix(HEADER).ok_or(DependencyError::Rejected)?;
        let envelope: Envelope =
            serde_json::from_slice(payload).map_err(|_| DependencyError::Rejected)?;
        let digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&envelope.snapshot).map_err(|_| DependencyError::Rejected)?,
        )
        .into();
        if envelope.digest != digest {
            return Err(DependencyError::Rejected);
        }
        let mut entries = BTreeMap::new();
        let mut due = BTreeSet::new();
        for entry in envelope.snapshot.entries {
            if entry.generation == [0; 32]
                || entry.due < entry.first_seen
                || entries.insert(index(&entry.key()), entry.clone()).is_some()
            {
                return Err(DependencyError::Rejected);
            }
            due.insert((entry.due, index(&entry.key())));
        }
        clear_temp(&root, TEMP)?;
        Ok(Self {
            root,
            file,
            bytes,
            healthy: true,
            maximum: maximum
                .checked_add(entries.len())
                .ok_or(DependencyError::Rejected)?,
            entries,
            due,
            cursor: None,
            retired_before: envelope.snapshot.retired_before,
            config,
        })
    }
    pub fn can_admit(&self, key: &ArtifactKey) -> Result<(), DependencyError> {
        self.healthy()?;
        if let Some(entry) = self.entries.get(&index(key)) {
            if !matches!(entry.phase, Phase::Cleaned { .. }) {
                return Err(DependencyError::Rejected);
            }
        } else if self.entries.len() >= self.maximum {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
    pub fn contains(&self, key: &ArtifactKey) -> bool {
        self.entries.contains_key(&index(key))
    }
    pub fn healthy(&self) -> Result<(), DependencyError> {
        if !self.healthy {
            return Err(DependencyError::OutcomeUncertain);
        }
        check_private(&self.file)?;
        let m = self
            .file
            .metadata()
            .map_err(|_| DependencyError::Unavailable)?;
        let link = nix::sys::stat::fstatat(self.root.as_fd(), NAME, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| DependencyError::Rejected)?;
        if m.len() != self.bytes || m.ino() != link.st_ino || m.dev() != link.st_dev {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
    fn persist(&mut self) -> Result<(), DependencyError> {
        self.healthy()?;
        let bytes = encode(Snapshot {
            retired_before: self.retired_before,
            entries: self.entries.values().cloned().collect(),
        })?;
        match replace_file(&self.root, NAME, TEMP, &bytes, MAX_BYTES as u64) {
            Ok(file) => {
                self.file = file;
                self.bytes = bytes.len() as u64;
                Ok(())
            }
            Err(error) => {
                self.healthy = false;
                Err(error)
            }
        }
    }
    fn put(&mut self, entry: Entry) -> Result<(), DependencyError> {
        self.healthy()?;
        let key = index(&entry.key());
        if !self.entries.contains_key(&key) && self.entries.len() >= self.maximum {
            return Err(DependencyError::Rejected);
        }
        if let Some(old) = self.entries.insert(key.clone(), entry.clone()) {
            self.due.remove(&(old.due, key.clone()));
        }
        self.due.insert((entry.due, key));
        if let Err(error) = self.persist() {
            self.healthy = false;
            return Err(error);
        }
        Ok(())
    }
    pub fn observe(
        &mut self,
        receipt: &ArtifactWriteReceipt,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.healthy()?;
        if let Some(entry) = self.entries.get(&index(receipt.key())) {
            if entry.matches(receipt) && entry.phase == Phase::Observed {
                return Ok(());
            }
            if !matches!(entry.phase, Phase::Cleaned { .. })
                || entry.generation() == receipt.object_generation()
            {
                return Err(DependencyError::Rejected);
            }
        }
        let due = now
            .checked_add(millis(self.config.orphan_grace)?)
            .ok_or(DependencyError::Rejected)?;
        self.put(Entry::from_receipt(receipt, now, due))
    }
    pub fn quarantine_entries(&self) -> Vec<Entry> {
        self.entries
            .values()
            .filter(|e| e.quarantine)
            .cloned()
            .collect()
    }
    pub fn observe_quarantine(
        &mut self,
        receipt: &ArtifactWriteReceipt,
        now: u64,
        due: u64,
    ) -> Result<(), DependencyError> {
        self.healthy()?;
        if let Some(old) = self.entries.get(&index(receipt.key())) {
            if old.matches(receipt) && old.quarantine {
                let due = due.max(old.first_seen);
                if old.phase != Phase::Observed || old.due == due {
                    return Ok(());
                }
                let mut updated = old.clone();
                updated.due = due;
                return self.put(updated);
            }
            if !matches!(old.phase, Phase::Cleaned { .. })
                || old.generation() == receipt.object_generation()
            {
                return Err(DependencyError::Rejected);
            }
        } else if self.entries.len() >= self.maximum {
            return Err(DependencyError::Rejected);
        }
        let mut entry = Entry::from_receipt(receipt, now, due.max(now));
        entry.quarantine = true;
        self.put(entry)
    }
    pub fn publish(
        &mut self,
        publication: &ArtifactPublication,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.validate_publish(publication, now)?;
        let mut entry = self
            .entries
            .get(&index(publication.key()))
            .cloned()
            .ok_or(DependencyError::Rejected)?;
        if entry.generation() != publication.object_generation() || entry.phase != Phase::Observed {
            return Err(DependencyError::Rejected);
        }
        if entry.due == publication.expires_at_unix_millis() {
            return Ok(());
        }
        entry.due = publication.expires_at_unix_millis();
        self.put(entry)
    }
    pub fn validate_publish(
        &self,
        publication: &ArtifactPublication,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.healthy()?;
        if now < publication.published_at_unix_millis()
            || now >= publication.expires_at_unix_millis()
            || publication.published_at_unix_millis() <= self.retired_before
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
    pub fn validate_absent_withdraw(
        &self,
        publication: &ArtifactPublication,
        charged: bool,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.healthy()?;
        if now < publication.published_at_unix_millis()
            || publication.published_at_unix_millis() <= self.retired_before
        {
            return Err(DependencyError::Rejected);
        }
        match self.entries.get(&index(publication.key())) {
            Some(entry)
                if entry.generation() == publication.object_generation()
                    && entry.size == publication.metadata().size_bytes()
                    && entry.checksum == *publication.metadata().checksum().as_bytes()
                    && !matches!(entry.phase, Phase::Retired | Phase::Vacant) =>
            {
                Ok(())
            }
            None if !charged => Ok(()),
            _ => Err(DependencyError::Rejected),
        }
    }
    pub fn vacant(
        &mut self,
        publication: &ArtifactPublication,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.vacant_record(&StoredPublication::from_available(publication)?, now)
    }
    pub fn vacant_record(
        &mut self,
        publication: &StoredPublication,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.healthy()?;
        if self.entries.contains_key(&index(publication.key())) {
            return Ok(());
        }
        let entry = Entry {
            tenant: publication.key().tenant_id().clone(),
            session: publication.key().session_id().clone(),
            artifact: publication.key().artifact_id().clone(),
            generation: *publication.object_generation().as_bytes(),
            size: publication.metadata().size_bytes(),
            checksum: *publication.metadata().checksum().as_bytes(),
            first_seen: now,
            due: now
                .checked_add(millis(self.config.cleaned_retry)?)
                .ok_or(DependencyError::Rejected)?
                .max(publication.expires_at_unix_millis()),
            phase: Phase::Vacant,
            quarantine: false,
        };
        self.put(entry)
    }
    pub fn intent(
        &mut self,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
        now: u64,
    ) -> Result<(), DependencyError> {
        let Some(mut entry) = self.entries.get(&index(key)).cloned() else {
            return Err(DependencyError::Rejected);
        };
        if entry.generation() != generation
            || now < entry.first_seen
            || matches!(entry.phase, Phase::Retired | Phase::Vacant)
        {
            return Err(DependencyError::Rejected);
        }
        if matches!(entry.phase, Phase::Intent | Phase::Cleaned { .. }) {
            return Ok(());
        }
        entry.phase = Phase::Intent;
        entry.due = now;
        self.put(entry)
    }
    pub fn cleaned(
        &mut self,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
        now: u64,
    ) -> Result<(), DependencyError> {
        let Some(mut entry) = self.entries.get(&index(key)).cloned() else {
            return Err(DependencyError::Rejected);
        };
        if entry.generation() != generation || now < entry.first_seen {
            return Err(DependencyError::Rejected);
        }
        if matches!(entry.phase, Phase::Cleaned { .. }) {
            return Ok(());
        }
        if entry.phase != Phase::Intent {
            return Err(DependencyError::Rejected);
        }
        entry.phase = Phase::Cleaned { at: now };
        entry.due = now
            .checked_add(millis(self.config.cleaned_retry)?)
            .ok_or(DependencyError::Rejected)?;
        self.put(entry)
    }
    fn candidates(&mut self, now: u64, limit: usize) -> Result<Vec<Entry>, DependencyError> {
        self.healthy()?;
        use std::ops::Bound::{Excluded, Unbounded};
        let after = self.cursor.clone().map_or(Unbounded, Excluded);
        let keys: Vec<_> = self
            .due
            .range((after, Unbounded))
            .take_while(|(due, _)| *due <= now)
            .take(limit)
            .cloned()
            .collect();
        self.cursor = keys.last().cloned();
        Ok(keys
            .iter()
            .filter_map(|(_, key)| self.entries.get(key).cloned())
            .collect())
    }
    pub(super) fn retire(
        &mut self,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
        now: u64,
    ) -> Result<(), DependencyError> {
        let mut entry = self
            .entries
            .get(&index(key))
            .cloned()
            .ok_or(DependencyError::Rejected)?;
        if entry.generation() != generation
            || entry.due > now
            || !matches!(
                entry.phase,
                Phase::Cleaned { .. } | Phase::Retired | Phase::Vacant
            )
        {
            return Err(DependencyError::Rejected);
        }
        self.retired_before = self
            .retired_before
            .max(now.saturating_sub(millis(self.config.cleaned_retry)?));
        entry.phase = Phase::Retired;
        self.put(entry)
    }
    pub(super) fn forget(
        &mut self,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
    ) -> Result<(), DependencyError> {
        let entry = self
            .entries
            .get(&index(key))
            .ok_or(DependencyError::Rejected)?;
        if entry.generation() != generation || entry.phase != Phase::Retired {
            return Err(DependencyError::Rejected);
        }
        let due = entry.due;
        self.entries.remove(&index(key));
        self.due.remove(&(due, index(key)));
        if let Err(error) = self.persist() {
            self.healthy = false;
            return Err(error);
        }
        Ok(())
    }
}
fn encode(snapshot: Snapshot) -> Result<Vec<u8>, DependencyError> {
    let digest =
        Sha256::digest(serde_json::to_vec(&snapshot).map_err(|_| DependencyError::Rejected)?)
            .into();
    let mut encoded = HEADER.to_vec();
    serde_json::to_writer(&mut encoded, &Envelope { snapshot, digest })
        .map_err(|_| DependencyError::Rejected)?;
    if encoded.len() > MAX_BYTES {
        return Err(DependencyError::Rejected);
    }
    Ok(encoded)
}

struct MaintenanceGuard(Arc<AtomicBool>);
impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl ProductionArtifactStore {
    pub fn maintain(&self, limit: usize) -> Result<ArtifactMaintenanceReport, DependencyError> {
        self.maintain_with_deadline(limit, Instant::now() + Duration::from_secs(5))
    }
    pub fn maintain_with_deadline(
        &self,
        limit: usize,
        deadline: Instant,
    ) -> Result<ArtifactMaintenanceReport, DependencyError> {
        if !(1..=64).contains(&limit) || Instant::now() >= deadline {
            return Err(DependencyError::Rejected);
        }
        self.shared
            .maintenance
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| DependencyError::Unavailable)?;
        let guard = MaintenanceGuard(self.shared.maintenance.clone());
        let shared = self.shared.clone();
        run(&self.shared.runtime, async move {
            let task = tokio::spawn(async move {
                let _guard = guard;
                let now = now(&shared)?;
                let pending = {
                    let mut queue = shared
                        .pending
                        .try_lock()
                        .map_err(|_| DependencyError::Unavailable)?;
                    let count = queue.len().min(limit);
                    queue
                        .drain(..count)
                        .map(|pending| PendingGuard {
                            pending: Some(pending),
                            owner: shared.pending.clone(),
                        })
                        .collect::<Vec<_>>()
                };
                let mut report = ArtifactMaintenanceReport::default();
                for mut guard in pending {
                    if Instant::now() >= deadline {
                        break;
                    }
                    report.scanned += 1;
                    if cleanup_write(
                        &shared,
                        guard
                            .pending
                            .as_mut()
                            .ok_or(DependencyError::OutcomeUncertain)?,
                        Some(deadline),
                    )
                    .await
                    .is_ok()
                    {
                        guard.pending.take();
                        report.cleaned += 1;
                    } else {
                        report.deferred += 1;
                    }
                }
                let entries = if report.scanned < limit {
                    shared
                        .retention
                        .try_lock()
                        .map_err(|_| DependencyError::Unavailable)?
                        .candidates(now, limit - report.scanned)?
                } else {
                    vec![]
                };
                for entry in entries {
                    if Instant::now() >= deadline {
                        break;
                    }
                    report.scanned += 1;
                    match sweep(&shared, entry, now, deadline).await {
                        Ok(true) => report.retired += 1,
                        Ok(false) => report.cleaned += 1,
                        Err(_) => report.deferred += 1,
                    }
                }
                compact(&shared, deadline).await?;
                Ok(report)
            });
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task)
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)?
        })?
    }
}
impl crate::ArtifactMaintenance for ProductionArtifactStore {
    fn sweep_expired(&self, limit: usize, deadline: Instant) -> Result<usize, DependencyError> {
        self.maintain_with_deadline(limit, deadline)
            .map(|report| report.cleaned + report.retired)
    }
}
pub(super) async fn durable<F>(
    shared: &Arc<SharedStore>,
    deadline: Option<Instant>,
    operation: F,
) -> Result<(), DependencyError>
where
    F: FnOnce(&mut Retention) -> Result<(), DependencyError> + Send + 'static,
{
    let shared = shared.clone();
    tokio::task::spawn_blocking(move || {
        if let Some(deadline) = deadline {
            within(deadline)?;
        }
        let mut retained = shared
            .retention
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?;
        operation(&mut retained)
    })
    .await
    .map_err(|_| DependencyError::OutcomeUncertain)?
}
pub(super) fn unpinned(
    shared: &SharedStore,
    key: &ArtifactKey,
    own_writer: bool,
) -> Result<(), DependencyError> {
    let ledger = shared
        .ledger
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?;
    if ledger.readers.get(key).copied().unwrap_or(0) > 0
        || (!own_writer && ledger.writers.contains(key))
    {
        return Err(DependencyError::Unavailable);
    }
    Ok(())
}
async fn sweep(
    shared: &Arc<SharedStore>,
    entry: Entry,
    now: u64,
    deadline: Instant,
) -> Result<bool, DependencyError> {
    if entry.quarantine {
        return quarantine::sweep(shared, entry, now, deadline).await;
    }
    within(deadline)?;
    let key = entry.key();
    let generation = entry.generation();
    let _ownership = exclusive(shared, &key, true)?;
    unpinned(shared, &key, false)?;
    if matches!(
        entry.phase,
        Phase::Cleaned { .. } | Phase::Retired | Phase::Vacant
    ) {
        if shared
            .ledger
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .charges
            .contains_key(&key)
        {
            return Err(DependencyError::Rejected);
        }
        let owned_key = key.clone();
        durable(shared, Some(deadline), move |r| {
            r.retire(&owned_key, generation, now)
        })
        .await?;
        within(deadline)?;
        match shared
            .filesystem
            .store
            .prune_delete_receipt(&key.namespace(), &key, generation)
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?
        {
            DeleteReceiptPruneOutcome::Pruned | DeleteReceiptPruneOutcome::AlreadyAbsent => {}
        }
        within(deadline)?;
        let pubs = shared.publications.clone();
        let retired_key = key.clone();
        let root = shared.filesystem._root_owner.clone();
        tokio::task::spawn_blocking(move || {
            within(deadline)?;
            let _root = root;
            pubs.try_lock()
                .map_err(|_| DependencyError::Unavailable)?
                .retire(&retired_key, generation)
        })
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)??;
        within(deadline)?;
        durable(shared, Some(deadline), move |r| r.forget(&key, generation)).await?;
        return Ok(true);
    }
    let publication = {
        let registry = shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?;
        registry.ensure_healthy()?;
        registry.record(&key)
    };
    if let Some((publication, withdrawn)) = publication {
        if publication.object_generation() != generation {
            return Err(DependencyError::Rejected);
        }
        if !withdrawn && now < publication.expires_at_unix_millis() {
            let key = publication.key().clone();
            let due = publication.expires_at_unix_millis();
            durable(shared, Some(deadline), move |r| {
                let mut entry = r
                    .entries
                    .get(&index(&key))
                    .cloned()
                    .ok_or(DependencyError::Rejected)?;
                if entry.generation() != generation || entry.phase != Phase::Observed {
                    return Err(DependencyError::Rejected);
                }
                entry.due = due;
                r.put(entry)
            })
            .await?;
            return Err(DependencyError::Unavailable);
        }
        within(deadline)?;
        let owned = shared.clone();
        tokio::task::spawn_blocking(move || {
            within(deadline)?;
            owned
                .publications
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?
                .withdraw_record(&publication, now)
        })
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)??;
    }
    within(deadline)?;
    let intent_key = key.clone();
    durable(shared, Some(deadline), move |r| {
        r.intent(&intent_key, generation, now)
    })
    .await?;
    within(deadline)?;
    match shared
        .filesystem
        .store
        .delete_exact(&key.namespace(), &key, generation)
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)?
    {
        ArtifactDeleteOutcome::Deleted | ArtifactDeleteOutcome::AlreadyDeleted => {}
    }
    within(deadline)?;
    let owned = shared.clone();
    let released_key = key.clone();
    tokio::task::spawn_blocking(move || {
        within(deadline)?;
        owned
            .ledger
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .release(&released_key)?;
        owned
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .deleted(&released_key, Some(generation), now)?;
        Ok::<(), DependencyError>(())
    })
    .await
    .map_err(|_| DependencyError::OutcomeUncertain)??;
    within(deadline)?;
    durable(shared, Some(deadline), move |r| {
        r.cleaned(&key, generation, now)
    })
    .await?;
    Ok(false)
}
async fn compact(shared: &Arc<SharedStore>, deadline: Instant) -> Result<(), DependencyError> {
    within(deadline)?;
    let shared = shared.clone();
    tokio::task::spawn_blocking(move || {
        within(deadline)?;
        let threshold = shared
            .retention
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .config
            .compact_at_bytes;
        let _operation = metadata_operation(&shared)?;
        within(deadline)?;
        shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .compact_if_needed(threshold, now(&shared)?)?;
        let mut ledger = shared
            .ledger
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?;
        validate_quota(&ledger, &shared.filesystem._root_owner)?;
        if ledger.journal_bytes >= threshold {
            within(deadline)?;
            let mut charges: Vec<_> = ledger.charges.iter().collect();
            charges.sort_by_key(|(key, _)| index(key));
            let mut bytes = JOURNAL_HEADER.to_vec();
            for (key, amount) in charges {
                serde_json::to_writer(
                    &mut bytes,
                    &JournalRecord::Charge {
                        tenant: key.tenant_id().clone(),
                        session: key.session_id().clone(),
                        artifact: key.artifact_id().clone(),
                        bytes: *amount,
                    },
                )
                .map_err(|_| DependencyError::Rejected)?;
                bytes.push(b'\n');
            }
            match replace_file(
                &shared.filesystem._root_owner,
                "quota.journal",
                "quota.tmp",
                &bytes,
                MAX_BYTES as u64,
            ) {
                Ok(file) => {
                    ledger.journal = file;
                    ledger.journal_bytes = bytes.len() as u64
                }
                Err(error) => {
                    ledger.healthy = false;
                    return Err(error);
                }
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| DependencyError::OutcomeUncertain)?
}

pub(super) fn recover(
    config: &ArtifactStoreConfig,
    runtime: &Handle,
    filesystem: &OwnedFilesystem,
    ledger: &mut Ledger,
    publications: &mut Publications,
    retention: &mut Retention,
    now: u64,
) -> Result<(), DependencyError> {
    let entries: Vec<_> = retention.entries.values().cloned().collect();
    for entry in entries {
        if entry.quarantine {
            continue;
        }
        let key = entry.key();
        let charged = ledger.charges.contains_key(&key);
        let committed = inspect_on_startup(config, runtime, filesystem, &key, None)?;
        if let Some(receipt) = committed {
            if charged
                && matches!(entry.phase, Phase::Cleaned { .. })
                && entry.generation() != receipt.object_generation()
            {
                retention.observe(&receipt, now)?;
                continue;
            }
            if !charged
                || !entry.matches(&receipt)
                || matches!(
                    entry.phase,
                    Phase::Cleaned { .. } | Phase::Retired | Phase::Vacant
                )
            {
                return Err(DependencyError::Rejected);
            }
            continue;
        }
        match entry.phase {
            Phase::Observed => return Err(DependencyError::Rejected),
            Phase::Intent => {
                let receipt = inspect_on_startup(
                    config,
                    runtime,
                    filesystem,
                    &key,
                    Some(entry.generation()),
                )?
                .ok_or(DependencyError::Rejected)?;
                if !entry.matches(&receipt) {
                    return Err(DependencyError::Rejected);
                }
                finish_delete_on_startup(config, runtime, filesystem, &key, entry.generation())?;
                publications.deleted(&key, Some(entry.generation()), now)?;
                ledger.release(&key)?;
                retention.cleaned(&key, entry.generation(), now)?;
            }
            Phase::Cleaned { .. } | Phase::Retired | Phase::Vacant => {
                if charged {
                    return Err(DependencyError::Rejected);
                }
            }
        }
    }
    let keys: Vec<_> = ledger.charges.keys().cloned().collect();
    for key in keys {
        if retention.entries.contains_key(&index(&key)) {
            continue;
        }
        if let Some(receipt) = inspect_on_startup(config, runtime, filesystem, &key, None)? {
            retention.observe(&receipt, now)?;
            if let Some((publication, withdrawn)) = publications.record(&key) {
                if withdrawn {
                    retention.intent(&key, receipt.object_generation(), now)?;
                } else {
                    let mut entry = retention
                        .entries
                        .get(&index(&key))
                        .cloned()
                        .ok_or(DependencyError::Rejected)?;
                    entry.due = publication.expires_at_unix_millis().max(entry.first_seen);
                    retention.put(entry)?;
                }
            }
        }
    }
    // Legacy exact deletion receipts are bounded by the already-validated tree inventory.
    let deleted = config.root.join(".deleted");
    for tenant in fs::read_dir(&deleted).map_err(|_| DependencyError::Unavailable)? {
        let tenant = tenant.map_err(|_| DependencyError::Unavailable)?;
        let tenant_id: TenantId = tenant
            .file_name()
            .to_str()
            .ok_or(DependencyError::Rejected)?
            .parse()
            .map_err(|_| DependencyError::Rejected)?;
        for session in fs::read_dir(tenant.path()).map_err(|_| DependencyError::Unavailable)? {
            let session = session.map_err(|_| DependencyError::Unavailable)?;
            let session_id: SessionId = session
                .file_name()
                .to_str()
                .ok_or(DependencyError::Rejected)?
                .parse()
                .map_err(|_| DependencyError::Rejected)?;
            for artifact in
                fs::read_dir(session.path()).map_err(|_| DependencyError::Unavailable)?
            {
                let artifact = artifact.map_err(|_| DependencyError::Unavailable)?;
                let artifact_id: ArtifactId = artifact
                    .file_name()
                    .to_str()
                    .ok_or(DependencyError::Rejected)?
                    .parse()
                    .map_err(|_| DependencyError::Rejected)?;
                let key = ArtifactKey::new(tenant_id.clone(), session_id.clone(), artifact_id);
                if retention.entries.contains_key(&index(&key)) {
                    continue;
                }
                if let Some(generation) = fs::read_dir(artifact.path())
                    .map_err(|_| DependencyError::Unavailable)?
                    .next()
                {
                    let generation = generation.map_err(|_| DependencyError::Unavailable)?;
                    let encoded = generation.file_name();
                    let encoded = encoded.to_str().ok_or(DependencyError::Rejected)?;
                    let mut bytes = [0u8; 32];
                    hex::decode_to_slice(encoded, &mut bytes)
                        .map_err(|_| DependencyError::Rejected)?;
                    let generation = ArtifactObjectGeneration::new(bytes);
                    let receipt =
                        inspect_on_startup(config, runtime, filesystem, &key, Some(generation))?
                            .ok_or(DependencyError::Rejected)?;
                    retention.observe(&receipt, now)?;
                    retention.intent(&key, generation, now)?;
                    finish_delete_on_startup(config, runtime, filesystem, &key, generation)?;
                    publications.deleted(&key, Some(generation), now)?;
                    ledger.release(&key)?;
                    retention.cleaned(&key, generation, now)?;
                    // Exact deletion also validates and compacts superseded receipts;
                    // process only one observed generation from this key directory.
                }
            }
        }
    }
    for (publication, withdrawn) in publications.records() {
        if withdrawn && !retention.contains(publication.key()) {
            if ledger.charges.contains_key(publication.key()) {
                return Err(DependencyError::Rejected);
            }
            retention.vacant_record(&publication, now)?;
        }
    }
    Ok(())
}

pub(super) fn check_deadline(deadline: Option<Instant>) -> Result<(), DependencyError> {
    match deadline {
        Some(deadline) => within(deadline),
        None => Ok(()),
    }
}
fn within(deadline: Instant) -> Result<(), DependencyError> {
    if Instant::now() >= deadline {
        Err(DependencyError::Unavailable)
    } else {
        Ok(())
    }
}

fn inspect_on_startup(
    config: &ArtifactStoreConfig,
    runtime: &Handle,
    filesystem: &OwnedFilesystem,
    key: &ArtifactKey,
    deleted: Option<ArtifactObjectGeneration>,
) -> Result<Option<ArtifactWriteReceipt>, DependencyError> {
    let owned = filesystem.clone();
    let key = key.clone();
    run(runtime, async move {
        let inspecting = tokio::spawn(async move {
            let _root = owned._root_owner;
            match deleted {
                Some(generation) => {
                    owned
                        .store
                        .inspect_delete_receipt(&key.namespace(), &key, generation)
                        .await
                }
                None => owned.store.inspect_committed(&key.namespace(), &key).await,
            }
            .map_err(|_| DependencyError::Rejected)
        });
        tokio::time::timeout(config.operation_timeout, inspecting)
            .await
            .map_err(|_| DependencyError::Unavailable)?
            .map_err(|_| DependencyError::OutcomeUncertain)?
    })?
}

fn finish_delete_on_startup(
    config: &ArtifactStoreConfig,
    runtime: &Handle,
    filesystem: &OwnedFilesystem,
    key: &ArtifactKey,
    generation: ArtifactObjectGeneration,
) -> Result<(), DependencyError> {
    let owned = filesystem.clone();
    let key = key.clone();
    run(runtime, async move {
        let task = tokio::spawn(async move {
            let _root = owned._root_owner;
            owned
                .store
                .delete_exact(&key.namespace(), &key, generation)
                .await
                .map(|_| ())
                .map_err(|_| DependencyError::OutcomeUncertain)
        });
        tokio::time::timeout(config.operation_timeout, task)
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?
            .map_err(|_| DependencyError::OutcomeUncertain)?
    })?
}
pub(super) fn validate_quota(ledger: &Ledger, root: &File) -> Result<(), DependencyError> {
    if !ledger.healthy {
        return Err(DependencyError::OutcomeUncertain);
    }
    check_private(&ledger.journal)?;
    let metadata = ledger
        .journal
        .metadata()
        .map_err(|_| DependencyError::Unavailable)?;
    let linked =
        nix::sys::stat::fstatat(root.as_fd(), "quota.journal", AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| DependencyError::Rejected)?;
    if metadata.len() != ledger.journal_bytes
        || metadata.ino() != linked.st_ino
        || metadata.dev() != linked.st_dev
    {
        return Err(DependencyError::Rejected);
    }
    Ok(())
}
