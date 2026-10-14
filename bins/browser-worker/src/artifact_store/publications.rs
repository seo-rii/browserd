//! Durable publication authority, separate from storage completion and live browser ownership.
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::os::fd::AsFd;

use browserd_artifacts::{ArtifactChecksum, ArtifactObjectGeneration};
use browserd_core::WorkerId;
use browserd_core::{NotificationAck, NotificationArtifactState, WorkerNotificationEvent};
use browserd_session::OwnershipFence;
use browserd_worker::{ArtifactPublication, ArtifactScanAttestation};
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, fstatat};

use super::*;

mod notifications;
use notifications::{Change as NotificationChange, Notifications};

pub(super) const JOURNAL_NAME: &str = "publications.journal";
const HEADER: &[u8] = b"browserd-artifact-publications-v1\n";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 32 * 1024;
/// Withdraw and delete frames reserved for every retained artifact.
const CLEANUP_FRAMES: usize = 2;
type IndexKey = (TenantId, SessionId, ArtifactId);

fn index_key(key: &ArtifactKey) -> IndexKey {
    (
        key.tenant_id().clone(),
        key.session_id().clone(),
        key.artifact_id().clone(),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    ClientUpload,
    BrowserDownload,
    Generated,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scan {
    Clean,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    tenant: TenantId,
    session: SessionId,
    artifact: ArtifactId,
    worker: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
    generation: [u8; 32],
    size: u64,
    checksum: [u8; 32],
    content_type: String,
    source: Source,
    origin: String,
    scan: Option<Scan>,
    display_filename: Option<String>,
    published_at: u64,
    expires_at: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_scan_attestation"
    )]
    scan_attestation: Option<ArtifactScanAttestation>,
}

fn present_scan_attestation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ArtifactScanAttestation>, D::Error> {
    // Only a missing field identifies old v1 data. Explicit null is malformed
    // evidence and must not gain the old-schema cleanup-only compatibility path.
    ArtifactScanAttestation::deserialize(deserializer).map(Some)
}

impl Publication {
    fn encode(value: &ArtifactPublication) -> Result<Self, DependencyError> {
        value.validate().map_err(|_| DependencyError::Rejected)?;
        let metadata = value.metadata();
        let fence = value.original_fence();
        Ok(Self {
            tenant: value.key().tenant_id().clone(),
            session: value.key().session_id().clone(),
            artifact: value.key().artifact_id().clone(),
            worker: fence.worker_id().clone(),
            worker_epoch: fence.worker_epoch(),
            placement_version: fence.placement_version(),
            session_incarnation: fence.session_incarnation(),
            generation: *value.object_generation().as_bytes(),
            size: metadata.size_bytes(),
            checksum: *metadata.checksum().as_bytes(),
            content_type: metadata.content_type().to_owned(),
            source: match metadata.source() {
                ArtifactContentSource::ClientUpload => Source::ClientUpload,
                ArtifactContentSource::BrowserDownload => Source::BrowserDownload,
                ArtifactContentSource::Generated => Source::Generated,
            },
            origin: metadata.origin().to_owned(),
            scan: value.scan_verdict().map(|_| Scan::Clean),
            display_filename: value.display_filename().map(str::to_owned),
            published_at: value.published_at_unix_millis(),
            expires_at: value.expires_at_unix_millis(),
            scan_attestation: value.scan_attestation().cloned(),
        })
    }
    fn decode(self) -> Result<StoredPublication, DependencyError> {
        let key = ArtifactKey::new(
            self.tenant.clone(),
            self.session.clone(),
            self.artifact.clone(),
        );
        let fence = OwnershipFence::new(
            self.worker.clone(),
            self.worker_epoch,
            self.placement_version,
            self.session_incarnation,
        );
        let generation = ArtifactObjectGeneration::new(self.generation);
        let metadata = ArtifactContentMetadata::new(
            self.size,
            ArtifactChecksum::new(self.checksum),
            self.content_type.clone(),
            match self.source {
                Source::ClientUpload => ArtifactContentSource::ClientUpload,
                Source::BrowserDownload => ArtifactContentSource::BrowserDownload,
                Source::Generated => ArtifactContentSource::Generated,
            },
            self.origin.clone(),
        )
        .map_err(|_| DependencyError::Rejected)?;
        let legacy_scanned = self.source != Source::Generated && self.scan_attestation.is_none();
        let available = if legacy_scanned {
            // Only the old valid schema's missing evidence is grandfathered as hidden
            // cleanup metadata. It never becomes an Available public resource.
            if self.worker_epoch == 0
                || self.placement_version == 0
                || self.session_incarnation == 0
                || self.generation.iter().all(|byte| *byte == 0)
                || self.scan != Some(Scan::Clean)
                || self.expires_at <= self.published_at
                || self.expires_at - self.published_at
                    > browserd_worker::ARTIFACT_PUBLICATION_TTL_MILLIS
                || self.display_filename.as_ref().is_some_and(|name| {
                    name.is_empty()
                        || name.len() > 255
                        || matches!(name.as_str(), "." | "..")
                        || name
                            .chars()
                            .any(|c| c == '/' || c == '\\' || c.is_control())
                })
            {
                return Err(DependencyError::Rejected);
            }
            None
        } else {
            Some(
                ArtifactPublication::new_with_scan_attestation(
                    key.clone(),
                    fence.clone(),
                    metadata.clone(),
                    generation,
                    self.scan.as_ref().map(|_| ArtifactScanVerdict::Clean),
                    self.display_filename.clone(),
                    self.published_at,
                    self.expires_at,
                    self.scan_attestation.clone(),
                )
                .map_err(|_| DependencyError::Rejected)?,
            )
        };
        Ok(StoredPublication {
            raw: self,
            key,
            metadata,
            available,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredPublication {
    raw: Publication,
    key: ArtifactKey,
    metadata: ArtifactContentMetadata,
    available: Option<ArtifactPublication>,
}
impl StoredPublication {
    pub fn from_available(publication: &ArtifactPublication) -> Result<Self, DependencyError> {
        Publication::encode(publication)?.decode()
    }
    pub fn key(&self) -> &ArtifactKey {
        &self.key
    }
    pub fn metadata(&self) -> &ArtifactContentMetadata {
        &self.metadata
    }
    pub fn object_generation(&self) -> ArtifactObjectGeneration {
        ArtifactObjectGeneration::new(self.raw.generation)
    }
    pub fn published_at_unix_millis(&self) -> u64 {
        self.raw.published_at
    }
    pub fn expires_at_unix_millis(&self) -> u64 {
        self.raw.expires_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Publish,
    Withdraw,
    Delete,
    Notification,
    Quarantine,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: u64,
    previous: [u8; 32],
    operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication: Option<Publication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notification: Option<NotificationChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notification_clock: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quarantine: Option<quarantine::Change>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    record: Record,
    digest: [u8; 32],
}
#[derive(Clone)]
struct Entry {
    publication: StoredPublication,
    withdrawn: bool,
    deleted: bool,
}

pub(super) struct StagedProvenance {
    pub fence: OwnershipFence,
    pub metadata: ArtifactContentMetadata,
    pub generation: ArtifactObjectGeneration,
    pub scan: Option<ArtifactScanVerdict>,
    pub scan_attestation: Option<ArtifactScanAttestation>,
}
impl StagedProvenance {
    fn matches(&self, publication: &ArtifactPublication) -> bool {
        self.fence == *publication.original_fence()
            && self.metadata == *publication.metadata()
            && self.generation == publication.object_generation()
            && self.scan == publication.scan_verdict()
            && self.scan_attestation.as_ref() == publication.scan_attestation()
    }
}

pub(super) struct Publications {
    file: File,
    root: Arc<File>,
    bytes: u64,
    max_bytes: u64,
    sequence: u64,
    digest: [u8; 32],
    healthy: bool,
    maximum_entries: usize,
    entries: BTreeMap<IndexKey, Entry>,
    staged: HashMap<ArtifactKey, StagedProvenance>,
    notifications: Notifications,
    quarantine: BTreeMap<IndexKey, quarantine::Record>,
    quarantine_retired_before: u64,
}

impl Publications {
    fn validate_quarantine_change(
        &self,
        change: &quarantine::Change,
    ) -> Result<(), DependencyError> {
        match change {
            quarantine::Change::Upsert { record } | quarantine::Change::Checkpoint { record } => {
                record.validate()?;
                if self.entries.contains_key(&index_key(&record.key())) {
                    return Err(DependencyError::Rejected);
                }
                if let Some(old) = self.quarantine.get(&index_key(&record.key())) {
                    if !old.same_object(record)
                        || !matches!(
                            (old.phase, record.phase),
                            (
                                quarantine::Phase::Retained,
                                quarantine::Phase::Retained | quarantine::Phase::DeleteIntent
                            ) | (
                                quarantine::Phase::DeleteIntent,
                                quarantine::Phase::DeleteIntent | quarantine::Phase::Deleted { .. }
                            ) | (
                                quarantine::Phase::Deleted { .. },
                                quarantine::Phase::Deleted { .. }
                            )
                        )
                    {
                        return Err(DependencyError::Rejected);
                    }
                } else if self.entries.len() + self.quarantine.len() >= self.maximum_entries
                    || (matches!(change, quarantine::Change::Upsert { .. })
                        && record.admitted_at <= self.quarantine_retired_before)
                    || (matches!(change, quarantine::Change::Upsert { .. })
                        && record.phase != quarantine::Phase::Retained)
                {
                    return Err(DependencyError::Rejected);
                }
            }
            quarantine::Change::Retire { record, before } => {
                if self.quarantine.get(&index_key(&record.key())) != Some(record)
                    || !matches!(record.phase, quarantine::Phase::Deleted { at } if *before >= at)
                {
                    return Err(DependencyError::Rejected);
                }
            }
            quarantine::Change::Watermark { before } => {
                if *before < self.quarantine_retired_before {
                    return Err(DependencyError::Rejected);
                }
            }
        }
        Ok(())
    }
    pub fn quarantine_records(&self) -> Vec<quarantine::Record> {
        self.quarantine.values().cloned().collect()
    }
    pub fn quarantine_record(&self, key: &ArtifactKey) -> Option<quarantine::Record> {
        self.quarantine.get(&index_key(key)).cloned()
    }
    pub fn retain_quarantine(
        &mut self,
        record: quarantine::Record,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if let Some(existing) = self.quarantine_record(&record.key()) {
            return if existing == record {
                Ok(())
            } else {
                Err(DependencyError::Rejected)
            };
        }
        let commit = self.notifications.commit(
            &record.key(),
            &record.fence(),
            now,
            vec![WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: record.artifact.clone(),
                state: NotificationArtifactState::Quarantined,
            }],
        )?;
        self.append_authority(
            None,
            Operation::Quarantine,
            Some(NotificationChange::Commit { commit }),
            Some(quarantine::Change::Upsert { record }),
            now,
        )
    }
    pub fn update_quarantine(
        &mut self,
        record: quarantine::Record,
        now: u64,
    ) -> Result<(), DependencyError> {
        if self.quarantine_record(&record.key()).as_ref() == Some(&record) {
            return Ok(());
        }
        self.append_authority(
            None,
            Operation::Quarantine,
            None,
            Some(quarantine::Change::Upsert { record }),
            now,
        )
    }
    pub fn quarantine_unpinned(&self, key: &ArtifactKey) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if self.notifications.rejection_pending(key) {
            return Err(DependencyError::Unavailable);
        }
        Ok(())
    }
    pub fn retire_quarantine(
        &mut self,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        let Some(record) = self.quarantine_record(key) else {
            return Ok(());
        };
        if record.generation() != generation
            || !matches!(record.phase, quarantine::Phase::Deleted { at } if now >= at.saturating_add(86_400_000))
            || !self.notifications.rejection_retirable(key, now)
        {
            return Err(DependencyError::Unavailable);
        }
        self.append_authority(
            None,
            Operation::Quarantine,
            None,
            Some(quarantine::Change::Retire {
                record,
                before: now.saturating_sub(86_400_000),
            }),
            now,
        )
    }
    pub fn open(root: Arc<File>, maximum_entries: usize) -> Result<Self, DependencyError> {
        // The fixed budget holds the actual records and unacknowledged notifications. Every
        // configured artifact also backs its reserved worst-case cleanup frames, so reservations
        // alone cannot exhaust the journal below the configured maximum.
        let max_bytes = maximum_entries
            .checked_mul(CLEANUP_FRAMES)
            .and_then(|frames| (frames as u64).checked_mul(MAX_RECORD_BYTES as u64 + 1))
            .and_then(|reserved| reserved.checked_add(MAX_BYTES))
            .ok_or(DependencyError::Rejected)?;
        let flags = OFlag::O_RDWR
            | OFlag::O_APPEND
            | OFlag::O_CLOEXEC
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK;
        let (descriptor, created) = match openat(root.as_fd(), JOURNAL_NAME, flags, Mode::empty()) {
            Ok(fd) => (fd, false),
            Err(nix::errno::Errno::ENOENT) => (
                openat(
                    root.as_fd(),
                    JOURNAL_NAME,
                    flags | OFlag::O_CREAT | OFlag::O_EXCL,
                    Mode::S_IRUSR | Mode::S_IWUSR,
                )
                .map_err(|_| DependencyError::Unavailable)?,
                true,
            ),
            Err(_) => return Err(DependencyError::Rejected),
        };
        let mut file = File::from(descriptor);
        if created {
            file.write_all(HEADER)
                .and_then(|()| file.sync_all())
                .and_then(|()| root.sync_all())
                .map_err(|_| DependencyError::OutcomeUncertain)?;
        }
        let metadata = file.metadata().map_err(|_| DependencyError::Unavailable)?;
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.len() > max_bytes
        {
            return Err(DependencyError::Rejected);
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| DependencyError::Rejected)?,
        );
        file.seek(SeekFrom::Start(0))
            .and_then(|_| {
                Read::by_ref(&mut file)
                    .take(max_bytes + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|_| DependencyError::Unavailable)?;
        if bytes.len() as u64 != metadata.len()
            || !bytes.starts_with(HEADER)
            || !bytes.ends_with(b"\n")
        {
            return Err(DependencyError::Rejected);
        }
        let mut registry = Self {
            file,
            root,
            bytes: metadata.len(),
            max_bytes,
            sequence: 0,
            digest: [0; 32],
            healthy: true,
            maximum_entries: maximum_entries
                .max(bytes.iter().filter(|byte| **byte == b'\n').count()),
            entries: BTreeMap::new(),
            staged: HashMap::new(),
            notifications: Notifications::with_cleanup_capacity(maximum_entries)?,
            quarantine: BTreeMap::new(),
            quarantine_retired_before: 0,
        };
        let body = &bytes[HEADER.len()..];
        for line in body.split_inclusive(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\n").ok_or(DependencyError::Rejected)?;
            if line.is_empty() || line.len() > MAX_RECORD_BYTES {
                return Err(DependencyError::Rejected);
            }
            let envelope: Envelope =
                serde_json::from_slice(line).map_err(|_| DependencyError::Rejected)?;
            let encoded =
                serde_json::to_vec(&envelope.record).map_err(|_| DependencyError::Rejected)?;
            if envelope.digest != <[u8; 32]>::from(Sha256::digest(encoded))
                || envelope.record.previous != registry.digest
                || envelope.record.sequence
                    != registry
                        .sequence
                        .checked_add(1)
                        .ok_or(DependencyError::Rejected)?
            {
                return Err(DependencyError::Rejected);
            }
            registry.apply_record(&envelope.record)?;
            registry.sequence = envelope.record.sequence;
            registry.digest = envelope.digest;
        }
        registry.ensure_healthy()?;
        registry.maximum_entries = maximum_entries
            .checked_add(registry.entries.len())
            .and_then(|n| n.checked_add(registry.quarantine.len()))
            .ok_or(DependencyError::Rejected)?;
        registry
            .notifications
            .validate_replay(registry.cleanup_reserves())?;
        if !registry.notifications.initialized() {
            registry.append_record(
                None,
                Operation::Notification,
                Some(NotificationChange::Initialize {
                    source_id: uuid::Uuid::new_v4(),
                }),
                0,
            )?;
        }
        Ok(registry)
    }

    pub fn ensure_healthy(&self) -> Result<(), DependencyError> {
        if !self.healthy {
            return Err(DependencyError::OutcomeUncertain);
        }
        let metadata = self
            .file
            .metadata()
            .map_err(|_| DependencyError::Unavailable)?;
        let linked = fstatat(
            self.root.as_fd(),
            JOURNAL_NAME,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| DependencyError::Rejected)?;
        if metadata.len() != self.bytes
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || linked.st_ino != metadata.ino()
            || linked.st_dev != metadata.dev()
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }

    fn apply(
        &mut self,
        publication: StoredPublication,
        operation: Operation,
    ) -> Result<(), DependencyError> {
        let key = index_key(publication.key());
        if let Some(existing) = self.entries.get_mut(&key) {
            if existing.publication != publication
                || existing.deleted
                || operation == Operation::Publish
                || (operation == Operation::Withdraw && existing.withdrawn)
                || (operation == Operation::Delete && !existing.withdrawn)
            {
                return Err(DependencyError::Rejected);
            }
            existing.withdrawn = true;
            existing.deleted = operation == Operation::Delete;
        } else {
            if self.entries.len() >= self.maximum_entries {
                return Err(DependencyError::Rejected);
            }
            self.entries.insert(
                key,
                Entry {
                    publication,
                    withdrawn: operation != Operation::Publish,
                    deleted: operation == Operation::Delete,
                },
            );
        }
        Ok(())
    }

    fn append(
        &mut self,
        publication: &StoredPublication,
        operation: Operation,
        notification: Option<NotificationChange>,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.append_record(Some(publication.raw.clone()), operation, notification, now)
    }

    fn apply_record(&mut self, record: &Record) -> Result<(), DependencyError> {
        if let Some(now) = record.notification_clock {
            self.notifications.advance_clock(now);
        }
        if let Some(change) = &record.notification {
            self.notifications.apply(change)?;
        }
        if let Some(change) = &record.quarantine {
            if record.operation != Operation::Quarantine || record.publication.is_some() {
                return Err(DependencyError::Rejected);
            }
            self.validate_quarantine_change(change)?;
            match change {
                quarantine::Change::Upsert { record }
                | quarantine::Change::Checkpoint { record } => {
                    self.quarantine
                        .insert(index_key(&record.key()), record.clone());
                }
                quarantine::Change::Retire { record, before } => {
                    self.quarantine.remove(&index_key(&record.key()));
                    self.quarantine_retired_before = self.quarantine_retired_before.max(*before);
                }
                quarantine::Change::Watermark { before } => {
                    self.quarantine_retired_before = self.quarantine_retired_before.max(*before)
                }
            }
            return Ok(());
        }
        match (&record.publication, record.operation) {
            (Some(publication), Operation::Publish | Operation::Withdraw | Operation::Delete) => {
                self.apply(publication.clone().decode()?, record.operation)
            }
            (None, Operation::Notification) if record.notification.is_some() => Ok(()),
            _ => Err(DependencyError::Rejected),
        }
    }

    fn cleanup_reserves(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.publication.available.is_some())
            .map(|entry| {
                if entry.deleted {
                    0
                } else if entry.withdrawn {
                    1
                } else {
                    2
                }
            })
            .sum::<usize>()
            + self
                .quarantine
                .values()
                .map(|entry| match entry.phase {
                    quarantine::Phase::Retained => 2,
                    quarantine::Phase::DeleteIntent => 1,
                    quarantine::Phase::Deleted { .. } => 0,
                })
                .sum::<usize>()
    }

    fn append_record(
        &mut self,
        publication: Option<Publication>,
        operation: Operation,
        notification: Option<NotificationChange>,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.append_authority(publication, operation, notification, None, now)
    }
    fn append_authority(
        &mut self,
        publication: Option<Publication>,
        operation: Operation,
        notification: Option<NotificationChange>,
        quarantine: Option<quarantine::Change>,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        let mut candidate = self.notifications.clone();
        candidate.advance_clock(now);
        if let Some(change) = &notification {
            candidate.apply(change)?;
        }
        let mut reserves = self.cleanup_reserves();
        if let Some(change) = &quarantine {
            if operation != Operation::Quarantine || publication.is_some() {
                return Err(DependencyError::Rejected);
            }
            self.validate_quarantine_change(change)?;
            if let quarantine::Change::Upsert { record } = change {
                let old = self
                    .quarantine
                    .get(&index_key(&record.key()))
                    .map_or(0, |old| match old.phase {
                        quarantine::Phase::Retained => 2,
                        quarantine::Phase::DeleteIntent => 1,
                        quarantine::Phase::Deleted { .. } => 0,
                    });
                let new = match record.phase {
                    quarantine::Phase::Retained => 2,
                    quarantine::Phase::DeleteIntent => 1,
                    quarantine::Phase::Deleted { .. } => 0,
                };
                reserves = reserves
                    .checked_sub(old)
                    .and_then(|n| n.checked_add(new))
                    .ok_or(DependencyError::Rejected)?;
            }
        }
        if let Some(raw) = &publication {
            let value = raw.clone().decode()?;
            let existing = self.entries.get(&index_key(value.key()));
            if existing.is_none()
                && self.entries.len() + self.quarantine.len() >= self.maximum_entries
            {
                return Err(DependencyError::Rejected);
            }
            if let Some(entry) = existing
                && (entry.publication != value
                    || entry.deleted
                    || operation == Operation::Publish
                    || (operation == Operation::Withdraw && entry.withdrawn)
                    || (operation == Operation::Delete && !entry.withdrawn))
            {
                return Err(DependencyError::Rejected);
            }
            if value.available.is_some() {
                reserves = match (operation, existing) {
                    (Operation::Publish, None) => {
                        reserves.checked_add(2).ok_or(DependencyError::Rejected)?
                    }
                    (Operation::Withdraw, Some(_)) | (Operation::Delete, Some(_)) => {
                        reserves.checked_sub(1).ok_or(DependencyError::Rejected)?
                    }
                    (Operation::Withdraw, None) => {
                        reserves.checked_add(1).ok_or(DependencyError::Rejected)?
                    }
                    _ => reserves,
                };
            }
        } else if quarantine.is_none()
            && (operation != Operation::Notification || notification.is_none())
        {
            return Err(DependencyError::Rejected);
        }
        candidate.check_capacity(reserves)?;
        let record = Record {
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(DependencyError::Rejected)?,
            previous: self.digest,
            operation,
            publication,
            notification,
            notification_clock: Some(candidate.clock_floor),
            quarantine,
        };
        let digest =
            Sha256::digest(serde_json::to_vec(&record).map_err(|_| DependencyError::Rejected)?)
                .into();
        let mut encoded = serde_json::to_vec(&Envelope { record, digest })
            .map_err(|_| DependencyError::Rejected)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(DependencyError::Rejected);
        }
        encoded.push(b'\n');
        let mut next = self
            .bytes
            .checked_add(encoded.len() as u64)
            .ok_or(DependencyError::Rejected)?;
        let reserved_bytes = (reserves as u64)
            .checked_mul(MAX_RECORD_BYTES as u64 + 1)
            .ok_or(DependencyError::Rejected)?;
        if next
            .checked_add(reserved_bytes)
            .is_none_or(|total| total > self.max_bytes)
        {
            self.rewrite(None)?;
            // Physical sequence/digest changed; re-encode this same immutable notification.
            let mut envelope: Envelope = serde_json::from_slice(&encoded[..encoded.len() - 1])
                .map_err(|_| DependencyError::Rejected)?;
            envelope.record.sequence = self
                .sequence
                .checked_add(1)
                .ok_or(DependencyError::Rejected)?;
            envelope.record.previous = self.digest;
            envelope.digest = Sha256::digest(
                serde_json::to_vec(&envelope.record).map_err(|_| DependencyError::Rejected)?,
            )
            .into();
            encoded = serde_json::to_vec(&envelope).map_err(|_| DependencyError::Rejected)?;
            encoded.push(b'\n');
            next = self
                .bytes
                .checked_add(encoded.len() as u64)
                .ok_or(DependencyError::Rejected)?;
            if next
                .checked_add(reserved_bytes)
                .is_none_or(|total| total > self.max_bytes)
            {
                return Err(DependencyError::Rejected);
            }
        }
        if self
            .file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_all())
            .is_err()
        {
            self.healthy = false;
            return Err(DependencyError::OutcomeUncertain);
        }
        self.bytes = next;
        self.sequence += 1;
        let envelope: Envelope = serde_json::from_slice(&encoded[..encoded.len() - 1])
            .map_err(|_| DependencyError::Rejected)?;
        self.digest = envelope.digest;
        if self.apply_record(&envelope.record).is_err() {
            self.healthy = false;
            return Err(DependencyError::OutcomeUncertain);
        }
        Ok(())
    }

    pub fn stage(
        &mut self,
        key: ArtifactKey,
        provenance: StagedProvenance,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if self.staged.len() >= self.maximum_entries && !self.staged.contains_key(&key) {
            return Err(DependencyError::Rejected);
        }
        if let Some(existing) = self.staged.get(&key)
            && (existing.fence != provenance.fence
                || existing.metadata != provenance.metadata
                || existing.generation != provenance.generation
                || existing.scan != provenance.scan
                || existing.scan_attestation != provenance.scan_attestation)
        {
            return Err(DependencyError::Rejected);
        }
        self.staged.insert(key, provenance);
        Ok(())
    }

    pub fn validate_publish(
        &self,
        publication: &ArtifactPublication,
    ) -> Result<bool, DependencyError> {
        self.ensure_healthy()?;
        if self.quarantine.contains_key(&index_key(publication.key())) {
            return Err(DependencyError::Rejected);
        }
        publication
            .validate()
            .map_err(|_| DependencyError::Rejected)?;
        if let Some(entry) = self.entries.get(&index_key(publication.key())) {
            return if entry.publication.available.as_ref() == Some(publication) && !entry.withdrawn
            {
                Ok(false)
            } else {
                Err(DependencyError::Rejected)
            };
        }
        if self.entries.len() >= self.maximum_entries
            || self.notifications.has_rejection(publication.key())
            || !self
                .staged
                .get(publication.key())
                .is_some_and(|staged| staged.matches(publication))
        {
            return Err(DependencyError::Rejected);
        }
        Ok(true)
    }

    pub fn publish(
        &mut self,
        publication: &ArtifactPublication,
        now: u64,
    ) -> Result<(), DependencyError> {
        if self.validate_publish(publication)? {
            let mut events = vec![WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: publication.key().artifact_id().clone(),
                state: NotificationArtifactState::Available,
            }];
            if publication.metadata().source() == ArtifactContentSource::BrowserDownload {
                events.push(WorkerNotificationEvent::DownloadCompleted {
                    artifact_id: publication.key().artifact_id().clone(),
                });
            }
            let commit = self.notifications.commit(
                publication.key(),
                publication.original_fence(),
                now,
                events,
            )?;
            self.append(
                &StoredPublication::from_available(publication)?,
                Operation::Publish,
                Some(NotificationChange::Commit { commit }),
                now,
            )?;
        }
        Ok(())
    }

    pub fn withdraw(
        &mut self,
        publication: &ArtifactPublication,
        charged: bool,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        publication
            .validate()
            .map_err(|_| DependencyError::Rejected)?;
        if let Some(entry) = self.entries.get(&index_key(publication.key())) {
            if entry.publication.available.as_ref() != Some(publication) {
                return Err(DependencyError::Rejected);
            }
            if entry.withdrawn {
                return Ok(());
            }
        } else if (charged && !self.staged.contains_key(publication.key()))
            || self
                .staged
                .get(publication.key())
                .is_some_and(|staged| !staged.matches(publication))
        {
            return Err(DependencyError::Rejected);
        }
        let notification = self
            .entries
            .contains_key(&index_key(publication.key()))
            .then(|| {
                self.notifications.commit(
                    publication.key(),
                    publication.original_fence(),
                    now,
                    vec![WorkerNotificationEvent::ArtifactStateChanged {
                        artifact_id: publication.key().artifact_id().clone(),
                        state: NotificationArtifactState::Deleting,
                    }],
                )
            })
            .transpose()?
            .map(|commit| NotificationChange::Commit { commit });
        self.append(
            &StoredPublication::from_available(publication)?,
            Operation::Withdraw,
            notification,
            now,
        )
    }

    pub fn withdraw_record(
        &mut self,
        publication: &StoredPublication,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        let current = self
            .entries
            .get(&index_key(publication.key()))
            .ok_or(DependencyError::Rejected)?;
        if current.publication != *publication {
            return Err(DependencyError::Rejected);
        }
        if current.withdrawn {
            return Ok(());
        }
        let notification = publication
            .available
            .as_ref()
            .map(|available| {
                self.notifications.commit(
                    available.key(),
                    available.original_fence(),
                    now,
                    vec![WorkerNotificationEvent::ArtifactStateChanged {
                        artifact_id: available.key().artifact_id().clone(),
                        state: NotificationArtifactState::Deleting,
                    }],
                )
            })
            .transpose()?
            .map(|commit| NotificationChange::Commit { commit });
        self.append(publication, Operation::Withdraw, notification, now)
    }

    pub fn permit_delete(
        &self,
        key: &ArtifactKey,
        generation: Option<ArtifactObjectGeneration>,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if let Some(entry) = self.entries.get(&index_key(key))
            && (!entry.withdrawn
                || generation
                    .is_some_and(|generation| generation != entry.publication.object_generation()))
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
    pub fn deleted(
        &mut self,
        key: &ArtifactKey,
        generation: Option<ArtifactObjectGeneration>,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if let Some(entry) = self.entries.get(&index_key(key)) {
            if !entry.withdrawn
                || generation
                    .is_some_and(|generation| generation != entry.publication.object_generation())
            {
                return Err(DependencyError::Rejected);
            }
            if !entry.deleted {
                let publication = entry.publication.clone();
                let notification = publication
                    .available
                    .as_ref()
                    .map(|available| {
                        self.notifications.commit(
                            key,
                            available.original_fence(),
                            now,
                            vec![WorkerNotificationEvent::ArtifactStateChanged {
                                artifact_id: key.artifact_id().clone(),
                                state: NotificationArtifactState::Deleted,
                            }],
                        )
                    })
                    .transpose()?
                    .map(|commit| NotificationChange::Commit { commit });
                self.append(&publication, Operation::Delete, notification, now)?;
            }
        }
        self.staged.remove(key);
        Ok(())
    }

    pub fn reject(
        &mut self,
        key: &ArtifactKey,
        fence: &OwnershipFence,
        state: NotificationArtifactState,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if !matches!(
            state,
            NotificationArtifactState::Rejected | NotificationArtifactState::Quarantined
        ) || self.entries.contains_key(&index_key(key))
        {
            return Err(DependencyError::Rejected);
        }
        if self.notifications.rejection_exists(key, fence, state)? {
            return Ok(());
        }
        let commit = self.notifications.commit(
            key,
            fence,
            now,
            vec![WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: key.artifact_id().clone(),
                state,
            }],
        )?;
        self.append_record(
            None,
            Operation::Notification,
            Some(NotificationChange::Commit { commit }),
            now,
        )
    }

    pub fn pending_notifications(
        &self,
        cursor: Option<&str>,
        max_scopes: usize,
        max_descriptors: usize,
    ) -> Result<browserd_worker::WorkerNotificationPage, DependencyError> {
        self.ensure_healthy()?;
        self.notifications.page(cursor, max_scopes, max_descriptors)
    }

    pub fn acknowledge_notifications(
        &mut self,
        ack: &NotificationAck,
        now: u64,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if self.notifications.validate_ack(ack)? {
            self.append_record(
                None,
                Operation::Notification,
                Some(NotificationChange::Acknowledge {
                    ack: ack.clone(),
                    acknowledged_at: now.max(self.notifications.clock_floor),
                }),
                now,
            )?;
        }
        Ok(())
    }

    pub fn records(&self) -> Vec<(StoredPublication, bool)> {
        self.entries
            .values()
            .map(|entry| (entry.publication.clone(), entry.withdrawn))
            .collect()
    }
    pub fn record(&self, key: &ArtifactKey) -> Option<(StoredPublication, bool)> {
        self.entries
            .get(&index_key(key))
            .map(|entry| (entry.publication.clone(), entry.withdrawn))
    }
    pub fn retire(
        &mut self,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
    ) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        if let Some(entry) = self.entries.get(&index_key(key))
            && (!entry.withdrawn || entry.publication.object_generation() != generation)
        {
            return Err(DependencyError::Rejected);
        }
        self.rewrite(Some(key))?;
        self.entries.remove(&index_key(key));
        self.staged.remove(key);
        Ok(())
    }
    pub fn compact_if_needed(&mut self, threshold: u64, now: u64) -> Result<(), DependencyError> {
        self.notifications.advance_clock(now);
        if self.bytes >= threshold {
            self.rewrite(None)?;
        }
        Ok(())
    }
    fn rewrite(&mut self, omit: Option<&ArtifactKey>) -> Result<(), DependencyError> {
        self.ensure_healthy()?;
        let mut bytes = HEADER.to_vec();
        let mut sequence = 0u64;
        let mut digest = [0; 32];
        let now = self.notifications.clock_floor;
        let pins = self.quarantine.keys().cloned().collect();
        for change in self.notifications.compact_changes(now, &pins)? {
            sequence = sequence.checked_add(1).ok_or(DependencyError::Rejected)?;
            let record = Record {
                sequence,
                previous: digest,
                operation: Operation::Notification,
                publication: None,
                notification: Some(change),
                notification_clock: Some(now),
                quarantine: None,
            };
            digest =
                Sha256::digest(serde_json::to_vec(&record).map_err(|_| DependencyError::Rejected)?)
                    .into();
            let encoded = serde_json::to_vec(&Envelope { record, digest })
                .map_err(|_| DependencyError::Rejected)?;
            if encoded.len() > MAX_RECORD_BYTES {
                return Err(DependencyError::Rejected);
            }
            bytes.extend(encoded);
            bytes.push(b'\n');
            if bytes.len() as u64 > self.max_bytes {
                return Err(DependencyError::Rejected);
            }
        }
        for entry in self.entries.values() {
            if omit == Some(entry.publication.key()) {
                continue;
            }
            sequence = sequence.checked_add(1).ok_or(DependencyError::Rejected)?;
            let record = Record {
                sequence,
                previous: digest,
                operation: if entry.deleted {
                    Operation::Delete
                } else if entry.withdrawn {
                    Operation::Withdraw
                } else {
                    Operation::Publish
                },
                publication: Some(entry.publication.raw.clone()),
                notification: None,
                notification_clock: None,
                quarantine: None,
            };
            digest =
                Sha256::digest(serde_json::to_vec(&record).map_err(|_| DependencyError::Rejected)?)
                    .into();
            serde_json::to_writer(&mut bytes, &Envelope { record, digest })
                .map_err(|_| DependencyError::Rejected)?;
            bytes.push(b'\n');
            if bytes.len() as u64 > self.max_bytes {
                return Err(DependencyError::Rejected);
            }
        }
        let mut changes = vec![quarantine::Change::Watermark {
            before: self.quarantine_retired_before,
        }];
        changes.extend(
            self.quarantine
                .values()
                .cloned()
                .map(|record| quarantine::Change::Checkpoint { record }),
        );
        if self.quarantine_retired_before == 0 && self.quarantine.is_empty() {
            changes.clear();
        }
        for change in changes {
            sequence = sequence.checked_add(1).ok_or(DependencyError::Rejected)?;
            let record = Record {
                sequence,
                previous: digest,
                operation: Operation::Quarantine,
                publication: None,
                notification: None,
                notification_clock: None,
                quarantine: Some(change),
            };
            digest =
                Sha256::digest(serde_json::to_vec(&record).map_err(|_| DependencyError::Rejected)?)
                    .into();
            let encoded = serde_json::to_vec(&Envelope { record, digest })
                .map_err(|_| DependencyError::Rejected)?;
            if encoded.len() > MAX_RECORD_BYTES {
                return Err(DependencyError::Rejected);
            }
            bytes.extend(encoded);
            bytes.push(b'\n');
            if bytes.len() as u64 > self.max_bytes {
                return Err(DependencyError::Rejected);
            }
        }
        match super::retention::replace_file(
            &self.root,
            JOURNAL_NAME,
            "publications.tmp",
            &bytes,
            self.max_bytes,
        ) {
            Ok(file) => {
                self.file = file;
                self.bytes = bytes.len() as u64;
                self.sequence = sequence;
                self.digest = digest;
                self.notifications.retire_rejections(now, &pins);
                Ok(())
            }
            Err(error) => {
                self.healthy = false;
                Err(error)
            }
        }
    }

    pub fn published(&self) -> impl Iterator<Item = &StoredPublication> {
        self.entries
            .values()
            .filter(|entry| !entry.withdrawn)
            .map(|entry| &entry.publication)
    }
    pub fn get(
        &self,
        key: &ArtifactKey,
        now: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        self.ensure_healthy()?;
        Ok(self
            .entries
            .get(&index_key(key))
            .filter(|entry| {
                !entry.withdrawn
                    && now >= entry.publication.published_at_unix_millis()
                    && now < entry.publication.expires_at_unix_millis()
            })
            .and_then(|entry| entry.publication.available.clone()))
    }
    pub fn list(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        after: Option<&ArtifactId>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        self.ensure_healthy()?;
        if !(1..=101).contains(&limit) {
            return Err(DependencyError::Rejected);
        }
        // Tuple range seeks directly to this namespace; expired/withdrawn records are bounded
        // by the configured total retained-entry ceiling and never resurrected by enumeration.
        let lower = after.map(|id| Excluded((tenant.clone(), session.clone(), id.clone())));
        let mut output = Vec::with_capacity(limit);
        let range = match lower {
            Some(lower) => self.entries.range((lower, Unbounded)),
            None => self.entries.range((
                Included((tenant.clone(), session.clone(), minimum_artifact_id()?)),
                Unbounded,
            )),
        };
        for ((current_tenant, current_session, _), entry) in range {
            if current_tenant != tenant || current_session != session {
                break;
            }
            if !entry.withdrawn
                && now >= entry.publication.published_at_unix_millis()
                && now < entry.publication.expires_at_unix_millis()
                && let Some(publication) = &entry.publication.available
            {
                output.push(publication.clone());
                if output.len() == limit {
                    break;
                }
            }
        }
        Ok(output)
    }
}

fn minimum_artifact_id() -> Result<ArtifactId, DependencyError> {
    "00000000-0000-7000-8000-000000000000"
        .parse()
        .map_err(|_| DependencyError::Rejected)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod admission_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::mpsc;

    #[test]
    fn old_publication_frames_preserve_their_digest_and_never_invent_historical_events() {
        let (root, _runtime, store, publication) = fixture();
        drop(store);
        let record = Record {
            sequence: 1,
            previous: [0; 32],
            operation: Operation::Publish,
            publication: Some(Publication::encode(&publication).expect("old publication")),
            notification: None,
            notification_clock: None,
            quarantine: None,
        };
        let digest = Sha256::digest(serde_json::to_vec(&record).expect("old encoding")).into();
        let mut bytes = HEADER.to_vec();
        serde_json::to_writer(&mut bytes, &Envelope { record, digest }).expect("v1 frame");
        bytes.push(b'\n');
        fs::write(root.path().join(JOURNAL_NAME), &bytes).expect("legacy authority");
        let owner = Arc::new(File::open(root.path()).expect("root"));
        let mut registry = Publications::open(owner, 4).expect("compatible old digest");
        assert_eq!(
            registry
                .get(publication.key(), 1001)
                .expect("legacy visible"),
            Some(publication.clone())
        );
        assert!(
            registry
                .pending_notifications(None, 32, 8)
                .expect("no fabricated event")
                .commits
                .is_empty()
        );
        let stored = registry.record(publication.key()).expect("record").0;
        registry
            .withdraw_record(&stored, 1002)
            .expect("actual new transition");
        let page = registry
            .pending_notifications(None, 32, 8)
            .expect("new event");
        assert_eq!(page.commits.len(), 1);
        assert_eq!(page.commits[0].source_sequence(), 1);
        assert_eq!(
            page.commits[0].descriptors()[0].event(),
            &WorkerNotificationEvent::ArtifactStateChanged {
                artifact_id: publication.key().artifact_id().clone(),
                state: NotificationArtifactState::Deleting
            }
        );
    }

    fn fixture() -> (
        tempfile::TempDir,
        tokio::runtime::Runtime,
        Arc<ProductionArtifactStore>,
        ArtifactPublication,
    ) {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let store = Arc::new(
            ProductionArtifactStore::open(
                ArtifactStoreConfig {
                    root: root.path().to_owned(),
                    max_file_bytes: 8,
                    max_worker_bytes: 16,
                    max_worker_in_flight_bytes: 8,
                    max_session_bytes: 12,
                    max_session_in_flight_bytes: 8,
                    max_retained_artifacts: 4,
                    max_operations: 4,
                    chunk_bytes: 2,
                    operation_timeout: Duration::from_millis(100),
                },
                runtime.handle().clone(),
                None,
            )
            .expect("store"),
        );
        let publication = ArtifactPublication::new(
            ArtifactKey::new(TenantId::new(), SessionId::new(), ArtifactId::new()),
            OwnershipFence::new(WorkerId::new("admission-test").expect("worker"), 1, 1, 1),
            ArtifactContentMetadata::new(
                1,
                ArtifactChecksum::new([1; 32]),
                "text/plain",
                ArtifactContentSource::Generated,
                "capture",
            )
            .expect("metadata"),
            ArtifactObjectGeneration::new([1; 32]),
            None,
            None,
            1000,
            2000,
        )
        .expect("publication");
        (root, runtime, store, publication)
    }

    #[test]
    fn journal_holds_its_configured_maximum_of_live_publications_and_no_more() {
        // Above both former ceilings: about 250 live artifacts from the byte reserve and 2048
        // from the pending-notification reserve.
        const CONFIGURED: usize = 2_100;
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let owner = Arc::new(File::open(root.path()).expect("root"));
        let mut registry = Publications::open(owner.clone(), CONFIGURED).expect("authority");
        let tenant = TenantId::new();
        let session = SessionId::new();
        let fence = OwnershipFence::new(WorkerId::new("capacity-test").expect("worker"), 1, 1, 1);
        let stage = |registry: &mut Publications| {
            let key = ArtifactKey::new(tenant.clone(), session.clone(), ArtifactId::new());
            let metadata = ArtifactContentMetadata::new(
                1,
                ArtifactChecksum::new([1; 32]),
                "text/plain",
                ArtifactContentSource::Generated,
                "capture",
            )
            .expect("metadata");
            let generation = ArtifactObjectGeneration::new([1; 32]);
            let publication = ArtifactPublication::new(
                key.clone(),
                fence.clone(),
                metadata.clone(),
                generation,
                None,
                None,
                1000,
                2000,
            )
            .expect("publication");
            registry
                .stage(
                    key,
                    StagedProvenance {
                        fence: fence.clone(),
                        metadata,
                        generation,
                        scan: None,
                        scan_attestation: None,
                    },
                )
                .expect("staged");
            publication
        };
        let mut live = Vec::new();
        for index in 0..CONFIGURED {
            let publication = stage(&mut registry);
            assert_eq!(registry.publish(&publication, 1000), Ok(()), "{index}");
            live.push(publication);
        }
        // No notification was acknowledged, yet every artifact's cleanup stays admissible.
        let first = &live[0];
        registry.withdraw(first, true, 1001).expect("withdraw");
        registry
            .deleted(first.key(), Some(first.object_generation()), 1002)
            .expect("delete");
        // The configured maximum remains the bound, counting the deleted record until retirement.
        let extra = stage(&mut registry);
        assert_eq!(
            registry.publish(&extra, 1003),
            Err(DependencyError::Rejected)
        );
        drop(registry);
        let reopened = Publications::open(owner, CONFIGURED).expect("restart");
        assert_eq!(reopened.published().count(), CONFIGURED - 1);
        assert_eq!(reopened.records().len(), CONFIGURED);
    }

    #[test]
    fn publication_admission_fails_promptly_while_quota_io_owns_ledger() {
        let (_root, _runtime, store, publication) = fixture();
        let ledger = store.shared.ledger.lock().expect("simulated quota fsync");
        let (tx, rx) = mpsc::channel();
        let worker = {
            let store = store.clone();
            std::thread::spawn(move || {
                let denied = [
                    store.publish_artifact(&publication).is_err(),
                    store.withdraw_artifact(&publication).is_err(),
                    store
                        .get_retained_artifact(publication.key(), 1001)
                        .is_err(),
                    store
                        .list_retained_artifacts(
                            publication.key().tenant_id(),
                            publication.key().session_id(),
                            None,
                            1,
                            1001,
                        )
                        .is_err(),
                ];
                tx.send(denied).expect("result");
            })
        };
        let result = rx.recv_timeout(Duration::from_millis(250));
        drop(ledger); // Always unblock a regressed implementation before asserting.
        worker.join().expect("worker");
        assert_eq!(
            result.expect("admission must not wait for fsync"),
            [true; 4]
        );
    }

    #[test]
    fn publication_guard_drop_defers_release_without_blocking_authority() {
        let (_root, _runtime, store, publication) = fixture();
        let exclusive = exclusive(&store.shared, publication.key(), true).expect("exclusive");
        let metadata = metadata_operation(&store.shared).expect("metadata permit");
        let ledger = store.shared.ledger.lock().expect("simulated quota fsync");
        assert_eq!(ledger.operations, 2);
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            drop(exclusive);
            drop(metadata);
            tx.send(()).expect("drop complete");
        });
        let result = rx.recv_timeout(Duration::from_millis(250));
        assert_eq!(
            ledger.operations, 2,
            "permits remain owned until actual release"
        );
        assert!(ledger.discarding.contains(publication.key()));
        drop(ledger);
        worker.join().expect("worker");
        result.expect("guard drop must not block CP authority");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            {
                let ledger = store.shared.ledger.lock().expect("settled ledger");
                if ledger.operations == 0 {
                    assert!(!ledger.discarding.contains(publication.key()));
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "deferred permits must settle"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    struct Clock(std::sync::atomic::AtomicU64);
    impl WorkerClock for Clock {
        fn now(&self) -> Result<browserd_session::SessionTime, browserd_worker::WorkerError> {
            Ok(browserd_session::SessionTime::new(
                self.0.load(std::sync::atomic::Ordering::SeqCst),
            ))
        }
    }
    #[test]
    fn legacy_clean_only_journal_stays_hidden_charged_and_expires_without_scanner_or_fake_publication()
     {
        let (root, runtime, original, _) = fixture();
        let config = original.shared.config.clone();
        drop(original);
        let clock = Arc::new(Clock(std::sync::atomic::AtomicU64::new(1000)));
        let store = ProductionArtifactStore::open_with_retention(
            config.clone(),
            runtime.handle().clone(),
            None,
            ArtifactRetentionConfig {
                compact_at_bytes: 1,
                ..Default::default()
            },
            clock.clone(),
        )
        .expect("store");
        let tenant = TenantId::new();
        let session = SessionId::new();
        let mut originals = Vec::new();
        for _ in 0..2 {
            let request = ArtifactStoreRequest::new_generated(
                tenant.clone(),
                session.clone(),
                ArtifactId::new(),
                OwnershipFence::new(WorkerId::new("legacy-owner").expect("worker"), 1, 1, 1),
                b"abc".to_vec(),
                "text/plain",
                8,
                "fixture",
            )
            .expect("request");
            let receipt = store.store(&request).expect("bytes");
            let publication = ArtifactPublication::new(
                receipt.key().clone(),
                request.fence().clone(),
                ArtifactContentMetadata::new(
                    receipt.size_bytes(),
                    *receipt.checksum(),
                    receipt.detected_content_type(),
                    receipt.source(),
                    request.origin(),
                )
                .expect("metadata"),
                receipt.object_generation(),
                None,
                Some("name.txt".into()),
                1000,
                2000,
            )
            .expect("publication");
            store.publish_artifact(&publication).expect("publish");
            originals.push(publication);
        }
        drop(store);
        // Encode exactly the v1 field order and hash chain. The optional evidence field
        // must be absent, so old authentic records remain readable without re-signing.
        let raw = fs::read(root.path().join(JOURNAL_NAME)).expect("journal");
        let mut output = HEADER.to_vec();
        let mut previous = [0; 32];
        let mut legacy_publications = 0;
        for line in raw[HEADER.len()..]
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let mut envelope: Envelope = serde_json::from_slice(line).expect("record");
            if let Some(publication) = envelope.record.publication.as_mut()
                && publication.artifact == *originals[0].key().artifact_id()
            {
                publication.source = Source::ClientUpload;
                publication.scan = Some(Scan::Clean);
                legacy_publications += 1;
            }
            envelope.record.previous = previous;
            let encoded = serde_json::to_vec(&envelope.record).expect("v1 canonical record");
            assert!(!String::from_utf8_lossy(&encoded).contains("scan_attestation"));
            envelope.digest = Sha256::digest(encoded).into();
            previous = envelope.digest;
            output.extend(serde_json::to_vec(&envelope).expect("envelope"));
            output.push(b'\n');
        }
        assert_eq!(legacy_publications, 1, "one exact legacy publication");
        fs::write(root.path().join(JOURNAL_NAME), &output).expect("old version fixture");
        let store = ProductionArtifactStore::open_with_retention(
            config.clone(),
            runtime.handle().clone(),
            None,
            ArtifactRetentionConfig {
                compact_at_bytes: 1,
                ..Default::default()
            },
            clock.clone(),
        )
        .expect("v1 compatible reopen");
        assert!(
            store
                .get_retained_artifact(originals[0].key(), 1000)
                .expect("hidden legacy")
                .is_none()
        );
        assert_eq!(
            store
                .list_retained_artifacts(&tenant, &session, None, 101, 1000)
                .expect("list"),
            vec![originals[1].clone()]
        );
        assert!(
            store
                .open_retained_artifact(
                    &originals[0],
                    ArtifactReadLimits::new(1).expect("limit"),
                    1000
                )
                .is_err()
        );
        assert!(
            store.publish_artifact(&originals[0]).is_err(),
            "legacy identity cannot be promoted"
        );
        assert_eq!(store.shared.ledger.lock().expect("ledger").charges.len(), 2);
        store
            .maintain(64)
            .expect("compaction preserves hidden metadata");
        drop(store);
        let store = ProductionArtifactStore::open_with_retention(
            config.clone(),
            runtime.handle().clone(),
            None,
            ArtifactRetentionConfig::default(),
            clock.clone(),
        )
        .expect("compacted legacy reopen");
        assert!(
            store
                .get_retained_artifact(originals[0].key(), 1000)
                .expect("still hidden")
                .is_none()
        );
        clock.0.store(2001, std::sync::atomic::Ordering::SeqCst);
        for _ in 0..4 {
            store.maintain(64).expect("exact expiry cleanup");
        }
        assert!(
            store
                .shared
                .ledger
                .lock()
                .expect("released ledger")
                .charges
                .is_empty()
        );
        assert!(
            store
                .list_retained_artifacts(&tenant, &session, None, 101, 2001)
                .expect("expired")
                .is_empty()
        );
        drop(store);
        ProductionArtifactStore::open_with_retention(
            config,
            runtime.handle().clone(),
            None,
            ArtifactRetentionConfig::default(),
            clock,
        )
        .expect("withdrawn legacy exact cleanup reopens");
    }

    #[test]
    fn legacy_cleanup_decoder_keeps_old_validation_and_never_downgrades_invalid_present_evidence() {
        let (_root, _runtime, _store, publication) = fixture();
        for invalid in 0..6 {
            let mut raw = Publication::encode(&publication).expect("dto");
            raw.source = Source::ClientUpload;
            raw.scan = Some(Scan::Clean);
            assert!(
                raw.clone()
                    .decode()
                    .expect("valid legacy")
                    .available
                    .is_none()
            );
            match invalid {
                0 => raw.worker_epoch = 0,
                1 => raw.generation = [0; 32],
                2 => raw.expires_at = raw.published_at,
                3 => {
                    raw.expires_at =
                        raw.published_at + browserd_worker::ARTIFACT_PUBLICATION_TTL_MILLIS + 1
                }
                4 => raw.display_filename = Some("../unsafe".into()),
                _ => raw.scan = None,
            }
            assert!(raw.decode().is_err());
        }
        let mut raw = Publication::encode(&publication).expect("dto");
        raw.source = Source::ClientUpload;
        raw.scan = Some(Scan::Clean);
        let mut explicit_null = serde_json::to_value(&raw).expect("legacy dto");
        explicit_null["scan_attestation"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<Publication>(explicit_null).is_err(),
            "present null evidence cannot masquerade as absent v1 field"
        );
        raw.scan_attestation = Some(
            ArtifactScanAttestation::new(
                publication.key(),
                publication.original_fence(),
                ArtifactContentSource::ClientUpload,
                publication.object_generation(),
                1,
                *publication.metadata().checksum(),
                browserd_worker::ArtifactScannerObservation {
                    schema_version: 1,
                    program_version: "fixture".into(),
                    database_version: 1,
                    database_built_at_unix_millis: 1000,
                    observed_before_unix_millis: 1000,
                    observed_after_unix_millis: 1000,
                    expected_peer_uid: 1000,
                    peer_uid: 1000,
                    version_metadata_sha256: [1; 32],
                    scanned_size_bytes: 1,
                    scanned_checksum_sha256: [1; 32],
                    max_database_age_millis: 1000,
                    max_future_skew_millis: 0,
                },
            )
            .expect("valid evidence"),
        );
        raw.worker_epoch += 1;
        assert!(
            raw.decode().is_err(),
            "present evidence mismatch cannot use legacy compatibility path"
        );
    }
}
