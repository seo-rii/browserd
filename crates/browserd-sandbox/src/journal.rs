use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{EgressFence, PreparedShardLifecycle, PreparedShardTransition, ShardFence};
use nix::dir::Dir;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat, openat2, renameat};
use nix::sys::stat::{Mode, fstat};
use nix::unistd::{Uid, UnlinkatFlags, unlinkat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

const SCHEMA_VERSION: u32 = 1;
const FILE_MAGIC: &[u8; 8] = b"BRPSJ001";
const CHECKSUM_BYTES: usize = 32;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_BACKEND_TOKEN_BYTES: usize = 4 * 1024;
const MAX_EVENTS: usize = 1_024;
const LOCK_FILE_NAME: &str = ".prepared-shard-journal.lock";
const RECORD_SUFFIX: &str = ".psj";
const DEFAULT_RECOVERY_CONCURRENCY: usize = 8;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedShardJournalLimits {
    max_records: usize,
    max_record_bytes: usize,
    max_total_bytes: usize,
    max_temporary_files: usize,
}

impl PreparedShardJournalLimits {
    pub fn new(
        max_records: usize,
        max_record_bytes: usize,
        max_total_bytes: usize,
        max_temporary_files: usize,
    ) -> Result<Self, PreparedShardJournalError> {
        let minimum_frame_bytes = FILE_MAGIC.len() + 4 + CHECKSUM_BYTES + 1;
        if max_records == 0
            || max_record_bytes == 0
            || max_record_bytes > MAX_RECORD_BYTES
            || max_total_bytes < minimum_frame_bytes + max_record_bytes
            || max_temporary_files == 0
        {
            return Err(PreparedShardJournalError::InvalidLimits);
        }
        Ok(Self {
            max_records,
            max_record_bytes,
            max_total_bytes,
            max_temporary_files,
        })
    }

    #[must_use]
    pub const fn max_records(self) -> usize {
        self.max_records
    }

    #[must_use]
    pub const fn max_record_bytes(self) -> usize {
        self.max_record_bytes
    }

    #[must_use]
    pub const fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }

    #[must_use]
    pub const fn max_temporary_files(self) -> usize {
        self.max_temporary_files
    }
}

impl Default for PreparedShardJournalLimits {
    fn default() -> Self {
        Self {
            max_records: 4_096,
            max_record_bytes: MAX_RECORD_BYTES,
            max_total_bytes: 64 * 1024 * 1024,
            max_temporary_files: 4_096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedShardRecoveryRoots {
    cgroup_root: PathBuf,
    runtime_root: PathBuf,
}

impl PreparedShardRecoveryRoots {
    pub fn new(
        cgroup_root: PathBuf,
        runtime_root: PathBuf,
    ) -> Result<Self, PreparedShardJournalError> {
        let roots_are_valid = [&cgroup_root, &runtime_root].into_iter().all(|root| {
            root.is_absolute()
                && root != Path::new("/")
                && !root.as_os_str().as_bytes().is_empty()
                && root.as_os_str().as_bytes().len() <= MAX_PATH_BYTES
                && root
                    .components()
                    .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
        });
        if !roots_are_valid
            || cgroup_root == runtime_root
            || cgroup_root.starts_with(&runtime_root)
            || runtime_root.starts_with(&cgroup_root)
        {
            return Err(PreparedShardJournalError::InvalidRecoveryRoots);
        }
        Ok(Self {
            cgroup_root,
            runtime_root,
        })
    }

    #[must_use]
    pub fn production() -> Self {
        Self {
            cgroup_root: PathBuf::from("/sys/fs/cgroup/browserd"),
            runtime_root: PathBuf::from("/run/browserd/shards"),
        }
    }

    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    #[must_use]
    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JournalSequence(NonZeroU64);

impl JournalSequence {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedShardRecoveryDisposition {
    CleanupOnly,
    CleanupPending,
    ReleasedTombstone,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedShardCleanupStage {
    RevokeEgress,
    AbortGate,
    KillCgroup,
    ConfirmProcessDeath,
    ConfirmEgressDrained,
    CloseCapabilities,
    CleanupNetworkNamespace,
    CleanupRuntimeFilesystem,
    RemoveCgroup,
    ReleaseEgressGeneration,
}

impl PreparedShardCleanupStage {
    pub const ALL: [Self; 10] = [
        Self::RevokeEgress,
        Self::AbortGate,
        Self::KillCgroup,
        Self::ConfirmProcessDeath,
        Self::ConfirmEgressDrained,
        Self::CloseCapabilities,
        Self::CleanupNetworkNamespace,
        Self::CleanupRuntimeFilesystem,
        Self::RemoveCgroup,
        Self::ReleaseEgressGeneration,
    ];

    const fn index(self) -> usize {
        match self {
            Self::RevokeEgress => 0,
            Self::AbortGate => 1,
            Self::KillCgroup => 2,
            Self::ConfirmProcessDeath => 3,
            Self::ConfirmEgressDrained => 4,
            Self::CloseCapabilities => 5,
            Self::CleanupNetworkNamespace => 6,
            Self::CleanupRuntimeFilesystem => 7,
            Self::RemoveCgroup => 8,
            Self::ReleaseEgressGeneration => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedShardCleanupStageStatus {
    NotStarted,
    InProgress,
    Failed,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedShardCleanupProgress {
    status: PreparedShardCleanupStageStatus,
    attempts: u64,
    last_failure: Option<PreparedShardCleanupFailure>,
}

impl PreparedShardCleanupProgress {
    const NOT_STARTED: Self = Self {
        status: PreparedShardCleanupStageStatus::NotStarted,
        attempts: 0,
        last_failure: None,
    };

    #[must_use]
    pub const fn status(self) -> PreparedShardCleanupStageStatus {
        self.status
    }

    #[must_use]
    pub const fn attempts(self) -> u64 {
        self.attempts
    }

    #[must_use]
    pub const fn last_failure(self) -> Option<PreparedShardCleanupFailure> {
        self.last_failure
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedShardCleanupFailure {
    Backend,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedShardCleanupPermit {
    fence: ShardFence,
    stage: PreparedShardCleanupStage,
    attempt: u64,
    sequence: JournalSequence,
    record: PreparedShardJournalRecord,
}

impl PreparedShardCleanupPermit {
    #[must_use]
    pub const fn fence(&self) -> &ShardFence {
        &self.fence
    }

    #[must_use]
    pub const fn stage(&self) -> PreparedShardCleanupStage {
        self.stage
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    #[must_use]
    pub const fn record(&self) -> &PreparedShardJournalRecord {
        &self.record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "effect", content = "evidence", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum PreparedShardEffect {
    CreateFilesystemCgroup,
    PrepareEgress(EgressFence),
    SpawnGatedChild,
    ProveProcessIdentity,
    AttachCgroup,
    ProveNetworkNamespace,
    RegisterIngress(EgressFence),
    ClaimCdp,
    ProveContainment,
    SendReleaseToken { release_sequence: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedShardEffectPermit {
    fence: ShardFence,
    effect: PreparedShardEffect,
    sequence: JournalSequence,
}

impl PreparedShardEffectPermit {
    #[must_use]
    pub const fn fence(&self) -> &ShardFence {
        &self.fence
    }

    #[must_use]
    pub const fn effect(&self) -> &PreparedShardEffect {
        &self.effect
    }

    #[must_use]
    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }
}

/// Exact capabilities needed to reclaim one prepared shard.
///
/// This secret-bearing type deliberately has no public serialization boundary.
///
/// ```compile_fail
/// use browserd_sandbox::PreparedShardRecoveryLocators;
///
/// fn serialize_publicly(locators: &PreparedShardRecoveryLocators) {
///     let _ = serde_json::to_string(locators);
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedShardRecoveryLocators {
    backend_token: String,
    cgroup_path: PathBuf,
    runtime_path: PathBuf,
    egress_daemon_epoch: Option<u64>,
    egress_fence: Option<EgressFence>,
}

impl PreparedShardRecoveryLocators {
    pub fn new(
        backend_token: impl Into<String>,
        cgroup_path: PathBuf,
        runtime_path: PathBuf,
    ) -> Result<Self, PreparedShardJournalError> {
        let backend_token = backend_token.into();
        if backend_token.is_empty()
            || backend_token.len() > MAX_BACKEND_TOKEN_BYTES
            || backend_token.chars().any(char::is_control)
            || backend_token.contains(['/', '\\'])
            || matches!(backend_token.as_str(), "." | "..")
        {
            return Err(PreparedShardJournalError::InvalidLocators);
        }
        if [&cgroup_path, &runtime_path].into_iter().any(|path| {
            !path.is_absolute()
                || path == Path::new("/")
                || path.as_os_str().as_bytes().is_empty()
                || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
                || path
                    .components()
                    .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        }) {
            return Err(PreparedShardJournalError::InvalidLocators);
        }
        Ok(Self {
            backend_token,
            cgroup_path,
            runtime_path,
            egress_daemon_epoch: None,
            egress_fence: None,
        })
    }

    pub fn with_egress_binding(
        mut self,
        daemon_epoch: u64,
        egress_fence: EgressFence,
    ) -> Result<Self, PreparedShardJournalError> {
        if daemon_epoch == 0 {
            return Err(PreparedShardJournalError::InvalidLocators);
        }
        self.egress_daemon_epoch = Some(daemon_epoch);
        self.egress_fence = Some(egress_fence);
        Ok(self)
    }

    #[must_use]
    pub fn backend_token(&self) -> &str {
        &self.backend_token
    }

    #[must_use]
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    #[must_use]
    pub fn runtime_path(&self) -> &Path {
        &self.runtime_path
    }

    #[must_use]
    pub const fn egress_daemon_epoch(&self) -> Option<u64> {
        self.egress_daemon_epoch
    }

    #[must_use]
    pub const fn egress_fence(&self) -> Option<&EgressFence> {
        self.egress_fence.as_ref()
    }
}

impl fmt::Debug for PreparedShardRecoveryLocators {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedShardRecoveryLocators")
            .field("backend_token", &"[REDACTED]")
            .field("cgroup_path", &self.cgroup_path)
            .field("runtime_path", &self.runtime_path)
            .field(
                "egress_binding",
                &self.egress_fence.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPreparedShardRecoveryLocators {
    backend_token: String,
    cgroup_path: PathBuf,
    runtime_path: PathBuf,
    #[serde(default)]
    egress_daemon_epoch: Option<u64>,
    #[serde(default)]
    egress_fence: Option<EgressFence>,
}

impl From<&PreparedShardRecoveryLocators> for StoredPreparedShardRecoveryLocators {
    fn from(locators: &PreparedShardRecoveryLocators) -> Self {
        Self {
            backend_token: locators.backend_token.clone(),
            cgroup_path: locators.cgroup_path.clone(),
            runtime_path: locators.runtime_path.clone(),
            egress_daemon_epoch: locators.egress_daemon_epoch,
            egress_fence: locators.egress_fence.clone(),
        }
    }
}

impl TryFrom<StoredPreparedShardRecoveryLocators> for PreparedShardRecoveryLocators {
    type Error = PreparedShardJournalError;

    fn try_from(stored: StoredPreparedShardRecoveryLocators) -> Result<Self, Self::Error> {
        let locators = Self::new(
            stored.backend_token,
            stored.cgroup_path,
            stored.runtime_path,
        )?;
        match (stored.egress_daemon_epoch, stored.egress_fence) {
            (None, None) => Ok(locators),
            (Some(epoch), Some(fence)) => locators.with_egress_binding(epoch, fence),
            _ => Err(PreparedShardJournalError::InvalidLocators),
        }
    }
}

/// Validated recovery state exposed without a public serialization boundary.
///
/// ```compile_fail
/// use browserd_sandbox::PreparedShardJournalRecord;
///
/// fn serialize_publicly(record: &PreparedShardJournalRecord) {
///     let _ = serde_json::to_string(record);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedShardJournalRecord {
    schema_version: u32,
    fence: ShardFence,
    sequence: JournalSequence,
    locators: PreparedShardRecoveryLocators,
    events: Vec<PreparedShardJournalEvent>,
    cleanup: [PreparedShardCleanupProgress; 10],
    cleanup_writes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
enum PreparedShardJournalEvent {
    Intent {
        sequence: JournalSequence,
        effect: PreparedShardEffect,
    },
    Completed {
        sequence: JournalSequence,
        effect: PreparedShardEffect,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPreparedShardJournalRecord {
    schema_version: u32,
    fence: ShardFence,
    sequence: JournalSequence,
    locators: StoredPreparedShardRecoveryLocators,
    events: Vec<PreparedShardJournalEvent>,
    cleanup: [PreparedShardCleanupProgress; 10],
    cleanup_writes: u64,
}

impl From<&PreparedShardJournalRecord> for StoredPreparedShardJournalRecord {
    fn from(record: &PreparedShardJournalRecord) -> Self {
        Self {
            schema_version: record.schema_version,
            fence: record.fence.clone(),
            sequence: record.sequence,
            locators: (&record.locators).into(),
            events: record.events.clone(),
            cleanup: record.cleanup,
            cleanup_writes: record.cleanup_writes,
        }
    }
}

impl TryFrom<StoredPreparedShardJournalRecord> for PreparedShardJournalRecord {
    type Error = PreparedShardJournalError;

    fn try_from(stored: StoredPreparedShardJournalRecord) -> Result<Self, Self::Error> {
        let record = Self {
            schema_version: stored.schema_version,
            fence: stored.fence,
            sequence: stored.sequence,
            locators: stored.locators.try_into()?,
            events: stored.events,
            cleanup: stored.cleanup,
            cleanup_writes: stored.cleanup_writes,
        };
        validate_record(&record)?;
        Ok(record)
    }
}

impl PreparedShardJournalRecord {
    #[must_use]
    pub const fn fence(&self) -> &ShardFence {
        &self.fence
    }

    #[must_use]
    pub const fn sequence(&self) -> JournalSequence {
        self.sequence
    }

    #[must_use]
    pub const fn locators(&self) -> &PreparedShardRecoveryLocators {
        &self.locators
    }

    #[must_use]
    pub fn pending_effect(&self) -> Option<&PreparedShardEffect> {
        if self.cleanup.iter().any(|progress| progress.attempts > 0) {
            return None;
        }
        match self.events.last() {
            Some(PreparedShardJournalEvent::Intent { effect, .. }) => Some(effect),
            Some(PreparedShardJournalEvent::Completed { .. }) | None => None,
        }
    }

    pub fn lifecycle_state(
        &self,
    ) -> Result<browserd_core::PreparedShardState, PreparedShardJournalError> {
        validate_record(self).map(|replay| replay.lifecycle.state())
    }

    pub fn cleanup_progress(
        &self,
        stage: PreparedShardCleanupStage,
    ) -> Result<PreparedShardCleanupProgress, PreparedShardJournalError> {
        validate_record(self).map(|replay| replay.cleanup[stage.index()])
    }

    #[must_use]
    pub fn recovery_disposition(&self) -> PreparedShardRecoveryDisposition {
        if self.cleanup[PreparedShardCleanupStage::ReleaseEgressGeneration.index()].status
            == PreparedShardCleanupStageStatus::Completed
        {
            PreparedShardRecoveryDisposition::ReleasedTombstone
        } else if self.cleanup.iter().any(|progress| progress.attempts > 0) {
            PreparedShardRecoveryDisposition::CleanupPending
        } else {
            PreparedShardRecoveryDisposition::CleanupOnly
        }
    }
}

#[derive(Debug)]
pub struct FilePreparedShardJournal {
    directory: File,
    _writer_lock: File,
    records: Mutex<BTreeMap<String, PreparedShardJournalRecord>>,
    limits: PreparedShardJournalLimits,
    recovery_roots: PreparedShardRecoveryRoots,
    reclaimable_cleanup: Mutex<BTreeMap<(String, PreparedShardCleanupStage), u64>>,
    reconciliation_active: AtomicBool,
    poisoned: AtomicBool,
    fail_after_rename: AtomicBool,
}

impl FilePreparedShardJournal {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, PreparedShardJournalError> {
        Self::open_with_limits_and_roots(
            directory,
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::production(),
        )
    }

    pub fn open_with_limits(
        directory: impl AsRef<Path>,
        limits: PreparedShardJournalLimits,
    ) -> Result<Self, PreparedShardJournalError> {
        Self::open_with_limits_and_roots(
            directory,
            limits,
            PreparedShardRecoveryRoots::production(),
        )
    }

    pub fn open_with_limits_and_roots(
        directory: impl AsRef<Path>,
        limits: PreparedShardJournalLimits,
        recovery_roots: PreparedShardRecoveryRoots,
    ) -> Result<Self, PreparedShardJournalError> {
        let directory_path = directory.as_ref();
        if !directory_path.is_absolute() {
            return Err(PreparedShardJournalError::UnsafeDirectory);
        }
        if directory_path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(PreparedShardJournalError::UnsafeDirectory);
        }
        let relative_directory = directory_path
            .strip_prefix(Path::new("/"))
            .map_err(|_| PreparedShardJournalError::UnsafeDirectory)?;
        if relative_directory.as_os_str().is_empty() {
            return Err(PreparedShardJournalError::UnsafeDirectory);
        }
        let filesystem_root = nix::fcntl::open(
            Path::new("/"),
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(PreparedShardJournalError::io)?;
        let directory_fd = openat2(
            &filesystem_root,
            relative_directory,
            OpenHow::new()
                .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
                .resolve(
                    ResolveFlag::RESOLVE_BENEATH
                        | ResolveFlag::RESOLVE_NO_MAGICLINKS
                        | ResolveFlag::RESOLVE_NO_SYMLINKS,
                ),
        )
        .map_err(|_| PreparedShardJournalError::UnsafeDirectory)?;
        let directory = File::from(directory_fd);
        let metadata = directory
            .metadata()
            .map_err(PreparedShardJournalError::io)?;
        let effective_uid = Uid::effective().as_raw();
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(PreparedShardJournalError::UnsafeDirectory);
        }

        let lock_fd = openat(
            &directory,
            LOCK_FILE_NAME,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(PreparedShardJournalError::io)?;
        let writer_lock = File::from(lock_fd);
        let lock_metadata = writer_lock
            .metadata()
            .map_err(PreparedShardJournalError::io)?;
        if !lock_metadata.is_file()
            || lock_metadata.nlink() != 1
            || lock_metadata.mode() & 0o077 != 0
        {
            return Err(PreparedShardJournalError::UnsafeJournalFile);
        }
        writer_lock
            .try_lock()
            .map_err(|_| PreparedShardJournalError::WriterAlreadyActive)?;
        let duplicate = directory
            .try_clone()
            .map_err(PreparedShardJournalError::io)?;
        let owned: OwnedFd = duplicate.into();
        let mut entries = Dir::from_fd(owned).map_err(PreparedShardJournalError::io)?;
        let mut orphan_names = Vec::new();
        let mut entry_count = 0_usize;
        for entry in entries.iter() {
            let entry = entry.map_err(PreparedShardJournalError::io)?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or(PreparedShardJournalError::LimitExceeded)?;
            if entry_count
                > limits
                    .max_records
                    .saturating_add(limits.max_temporary_files)
                    .saturating_add(3)
            {
                return Err(PreparedShardJournalError::LimitExceeded);
            }
            let name_bytes = entry.file_name().to_bytes();
            if name_bytes == b"." || name_bytes == b".." || name_bytes == LOCK_FILE_NAME.as_bytes()
            {
                continue;
            }
            let name = std::str::from_utf8(name_bytes).map_err(|_| {
                PreparedShardJournalError::Corrupt("journal entry name is not UTF-8")
            })?;
            if name.ends_with(RECORD_SUFFIX) {
                continue;
            }
            let Some(body) = name
                .strip_prefix('.')
                .and_then(|name| name.strip_suffix(".tmp"))
            else {
                return Err(PreparedShardJournalError::Corrupt(
                    "journal contains an unknown entry",
                ));
            };
            let Some((key, sequence)) = body.rsplit_once('.') else {
                return Err(PreparedShardJournalError::Corrupt(
                    "temporary record name is invalid",
                ));
            };
            if key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && !sequence.is_empty()
                && sequence.bytes().all(|byte| byte.is_ascii_digit())
            {
                if orphan_names.len() >= limits.max_temporary_files {
                    return Err(PreparedShardJournalError::LimitExceeded);
                }
                orphan_names.push(name.to_owned());
            } else {
                return Err(PreparedShardJournalError::Corrupt(
                    "temporary record name is invalid",
                ));
            }
        }
        for orphan_name in orphan_names {
            unlinkat(&directory, orphan_name.as_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(PreparedShardJournalError::io)?;
        }
        directory
            .sync_all()
            .map_err(PreparedShardJournalError::io)?;

        let records = read_all_records(&directory, limits, &recovery_roots)?;
        let mut reclaimable_cleanup = BTreeMap::new();
        for (key, record) in &records {
            for (stage, attempt) in validate_record(record)?.pending_cleanup {
                reclaimable_cleanup.insert((key.clone(), stage), attempt);
            }
        }
        Ok(Self {
            directory,
            _writer_lock: writer_lock,
            records: Mutex::new(records),
            limits,
            recovery_roots,
            reclaimable_cleanup: Mutex::new(reclaimable_cleanup),
            reconciliation_active: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            fail_after_rename: AtomicBool::new(false),
        })
    }

    pub fn reserve(
        &self,
        fence: ShardFence,
        locators: PreparedShardRecoveryLocators,
    ) -> Result<PreparedShardJournalRecord, PreparedShardJournalError> {
        validate_locator_roots(&locators, &self.recovery_roots)?;
        validate_recovery_binding(&fence, &locators)?;
        let key = record_key(&fence)?;
        let mut records = self.lock_records()?;
        if let Some(record) = records.get(&key) {
            return if record.fence == fence && record.locators == locators {
                Ok(record.clone())
            } else {
                Err(PreparedShardJournalError::ReservationConflict)
            };
        }
        let record = PreparedShardJournalRecord {
            schema_version: SCHEMA_VERSION,
            fence,
            sequence: JournalSequence(NonZeroU64::MIN),
            locators,
            events: Vec::new(),
            cleanup: [PreparedShardCleanupProgress::NOT_STARTED; 10],
            cleanup_writes: 0,
        };
        validate_record(&record)?;
        if !record_set_is_consistent(records.values().chain(std::iter::once(&record))) {
            return Err(PreparedShardJournalError::ReservationConflict);
        }
        self.ensure_capacity(&records, None, &record)?;
        self.persist_record(&key, &record)?;
        records.insert(key, record.clone());
        Ok(record)
    }

    pub fn begin_effect(
        &self,
        fence: &ShardFence,
        expected_sequence: JournalSequence,
        effect: PreparedShardEffect,
    ) -> Result<PreparedShardEffectPermit, PreparedShardJournalError> {
        let key = record_key(fence)?;
        let mut records = self.lock_records()?;
        let record = records
            .get(&key)
            .ok_or(PreparedShardJournalError::RecordNotFound)?;
        if record.fence != *fence {
            return Err(PreparedShardJournalError::FenceMismatch);
        }
        if record.sequence != expected_sequence {
            return Err(PreparedShardJournalError::StaleSequence {
                expected: record.sequence,
                received: expected_sequence,
            });
        }
        let replay = validate_record(record)?;
        if replay.pending_effect.is_some()
            || !replay.pending_cleanup.is_empty()
            || record.cleanup.iter().any(|progress| progress.attempts > 0)
        {
            return Err(PreparedShardJournalError::EffectInProgress);
        }
        validate_effect_begin(&replay.lifecycle, fence, &effect)?;
        let sequence = next_sequence(record.sequence)?;
        let mut updated = record.clone();
        if updated.events.len() >= MAX_EVENTS {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        updated.sequence = sequence;
        updated.events.push(PreparedShardJournalEvent::Intent {
            sequence,
            effect: effect.clone(),
        });
        validate_record(&updated)?;
        self.ensure_capacity(&records, Some(&key), &updated)?;
        self.persist_record(&key, &updated)?;
        records.insert(key, updated);
        Ok(PreparedShardEffectPermit {
            fence: fence.clone(),
            effect,
            sequence,
        })
    }

    pub fn complete_effect(
        &self,
        permit: &PreparedShardEffectPermit,
    ) -> Result<PreparedShardJournalRecord, PreparedShardJournalError> {
        let key = record_key(&permit.fence)?;
        let mut records = self.lock_records()?;
        let record = records
            .get(&key)
            .ok_or(PreparedShardJournalError::RecordNotFound)?;
        if record.fence != permit.fence {
            return Err(PreparedShardJournalError::FenceMismatch);
        }
        if record.sequence != permit.sequence {
            return Err(PreparedShardJournalError::StaleSequence {
                expected: record.sequence,
                received: permit.sequence,
            });
        }
        let replay = validate_record(record)?;
        if replay.pending_effect.as_ref() != Some(&permit.effect) {
            return Err(PreparedShardJournalError::EffectMismatch);
        }
        let sequence = next_sequence(record.sequence)?;
        let mut updated = record.clone();
        if updated.events.len() >= MAX_EVENTS {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        updated.sequence = sequence;
        updated.events.push(PreparedShardJournalEvent::Completed {
            sequence,
            effect: permit.effect.clone(),
        });
        validate_record(&updated)?;
        self.ensure_capacity(&records, Some(&key), &updated)?;
        self.persist_record(&key, &updated)?;
        records.insert(key, updated.clone());
        Ok(updated)
    }

    pub fn begin_cleanup_stage(
        &self,
        fence: &ShardFence,
        expected_sequence: JournalSequence,
        stage: PreparedShardCleanupStage,
    ) -> Result<PreparedShardCleanupPermit, PreparedShardJournalError> {
        let key = record_key(fence)?;
        let mut records = self.lock_records()?;
        let record = records
            .get(&key)
            .ok_or(PreparedShardJournalError::RecordNotFound)?;
        if record.fence != *fence {
            return Err(PreparedShardJournalError::FenceMismatch);
        }
        if record.sequence != expected_sequence {
            return Err(PreparedShardJournalError::StaleSequence {
                expected: record.sequence,
                received: expected_sequence,
            });
        }
        if record.recovery_disposition() == PreparedShardRecoveryDisposition::ReleasedTombstone {
            return Err(PreparedShardJournalError::CleanupAlreadyCompleted);
        }
        let replay = validate_record(record)?;
        let mut reclaimable_cleanup = None;
        if let Some((_, pending_attempt)) = replay
            .pending_cleanup
            .iter()
            .find(|(pending_stage, _)| *pending_stage == stage)
        {
            let pending_attempt = *pending_attempt;
            let reclaimable_key = (key.clone(), stage);
            let reclaimable = self
                .reclaimable_cleanup
                .lock()
                .map_err(|_| PreparedShardJournalError::LockPoisoned)?;
            if reclaimable.get(&reclaimable_key) != Some(&pending_attempt) {
                return Err(PreparedShardJournalError::CleanupStageInProgress);
            }
            reclaimable_cleanup = Some((reclaimable, reclaimable_key));
        } else if replay
            .pending_cleanup
            .iter()
            .any(|(pending_stage, _)| !cleanup_stages_can_overlap(*pending_stage, stage))
        {
            return Err(PreparedShardJournalError::CleanupStageInProgress);
        }
        if replay.pending_effect.is_some() && stage != PreparedShardCleanupStage::RevokeEgress {
            return Err(PreparedShardJournalError::CleanupStageOutOfOrder);
        }
        if replay.cleanup[stage.index()].status == PreparedShardCleanupStageStatus::Completed {
            return Err(PreparedShardJournalError::CleanupStageAlreadyCompleted);
        }
        if !cleanup_stage_is_eligible(&replay.cleanup, stage) {
            return Err(PreparedShardJournalError::CleanupStageOutOfOrder);
        }
        let attempt = replay.cleanup[stage.index()]
            .attempts
            .checked_add(1)
            .ok_or(PreparedShardJournalError::CleanupAttemptExhausted)?;
        let sequence = next_sequence(record.sequence)?;
        let mut updated = record.clone();
        updated.sequence = sequence;
        updated.cleanup_writes = updated
            .cleanup_writes
            .checked_add(1)
            .ok_or(PreparedShardJournalError::SequenceExhausted)?;
        updated.cleanup[stage.index()] = PreparedShardCleanupProgress {
            status: PreparedShardCleanupStageStatus::InProgress,
            attempts: attempt,
            last_failure: None,
        };
        validate_record(&updated)?;
        self.ensure_capacity(&records, Some(&key), &updated)?;
        self.persist_record(&key, &updated)?;
        if let Some((mut reclaimable, reclaimable_key)) = reclaimable_cleanup {
            reclaimable.remove(&reclaimable_key);
        }
        records.insert(key, updated.clone());
        Ok(PreparedShardCleanupPermit {
            fence: fence.clone(),
            stage,
            attempt,
            sequence,
            record: updated,
        })
    }

    pub fn complete_cleanup_stage(
        &self,
        permit: &PreparedShardCleanupPermit,
    ) -> Result<PreparedShardJournalRecord, PreparedShardJournalError> {
        self.finish_cleanup_stage(permit, None)
    }

    pub fn record_cleanup_failure(
        &self,
        permit: &PreparedShardCleanupPermit,
        failure: PreparedShardCleanupFailure,
    ) -> Result<PreparedShardJournalRecord, PreparedShardJournalError> {
        self.finish_cleanup_stage(permit, Some(failure))
    }

    pub(crate) fn abandon_cleanup_stage(
        &self,
        permit: &PreparedShardCleanupPermit,
    ) -> Result<(), PreparedShardJournalError> {
        let key = record_key(&permit.fence)?;
        let records = self.lock_records()?;
        let record = records
            .get(&key)
            .ok_or(PreparedShardJournalError::RecordNotFound)?;
        if record.fence != permit.fence {
            return Err(PreparedShardJournalError::FenceMismatch);
        }
        let replay = validate_record(record)?;
        if !replay
            .pending_cleanup
            .contains(&(permit.stage, permit.attempt))
        {
            return Err(PreparedShardJournalError::CleanupPermitMismatch);
        }
        self.reclaimable_cleanup
            .lock()
            .map_err(|_| PreparedShardJournalError::LockPoisoned)?
            .insert((key, permit.stage), permit.attempt);
        Ok(())
    }

    fn finish_cleanup_stage(
        &self,
        permit: &PreparedShardCleanupPermit,
        failure: Option<PreparedShardCleanupFailure>,
    ) -> Result<PreparedShardJournalRecord, PreparedShardJournalError> {
        let key = record_key(&permit.fence)?;
        let mut records = self.lock_records()?;
        let record = records
            .get(&key)
            .ok_or(PreparedShardJournalError::RecordNotFound)?;
        if record.fence != permit.fence {
            return Err(PreparedShardJournalError::FenceMismatch);
        }
        let replay = validate_record(record)?;
        if !replay
            .pending_cleanup
            .contains(&(permit.stage, permit.attempt))
        {
            return Err(PreparedShardJournalError::CleanupPermitMismatch);
        }
        let sequence = next_sequence(record.sequence)?;
        let mut updated = record.clone();
        updated.sequence = sequence;
        updated.cleanup_writes = updated
            .cleanup_writes
            .checked_add(1)
            .ok_or(PreparedShardJournalError::SequenceExhausted)?;
        if let Some(failure) = failure {
            updated.cleanup[permit.stage.index()] = PreparedShardCleanupProgress {
                status: PreparedShardCleanupStageStatus::Failed,
                attempts: permit.attempt,
                last_failure: Some(failure),
            };
        } else {
            updated.cleanup[permit.stage.index()] = PreparedShardCleanupProgress {
                status: PreparedShardCleanupStageStatus::Completed,
                attempts: permit.attempt,
                last_failure: None,
            };
        }
        validate_record(&updated)?;
        self.ensure_capacity(&records, Some(&key), &updated)?;
        self.persist_record(&key, &updated)?;
        records.insert(key, updated.clone());
        Ok(updated)
    }

    pub fn records(&self) -> Result<Vec<PreparedShardJournalRecord>, PreparedShardJournalError> {
        Ok(self.lock_records()?.values().cloned().collect())
    }

    fn lock_records(
        &self,
    ) -> Result<
        MutexGuard<'_, BTreeMap<String, PreparedShardJournalRecord>>,
        PreparedShardJournalError,
    > {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(PreparedShardJournalError::StorageUncertain);
        }
        let records = self
            .records
            .lock()
            .map_err(|_| PreparedShardJournalError::LockPoisoned)?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(PreparedShardJournalError::StorageUncertain);
        }
        Ok(records)
    }

    #[cfg(test)]
    fn inject_failure_after_next_rename(&self) {
        self.fail_after_rename.store(true, Ordering::Release);
    }

    fn persist_record(
        &self,
        key: &str,
        record: &PreparedShardJournalRecord,
    ) -> Result<(), PreparedShardJournalError> {
        let result = write_record(
            &self.directory,
            key,
            record,
            self.limits.max_record_bytes,
            &self.fail_after_rename,
        );
        if matches!(result, Err(PreparedShardJournalError::StorageUncertain)) {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    fn ensure_capacity(
        &self,
        records: &BTreeMap<String, PreparedShardJournalRecord>,
        replaced_key: Option<&str>,
        candidate: &PreparedShardJournalRecord,
    ) -> Result<(), PreparedShardJournalError> {
        if replaced_key.is_none() && records.len() >= self.limits.max_records {
            return Err(PreparedShardJournalError::LimitExceeded);
        }
        let candidate_bytes = encoded_record_frame_length(candidate)?;
        if candidate_bytes > self.limits.max_record_bytes + FILE_MAGIC.len() + 4 + CHECKSUM_BYTES {
            return Err(PreparedShardJournalError::LimitExceeded);
        }
        let mut total_bytes = candidate_bytes;
        for (key, record) in records {
            if replaced_key == Some(key.as_str()) {
                continue;
            }
            total_bytes = total_bytes
                .checked_add(encoded_record_frame_length(record)?)
                .ok_or(PreparedShardJournalError::LimitExceeded)?;
            if total_bytes > self.limits.max_total_bytes {
                return Err(PreparedShardJournalError::LimitExceeded);
            }
        }
        if total_bytes > self.limits.max_total_bytes {
            return Err(PreparedShardJournalError::LimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error)]
#[error("prepared-shard recovery backend rejected a cleanup stage")]
pub struct PreparedShardRecoveryError;

impl PreparedShardRecoveryError {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for PreparedShardRecoveryError {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait PreparedShardRecoveryBackend: Send + Sync + 'static {
    async fn run_stage(
        &self,
        record: &PreparedShardJournalRecord,
        stage: PreparedShardCleanupStage,
    ) -> Result<(), PreparedShardRecoveryError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartupReconciliationReport {
    released_tombstones: usize,
    cleanup_pending: usize,
}

impl StartupReconciliationReport {
    #[must_use]
    pub const fn released_tombstones(self) -> usize {
        self.released_tombstones
    }

    #[must_use]
    pub const fn cleanup_pending(self) -> usize {
        self.cleanup_pending
    }
}

#[derive(Debug)]
pub struct StartupReconciliationHandle {
    outcome: oneshot::Receiver<Result<StartupReconciliationReport, PreparedShardJournalError>>,
}

impl StartupReconciliationHandle {
    pub async fn wait(self) -> Result<StartupReconciliationReport, PreparedShardJournalError> {
        self.outcome
            .await
            .map_err(|_| PreparedShardJournalError::ReconcilerStopped)?
    }
}

struct ActiveReconciliation<'a> {
    active: &'a AtomicBool,
}

impl Drop for ActiveReconciliation<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
pub struct StartupPreparedShardReconciler<B> {
    journal: Arc<FilePreparedShardJournal>,
    backend: Arc<B>,
    stage_timeout: Duration,
    max_concurrency: usize,
}

impl<B> StartupPreparedShardReconciler<B>
where
    B: PreparedShardRecoveryBackend,
{
    pub fn new(
        journal: Arc<FilePreparedShardJournal>,
        backend: Arc<B>,
        stage_timeout: Duration,
    ) -> Result<Self, PreparedShardJournalError> {
        if stage_timeout.is_zero() {
            return Err(PreparedShardJournalError::InvalidRecoveryTimeout);
        }
        Ok(Self {
            journal,
            backend,
            stage_timeout,
            max_concurrency: DEFAULT_RECOVERY_CONCURRENCY,
        })
    }

    pub fn with_max_concurrency(
        mut self,
        max_concurrency: usize,
    ) -> Result<Self, PreparedShardJournalError> {
        if max_concurrency == 0 {
            return Err(PreparedShardJournalError::InvalidRecoveryConcurrency);
        }
        self.max_concurrency = max_concurrency;
        Ok(self)
    }

    #[must_use]
    pub fn start_detached(self) -> StartupReconciliationHandle {
        let (sender, outcome) = oneshot::channel();
        tokio::spawn(async move {
            let result = self.reconcile().await;
            let _ = sender.send(result);
        });
        StartupReconciliationHandle { outcome }
    }

    async fn reconcile(&self) -> Result<StartupReconciliationReport, PreparedShardJournalError> {
        self.journal
            .reconciliation_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PreparedShardJournalError::ReconcilerAlreadyActive)?;
        let _active_reconciliation = ActiveReconciliation {
            active: &self.journal.reconciliation_active,
        };
        let journal = Arc::clone(&self.journal);
        let records = tokio::task::spawn_blocking(move || journal.records())
            .await
            .map_err(|_| PreparedShardJournalError::ReconcilerStopped)??;
        let concurrency = Arc::new(Semaphore::new(self.max_concurrency));
        let mut tasks = JoinSet::new();
        for mut record in records {
            let journal = Arc::clone(&self.journal);
            let backend = Arc::clone(&self.backend);
            let concurrency = Arc::clone(&concurrency);
            let stage_timeout = self.stage_timeout;
            tasks.spawn(async move {
                let _slot = concurrency
                    .acquire_owned()
                    .await
                    .map_err(|_| PreparedShardJournalError::ReconcilerStopped)?;
                if record.recovery_disposition()
                    == PreparedShardRecoveryDisposition::ReleasedTombstone
                {
                    return Ok(PreparedShardRecoveryDisposition::ReleasedTombstone);
                }
                for stage in PreparedShardCleanupStage::ALL {
                    let replay = validate_record(&record)?;
                    if replay.cleanup[stage.index()].status
                        == PreparedShardCleanupStageStatus::Completed
                        || !cleanup_stage_is_eligible(&replay.cleanup, stage)
                    {
                        continue;
                    }
                    if replay.pending_effect.is_some()
                        && stage != PreparedShardCleanupStage::RevokeEgress
                    {
                        continue;
                    }
                    if replay.pending_cleanup.iter().any(|(pending, _)| {
                        *pending != stage && !cleanup_stages_can_overlap(*pending, stage)
                    }) {
                        continue;
                    }
                    let journal_operation = Arc::clone(&journal);
                    let fence = record.fence().clone();
                    let sequence = record.sequence();
                    let permit = tokio::task::spawn_blocking(move || {
                        journal_operation.begin_cleanup_stage(&fence, sequence, stage)
                    })
                    .await
                    .map_err(|_| PreparedShardJournalError::ReconcilerStopped)??;
                    let backend = Arc::clone(&backend);
                    let backend_record = permit.record().clone();
                    let mut stage_task =
                        tokio::spawn(
                            async move { backend.run_stage(&backend_record, stage).await },
                        );
                    let stage_result = timeout(stage_timeout, &mut stage_task).await;
                    let journal_operation = Arc::clone(&journal);
                    record = match stage_result {
                        Ok(Ok(Ok(()))) => tokio::task::spawn_blocking(move || {
                            journal_operation.complete_cleanup_stage(&permit)
                        })
                        .await
                        .map_err(|_| PreparedShardJournalError::ReconcilerStopped)??,
                        Ok(Ok(Err(_))) | Ok(Err(_)) => tokio::task::spawn_blocking(move || {
                            journal_operation.record_cleanup_failure(
                                &permit,
                                PreparedShardCleanupFailure::Backend,
                            )
                        })
                        .await
                        .map_err(|_| PreparedShardJournalError::ReconcilerStopped)??,
                        Err(_) => {
                            stage_task.abort();
                            let _ = stage_task.await;
                            tokio::task::spawn_blocking(move || {
                                journal_operation.record_cleanup_failure(
                                    &permit,
                                    PreparedShardCleanupFailure::TimedOut,
                                )
                            })
                            .await
                            .map_err(|_| PreparedShardJournalError::ReconcilerStopped)??
                        }
                    };
                }
                Ok(record.recovery_disposition())
            });
        }
        let mut report = StartupReconciliationReport::default();
        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(PreparedShardRecoveryDisposition::ReleasedTombstone)) => {
                    report.released_tombstones += 1;
                }
                Ok(Ok(
                    PreparedShardRecoveryDisposition::CleanupOnly
                    | PreparedShardRecoveryDisposition::CleanupPending,
                )) => {
                    report.cleanup_pending += 1;
                }
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(_) => {
                    first_error.get_or_insert(PreparedShardJournalError::ReconcilerStopped);
                }
            }
        }
        first_error.map_or(Ok(report), Err)
    }
}

#[derive(Debug, Error)]
pub enum PreparedShardJournalError {
    #[error("prepared-shard recovery locators are invalid")]
    InvalidLocators,
    #[error("prepared-shard journal directory is unsafe")]
    UnsafeDirectory,
    #[error("prepared-shard journal file is unsafe")]
    UnsafeJournalFile,
    #[error("prepared-shard journal already has an active writer")]
    WriterAlreadyActive,
    #[error("prepared-shard fence reservation conflicts with durable state")]
    ReservationConflict,
    #[error("prepared-shard journal record was not found")]
    RecordNotFound,
    #[error("prepared-shard journal fence does not match")]
    FenceMismatch,
    #[error(
        "prepared-shard journal sequence is stale: expected {expected:?}, received {received:?}"
    )]
    StaleSequence {
        expected: JournalSequence,
        received: JournalSequence,
    },
    #[error("prepared-shard journal already has an effect in progress")]
    EffectInProgress,
    #[error("prepared-shard journal effect permit does not match the pending effect")]
    EffectMismatch,
    #[error("prepared-shard journal sequence is exhausted")]
    SequenceExhausted,
    #[error("prepared-shard journal history is invalid")]
    InvalidHistory,
    #[error("prepared-shard cleanup is already complete")]
    CleanupAlreadyCompleted,
    #[error("a different prepared-shard cleanup stage is in progress")]
    CleanupStageInProgress,
    #[error("prepared-shard cleanup stage is out of order")]
    CleanupStageOutOfOrder,
    #[error("prepared-shard cleanup stage is already complete")]
    CleanupStageAlreadyCompleted,
    #[error("prepared-shard cleanup attempt counter is exhausted")]
    CleanupAttemptExhausted,
    #[error("prepared-shard cleanup permit does not match durable state")]
    CleanupPermitMismatch,
    #[error("prepared-shard recovery task stopped before reporting an outcome")]
    ReconcilerStopped,
    #[error("prepared-shard journal already has an active reconciler")]
    ReconcilerAlreadyActive,
    #[error("prepared-shard recovery timeout must be positive")]
    InvalidRecoveryTimeout,
    #[error("prepared-shard recovery concurrency must be positive")]
    InvalidRecoveryConcurrency,
    #[error("prepared-shard journal limits are invalid")]
    InvalidLimits,
    #[error("prepared-shard recovery roots are invalid")]
    InvalidRecoveryRoots,
    #[error("prepared-shard recovery locator escapes its configured root")]
    LocatorOutsideRecoveryRoots,
    #[error("prepared-shard journal resource limit was exceeded")]
    LimitExceeded,
    #[error("prepared-shard journal durability is uncertain; reopen before continuing")]
    StorageUncertain,
    #[error("prepared-shard journal is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("prepared-shard journal lock is poisoned")]
    LockPoisoned,
    #[error("prepared-shard journal I/O failed: {0}")]
    Io(String),
}

impl PreparedShardJournalError {
    fn io(error: impl std::fmt::Display) -> Self {
        Self::Io(error.to_string())
    }
}

fn read_all_records(
    directory: &File,
    limits: PreparedShardJournalLimits,
    recovery_roots: &PreparedShardRecoveryRoots,
) -> Result<BTreeMap<String, PreparedShardJournalRecord>, PreparedShardJournalError> {
    let duplicate = directory
        .try_clone()
        .map_err(PreparedShardJournalError::io)?;
    let owned: OwnedFd = duplicate.into();
    let mut entries = Dir::from_fd(owned).map_err(PreparedShardJournalError::io)?;
    let mut records = BTreeMap::new();
    let mut total_bytes = 0_usize;
    for entry in entries.iter() {
        let entry = entry.map_err(PreparedShardJournalError::io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || name == LOCK_FILE_NAME.as_bytes() {
            continue;
        }
        if !name.ends_with(RECORD_SUFFIX.as_bytes()) {
            continue;
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| PreparedShardJournalError::Corrupt("record name is not UTF-8"))?;
        let key = name
            .strip_suffix(RECORD_SUFFIX)
            .ok_or(PreparedShardJournalError::Corrupt(
                "record suffix is invalid",
            ))?;
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PreparedShardJournalError::Corrupt("record key is invalid"));
        }
        if records.len() >= limits.max_records {
            return Err(PreparedShardJournalError::LimitExceeded);
        }
        let (record, frame_bytes) = read_record(directory, name, limits.max_record_bytes)?;
        validate_locator_roots(record.locators(), recovery_roots)?;
        total_bytes = total_bytes
            .checked_add(frame_bytes)
            .ok_or(PreparedShardJournalError::LimitExceeded)?;
        if total_bytes > limits.max_total_bytes {
            return Err(PreparedShardJournalError::LimitExceeded);
        }
        if record.schema_version != SCHEMA_VERSION {
            return Err(PreparedShardJournalError::Corrupt(
                "record schema is unsupported",
            ));
        }
        if record_key(&record.fence)? != key {
            return Err(PreparedShardJournalError::Corrupt(
                "record fence does not match its key",
            ));
        }
        validate_record(&record)?;
        if records.insert(key.to_owned(), record).is_some() {
            return Err(PreparedShardJournalError::Corrupt(
                "record key is duplicated",
            ));
        }
    }
    if !record_set_is_consistent(records.values()) {
        return Err(PreparedShardJournalError::Corrupt(
            "record set violates durable reservation invariants",
        ));
    }
    Ok(records)
}

fn record_set_is_consistent<'a>(
    records: impl IntoIterator<Item = &'a PreparedShardJournalRecord>,
) -> bool {
    let mut records = records.into_iter().collect::<Vec<_>>();
    let mut backend_tokens = BTreeSet::new();
    let mut cgroup_paths = BTreeSet::new();
    let mut runtime_paths = BTreeSet::new();
    let mut live_shards = BTreeSet::new();
    for record in &records {
        if !backend_tokens.insert(record.locators.backend_token.as_str())
            || !cgroup_paths.insert(record.locators.cgroup_path.as_path())
            || !runtime_paths.insert(record.locators.runtime_path.as_path())
        {
            return false;
        }
        if record.recovery_disposition() != PreparedShardRecoveryDisposition::ReleasedTombstone
            && !live_shards.insert(record.fence.shard_id())
        {
            return false;
        }
    }
    records.sort_unstable_by(|left, right| left.fence.cmp(&right.fence));
    records.windows(2).all(|pair| {
        let lower = pair[0];
        let higher = pair[1];
        lower.fence.owner() != higher.fence.owner()
            || lower.fence.shard_id() != higher.fence.shard_id()
            || (lower.fence.launch_generation() < higher.fence.launch_generation()
                && lower.recovery_disposition()
                    == PreparedShardRecoveryDisposition::ReleasedTombstone)
    })
}

fn validate_locator_roots(
    locators: &PreparedShardRecoveryLocators,
    roots: &PreparedShardRecoveryRoots,
) -> Result<(), PreparedShardJournalError> {
    let paths = [
        (locators.cgroup_path(), roots.cgroup_root()),
        (locators.runtime_path(), roots.runtime_root()),
    ];
    if paths.into_iter().any(|(path, root)| {
        path.strip_prefix(root).map_or(true, |relative| {
            relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
        })
    }) {
        return Err(PreparedShardJournalError::LocatorOutsideRecoveryRoots);
    }
    Ok(())
}

fn read_record(
    directory: &File,
    name: &str,
    max_record_bytes: usize,
) -> Result<(PreparedShardJournalRecord, usize), PreparedShardJournalError> {
    let fd = openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(PreparedShardJournalError::io)?;
    let metadata = fstat(&fd).map_err(PreparedShardJournalError::io)?;
    if metadata.st_nlink != 1
        || metadata.st_mode & nix::libc::S_IFMT != nix::libc::S_IFREG
        || metadata.st_mode & 0o077 != 0
    {
        return Err(PreparedShardJournalError::UnsafeJournalFile);
    }
    let mut file = File::from(fd);
    let file_length = usize::try_from(metadata.st_size)
        .map_err(|_| PreparedShardJournalError::Corrupt("record length is invalid"))?;
    let maximum_frame = FILE_MAGIC.len() + 4 + max_record_bytes + CHECKSUM_BYTES;
    if file_length > maximum_frame {
        return Err(PreparedShardJournalError::LimitExceeded);
    }
    let bytes = read_record_bytes(&mut file, file_length, maximum_frame)?;
    decode_record(&bytes).map(|record| (record, bytes.len()))
}

fn read_record_bytes(
    reader: &mut impl Read,
    expected_length: usize,
    maximum_frame: usize,
) -> Result<Vec<u8>, PreparedShardJournalError> {
    if expected_length > maximum_frame {
        return Err(PreparedShardJournalError::LimitExceeded);
    }
    let read_limit = maximum_frame
        .checked_add(1)
        .ok_or(PreparedShardJournalError::LimitExceeded)?;
    let read_limit =
        u64::try_from(read_limit).map_err(|_| PreparedShardJournalError::LimitExceeded)?;
    let mut bytes = Vec::with_capacity(expected_length);
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(PreparedShardJournalError::io)?;
    if bytes.len() > maximum_frame {
        return Err(PreparedShardJournalError::LimitExceeded);
    }
    if bytes.len() != expected_length {
        return Err(PreparedShardJournalError::Corrupt(
            "record changed while it was read",
        ));
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<PreparedShardJournalRecord, PreparedShardJournalError> {
    let minimum_length = FILE_MAGIC.len() + 4 + CHECKSUM_BYTES;
    if bytes.len() < minimum_length || &bytes[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(PreparedShardJournalError::Corrupt(
            "record header is truncated or invalid",
        ));
    }
    let length_offset = FILE_MAGIC.len();
    let payload_length = u32::from_be_bytes(
        bytes[length_offset..length_offset + 4]
            .try_into()
            .map_err(|_| PreparedShardJournalError::Corrupt("record length is truncated"))?,
    ) as usize;
    if payload_length == 0 || payload_length > MAX_RECORD_BYTES {
        return Err(PreparedShardJournalError::Corrupt(
            "record payload length is invalid",
        ));
    }
    let payload_start = length_offset + 4;
    let payload_end =
        payload_start
            .checked_add(payload_length)
            .ok_or(PreparedShardJournalError::Corrupt(
                "record payload length overflows",
            ))?;
    if payload_end
        .checked_add(CHECKSUM_BYTES)
        .is_none_or(|expected| expected != bytes.len())
    {
        return Err(PreparedShardJournalError::Corrupt(
            "record frame length is inconsistent",
        ));
    }
    let payload = &bytes[payload_start..payload_end];
    let expected_checksum = Sha256::digest(payload);
    if expected_checksum.as_slice() != &bytes[payload_end..] {
        return Err(PreparedShardJournalError::Corrupt(
            "record checksum does not match",
        ));
    }
    let stored: StoredPreparedShardJournalRecord = serde_json::from_slice(payload)
        .map_err(|_| PreparedShardJournalError::Corrupt("record payload is invalid"))?;
    stored
        .try_into()
        .map_err(|_| PreparedShardJournalError::Corrupt("record payload is invalid"))
}

fn encoded_record_frame_length(
    record: &PreparedShardJournalRecord,
) -> Result<usize, PreparedShardJournalError> {
    let payload = serde_json::to_vec(&StoredPreparedShardJournalRecord::from(record))
        .map_err(|_| PreparedShardJournalError::Corrupt("record cannot be encoded"))?;
    FILE_MAGIC
        .len()
        .checked_add(4)
        .and_then(|length| length.checked_add(payload.len()))
        .and_then(|length| length.checked_add(CHECKSUM_BYTES))
        .ok_or(PreparedShardJournalError::LimitExceeded)
}

fn write_record(
    directory: &File,
    key: &str,
    record: &PreparedShardJournalRecord,
    max_record_bytes: usize,
    fail_after_rename: &AtomicBool,
) -> Result<(), PreparedShardJournalError> {
    let payload = serde_json::to_vec(&StoredPreparedShardJournalRecord::from(record))
        .map_err(|_| PreparedShardJournalError::Corrupt("record cannot be encoded"))?;
    if payload.is_empty() || payload.len() > max_record_bytes {
        return Err(PreparedShardJournalError::LimitExceeded);
    }
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| PreparedShardJournalError::Corrupt("record length cannot be encoded"))?;
    let checksum = Sha256::digest(&payload);
    let temporary_number = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".{key}.{temporary_number}.tmp");
    let record_name = format!("{key}{RECORD_SUFFIX}");
    let temporary_fd = openat(
        directory,
        temporary_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(PreparedShardJournalError::io)?;
    let mut temporary = File::from(temporary_fd);
    let write_result = (|| -> std::io::Result<()> {
        temporary.write_all(FILE_MAGIC)?;
        temporary.write_all(&payload_length.to_be_bytes())?;
        temporary.write_all(&payload)?;
        temporary.write_all(&checksum)?;
        temporary.flush()?;
        temporary.sync_all()
    })();
    if let Err(error) = write_result {
        let _ = unlinkat(
            directory,
            temporary_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
        return Err(PreparedShardJournalError::io(error));
    }
    if renameat(
        directory,
        temporary_name.as_str(),
        directory,
        record_name.as_str(),
    )
    .is_err()
    {
        let _ = unlinkat(
            directory,
            temporary_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
        return Err(PreparedShardJournalError::StorageUncertain);
    }
    if fail_after_rename.swap(false, Ordering::AcqRel) {
        return Err(PreparedShardJournalError::StorageUncertain);
    }
    directory
        .sync_all()
        .map_err(|_| PreparedShardJournalError::StorageUncertain)
}

fn record_key(fence: &ShardFence) -> Result<String, PreparedShardJournalError> {
    let worker = fence.owner().worker_id().as_str().as_bytes();
    let worker_length = u16::try_from(worker.len())
        .map_err(|_| PreparedShardJournalError::Corrupt("worker identity is too long"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"browserd-prepared-shard-journal-key-v1");
    hasher.update(worker_length.to_be_bytes());
    hasher.update(worker);
    hasher.update(fence.owner().worker_epoch().get().to_be_bytes());
    hasher.update(fence.shard_id().as_bytes());
    hasher.update(fence.launch_generation().get().to_be_bytes());
    let digest = hasher.finalize();
    let mut key = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(key)
}

fn next_sequence(current: JournalSequence) -> Result<JournalSequence, PreparedShardJournalError> {
    current
        .get()
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .map(JournalSequence)
        .ok_or(PreparedShardJournalError::SequenceExhausted)
}

struct PreparedShardRecordReplay {
    lifecycle: PreparedShardLifecycle,
    pending_effect: Option<PreparedShardEffect>,
    pending_cleanup: Vec<(PreparedShardCleanupStage, u64)>,
    cleanup: [PreparedShardCleanupProgress; 10],
}

fn validate_record(
    record: &PreparedShardJournalRecord,
) -> Result<PreparedShardRecordReplay, PreparedShardJournalError> {
    if record.schema_version != SCHEMA_VERSION || record.events.len() > MAX_EVENTS {
        return Err(PreparedShardJournalError::InvalidHistory);
    }
    validate_recovery_binding(&record.fence, &record.locators)?;
    let mut lifecycle = PreparedShardLifecycle::new(record.fence.clone());
    let mut pending_effect: Option<PreparedShardEffect> = None;
    let mut pending_cleanup = Vec::new();
    let mut expected_sequence = JournalSequence(NonZeroU64::MIN);
    for event in &record.events {
        expected_sequence = next_sequence(expected_sequence)?;
        let event_sequence = match event {
            PreparedShardJournalEvent::Intent { sequence, .. }
            | PreparedShardJournalEvent::Completed { sequence, .. } => *sequence,
        };
        if event_sequence != expected_sequence {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        match event {
            PreparedShardJournalEvent::Intent { effect, .. } => {
                if pending_effect.is_some() {
                    return Err(PreparedShardJournalError::InvalidHistory);
                }
                validate_effect_begin(&lifecycle, &record.fence, effect)?;
                apply_effect_begin(&mut lifecycle, &record.fence, effect)?;
                pending_effect = Some(effect.clone());
            }
            PreparedShardJournalEvent::Completed { effect, .. } => {
                if pending_effect.as_ref() != Some(effect) {
                    return Err(PreparedShardJournalError::InvalidHistory);
                }
                apply_effect_completion(&mut lifecycle, &record.fence, effect)?;
                pending_effect = None;
            }
        }
    }
    let mut minimum_cleanup_writes = 0_u64;
    let mut maximum_cleanup_writes = 0_u64;
    for stage in PreparedShardCleanupStage::ALL {
        let progress = record.cleanup[stage.index()];
        let valid_shape = match progress.status {
            PreparedShardCleanupStageStatus::NotStarted => {
                progress.attempts == 0 && progress.last_failure.is_none()
            }
            PreparedShardCleanupStageStatus::InProgress => {
                progress.attempts > 0 && progress.last_failure.is_none()
            }
            PreparedShardCleanupStageStatus::Failed => {
                progress.attempts > 0 && progress.last_failure.is_some()
            }
            PreparedShardCleanupStageStatus::Completed => {
                progress.attempts > 0 && progress.last_failure.is_none()
            }
        };
        if !valid_shape
            || (progress.attempts > 0 && !cleanup_stage_is_eligible(&record.cleanup, stage))
        {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        if progress.attempts > 0 {
            if stage == PreparedShardCleanupStage::RevokeEgress {
                pending_effect = None;
            } else if pending_effect.is_some() {
                return Err(PreparedShardJournalError::InvalidHistory);
            }
            apply_cleanup_begin(&mut lifecycle, &record.fence, stage)?;
            if progress.status == PreparedShardCleanupStageStatus::Completed {
                apply_cleanup_completion(&mut lifecycle, &record.fence, stage)?;
            }
            if progress.status == PreparedShardCleanupStageStatus::InProgress {
                if pending_cleanup
                    .iter()
                    .any(|(pending, _)| !cleanup_stages_can_overlap(*pending, stage))
                {
                    return Err(PreparedShardJournalError::InvalidHistory);
                }
                pending_cleanup.push((stage, progress.attempts));
            }
        }
        let attempts = progress.attempts;
        let finish_write = u64::from(matches!(
            progress.status,
            PreparedShardCleanupStageStatus::Failed | PreparedShardCleanupStageStatus::Completed
        ));
        minimum_cleanup_writes = minimum_cleanup_writes
            .checked_add(attempts)
            .and_then(|writes| writes.checked_add(finish_write))
            .ok_or(PreparedShardJournalError::InvalidHistory)?;
        maximum_cleanup_writes = maximum_cleanup_writes
            .checked_add(
                attempts
                    .checked_mul(2)
                    .ok_or(PreparedShardJournalError::InvalidHistory)?,
            )
            .ok_or(PreparedShardJournalError::InvalidHistory)?;
    }
    if !pending_cleanup.is_empty() {
        maximum_cleanup_writes = maximum_cleanup_writes
            .checked_sub(
                u64::try_from(pending_cleanup.len())
                    .map_err(|_| PreparedShardJournalError::InvalidHistory)?,
            )
            .ok_or(PreparedShardJournalError::InvalidHistory)?;
    }
    if record.cleanup_writes < minimum_cleanup_writes
        || record.cleanup_writes > maximum_cleanup_writes
    {
        return Err(PreparedShardJournalError::InvalidHistory);
    }
    expected_sequence = expected_sequence
        .get()
        .checked_add(record.cleanup_writes)
        .and_then(NonZeroU64::new)
        .map(JournalSequence)
        .ok_or(PreparedShardJournalError::InvalidHistory)?;
    if record.sequence != expected_sequence {
        return Err(PreparedShardJournalError::InvalidHistory);
    }
    Ok(PreparedShardRecordReplay {
        lifecycle,
        pending_effect,
        pending_cleanup,
        cleanup: record.cleanup,
    })
}

fn validate_recovery_binding(
    fence: &ShardFence,
    locators: &PreparedShardRecoveryLocators,
) -> Result<(), PreparedShardJournalError> {
    match (locators.egress_daemon_epoch, locators.egress_fence.as_ref()) {
        (None, None) => Ok(()),
        (Some(epoch), Some(egress_fence)) if epoch != 0 && egress_fence.shard() == fence => Ok(()),
        _ => Err(PreparedShardJournalError::InvalidLocators),
    }
}

fn cleanup_stage_is_eligible(
    cleanup: &[PreparedShardCleanupProgress; 10],
    stage: PreparedShardCleanupStage,
) -> bool {
    let attempted = |candidate: PreparedShardCleanupStage| cleanup[candidate.index()].attempts > 0;
    let completed = |candidate: PreparedShardCleanupStage| {
        cleanup[candidate.index()].status == PreparedShardCleanupStageStatus::Completed
    };
    match stage {
        PreparedShardCleanupStage::RevokeEgress => true,
        PreparedShardCleanupStage::AbortGate => attempted(PreparedShardCleanupStage::RevokeEgress),
        PreparedShardCleanupStage::KillCgroup => attempted(PreparedShardCleanupStage::AbortGate),
        PreparedShardCleanupStage::ConfirmProcessDeath => {
            attempted(PreparedShardCleanupStage::KillCgroup)
        }
        PreparedShardCleanupStage::ConfirmEgressDrained => {
            completed(PreparedShardCleanupStage::RevokeEgress)
        }
        PreparedShardCleanupStage::CloseCapabilities => {
            completed(PreparedShardCleanupStage::ConfirmProcessDeath)
                && completed(PreparedShardCleanupStage::ConfirmEgressDrained)
        }
        PreparedShardCleanupStage::CleanupNetworkNamespace => {
            completed(PreparedShardCleanupStage::ConfirmProcessDeath)
                && completed(PreparedShardCleanupStage::ConfirmEgressDrained)
                && completed(PreparedShardCleanupStage::CloseCapabilities)
        }
        PreparedShardCleanupStage::CleanupRuntimeFilesystem => {
            completed(PreparedShardCleanupStage::CleanupNetworkNamespace)
        }
        PreparedShardCleanupStage::RemoveCgroup => {
            completed(PreparedShardCleanupStage::CleanupRuntimeFilesystem)
        }
        PreparedShardCleanupStage::ReleaseEgressGeneration => PreparedShardCleanupStage::ALL
            .into_iter()
            .take(PreparedShardCleanupStage::ReleaseEgressGeneration.index())
            .all(completed),
    }
}

fn cleanup_stages_can_overlap(
    left: PreparedShardCleanupStage,
    right: PreparedShardCleanupStage,
) -> bool {
    let branch = |stage| match stage {
        PreparedShardCleanupStage::RevokeEgress
        | PreparedShardCleanupStage::ConfirmEgressDrained => Some(false),
        PreparedShardCleanupStage::AbortGate
        | PreparedShardCleanupStage::KillCgroup
        | PreparedShardCleanupStage::ConfirmProcessDeath => Some(true),
        PreparedShardCleanupStage::CloseCapabilities
        | PreparedShardCleanupStage::CleanupNetworkNamespace
        | PreparedShardCleanupStage::CleanupRuntimeFilesystem
        | PreparedShardCleanupStage::RemoveCgroup
        | PreparedShardCleanupStage::ReleaseEgressGeneration => None,
    };
    matches!((branch(left), branch(right)), (Some(left), Some(right)) if left != right)
}

fn apply_cleanup_begin(
    lifecycle: &mut PreparedShardLifecycle,
    fence: &ShardFence,
    stage: PreparedShardCleanupStage,
) -> Result<(), PreparedShardJournalError> {
    let transition = match stage {
        PreparedShardCleanupStage::RevokeEgress => Some(PreparedShardTransition::RevokeStarted),
        PreparedShardCleanupStage::AbortGate => Some(PreparedShardTransition::GateAbortStarted),
        PreparedShardCleanupStage::KillCgroup => Some(PreparedShardTransition::CgroupKillStarted),
        PreparedShardCleanupStage::CloseCapabilities => {
            Some(PreparedShardTransition::CleanupStarted)
        }
        PreparedShardCleanupStage::ConfirmProcessDeath
        | PreparedShardCleanupStage::ConfirmEgressDrained
        | PreparedShardCleanupStage::CleanupNetworkNamespace
        | PreparedShardCleanupStage::CleanupRuntimeFilesystem
        | PreparedShardCleanupStage::RemoveCgroup
        | PreparedShardCleanupStage::ReleaseEgressGeneration => None,
    };
    if let Some(transition) = transition {
        lifecycle
            .apply(fence, transition)
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
    }
    Ok(())
}

fn apply_cleanup_completion(
    lifecycle: &mut PreparedShardLifecycle,
    fence: &ShardFence,
    stage: PreparedShardCleanupStage,
) -> Result<(), PreparedShardJournalError> {
    if stage == PreparedShardCleanupStage::ReleaseEgressGeneration {
        lifecycle
            .apply(fence, PreparedShardTransition::CleanupCompleted)
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
    }
    Ok(())
}

fn validate_effect_begin(
    lifecycle: &PreparedShardLifecycle,
    fence: &ShardFence,
    effect: &PreparedShardEffect,
) -> Result<(), PreparedShardJournalError> {
    let mut projected = lifecycle.clone();
    apply_effect_begin(&mut projected, fence, effect)?;
    apply_effect_completion(&mut projected, fence, effect)
}

fn apply_effect_begin(
    lifecycle: &mut PreparedShardLifecycle,
    fence: &ShardFence,
    effect: &PreparedShardEffect,
) -> Result<(), PreparedShardJournalError> {
    if let PreparedShardEffect::PrepareEgress(egress_fence) = effect
        && (egress_fence.shard() != fence
            || lifecycle.state() != browserd_core::PreparedShardState::FilesystemCgroupReady)
    {
        return Err(PreparedShardJournalError::InvalidHistory);
    }
    let transition = match effect {
        PreparedShardEffect::SendReleaseToken { .. } => {
            Some(PreparedShardTransition::ReleaseIntentRecorded)
        }
        PreparedShardEffect::CreateFilesystemCgroup
        | PreparedShardEffect::PrepareEgress(_)
        | PreparedShardEffect::SpawnGatedChild
        | PreparedShardEffect::ProveProcessIdentity
        | PreparedShardEffect::AttachCgroup
        | PreparedShardEffect::ProveNetworkNamespace
        | PreparedShardEffect::RegisterIngress(_)
        | PreparedShardEffect::ClaimCdp
        | PreparedShardEffect::ProveContainment => None,
    };
    if let Some(transition) = transition {
        lifecycle
            .apply(fence, transition)
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
    }
    Ok(())
}

fn apply_effect_completion(
    lifecycle: &mut PreparedShardLifecycle,
    fence: &ShardFence,
    effect: &PreparedShardEffect,
) -> Result<(), PreparedShardJournalError> {
    let transition = match effect {
        PreparedShardEffect::CreateFilesystemCgroup => {
            Some(PreparedShardTransition::FilesystemCgroupReady)
        }
        PreparedShardEffect::PrepareEgress(_) => None,
        PreparedShardEffect::SpawnGatedChild => Some(PreparedShardTransition::ChildGated),
        PreparedShardEffect::ProveProcessIdentity => {
            Some(PreparedShardTransition::ProcessIdentityProven)
        }
        PreparedShardEffect::AttachCgroup => Some(PreparedShardTransition::CgroupAttached),
        PreparedShardEffect::ProveNetworkNamespace => {
            Some(PreparedShardTransition::NetnsIdentityProven)
        }
        PreparedShardEffect::RegisterIngress(egress_fence) => Some(
            PreparedShardTransition::IngressRegistered(egress_fence.clone()),
        ),
        PreparedShardEffect::ClaimCdp => Some(PreparedShardTransition::CdpClaimed),
        PreparedShardEffect::ProveContainment => Some(PreparedShardTransition::ContainmentProven),
        PreparedShardEffect::SendReleaseToken { release_sequence } => {
            Some(PreparedShardTransition::ReleaseTokenSent {
                release_sequence: *release_sequence,
            })
        }
    };
    if let Some(transition) = transition {
        lifecycle
            .apply(fence, transition)
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::io::Cursor;
    use std::path::PathBuf;

    use browserd_core::{LaunchGeneration, OwnerFence, ShardId, WorkerEpoch, WorkerId};

    use super::{
        FilePreparedShardJournal, PreparedShardJournalError, PreparedShardRecoveryLocators,
        ShardFence, read_record_bytes,
    };

    #[test]
    fn record_read_stops_after_the_maximum_frame_plus_one() {
        let maximum_frame = 128;
        let mut growing_file = Cursor::new(vec![0_u8; 4_096]);

        assert!(matches!(
            read_record_bytes(&mut growing_file, 64, maximum_frame),
            Err(PreparedShardJournalError::LimitExceeded)
        ));
        assert_eq!(growing_file.position(), 129);
    }

    #[test]
    fn rename_without_parent_fsync_poisons_the_open_writer_until_reopen() {
        let directory = tempfile::tempdir().expect("journal directory must be created");
        let fence = ShardFence::new(
            OwnerFence::new(
                WorkerId::new("worker-storage-uncertain").expect("worker identity must be valid"),
                WorkerEpoch::new(1).expect("worker epoch must be positive"),
            ),
            ShardId::new(),
            LaunchGeneration::new(1).expect("launch generation must be positive"),
        );
        let journal = FilePreparedShardJournal::open(directory.path())
            .expect("prepared-shard journal must open");
        journal.inject_failure_after_next_rename();

        assert!(matches!(
            journal.reserve(
                fence.clone(),
                PreparedShardRecoveryLocators::new(
                    "backend-token-storage-uncertain",
                    PathBuf::from("/sys/fs/cgroup/browserd/storage-uncertain"),
                    PathBuf::from("/run/browserd/shards/storage-uncertain"),
                )
                .expect("recovery locators must be valid"),
            ),
            Err(PreparedShardJournalError::StorageUncertain)
        ));
        assert!(matches!(
            journal.records(),
            Err(PreparedShardJournalError::StorageUncertain)
        ));
        drop(journal);

        let reopened = FilePreparedShardJournal::open(directory.path())
            .expect("reopen must rebuild truth from the renamed record");
        assert_eq!(
            reopened
                .records()
                .expect("reopened journal must be usable")
                .len(),
            1
        );
    }
}
