//! Private, authenticated checkpoint state. Plaintext never enters the artifact store.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use browserd_chromium::ChromiumArtifactIdentity;
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use browserd_policy::Origin;
use browserd_session::OwnershipFence;
use nix::dir::Dir;
use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, RenameFlags, open, openat, renameat2};
use nix::sys::stat::{Mode, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use uuid::{Uuid, Version};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CHECKPOINT_STATE_BYTES: usize = 32 * 1024;
pub const MAX_CHECKPOINT_FILE_BYTES: usize = 64 * 1024;
pub const MAX_CHECKPOINT_COOKIES: usize = 128;
pub const MAX_CHECKPOINT_ORIGINS: usize = 16;
pub const MAX_CHECKPOINT_STORAGE_ENTRIES: usize = 256;
const MAX_NAME_BYTES: usize = 1024;
const MAX_COOKIE_VALUE_BYTES: usize = 4096;
const MAX_STORAGE_VALUE_BYTES: usize = 16 * 1024;
const MAX_ORIGIN_BYTES: usize = 2048;
const MAX_RECORDS: usize = 128;
const MAX_STORE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const STORE_SCHEMA: u32 = 1;
const STATE_TAG_BYTES: usize = 16;
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const AAD_DOMAIN: &[u8] = b"browserd.checkpoint.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    Rejected,
    Unavailable,
    DeadlineBeforeDispatch,
    OutcomeUncertain,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected => "checkpoint rejected",
            Self::Unavailable => "checkpoint unavailable",
            Self::DeadlineBeforeDispatch => "checkpoint deadline elapsed before dispatch",
            Self::OutcomeUncertain => "checkpoint outcome uncertain",
        })
    }
}

impl std::error::Error for CheckpointError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRestoreReceipt {
    pub checkpoint_ref: String,
    pub source_session_id: SessionId,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSnapshot {
    pub artifact_identity: ChromiumArtifactIdentity,
    pub cookies: Vec<CheckpointCookie>,
    pub origins: Vec<CheckpointOriginStorage>,
}

impl fmt::Debug for CheckpointSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointSnapshot([REDACTED])")
    }
}

impl CheckpointSnapshot {
    pub fn validate(&self) -> Result<(), CheckpointError> {
        self.artifact_identity
            .validate()
            .map_err(|_| CheckpointError::Rejected)?;
        if self.cookies.len() > MAX_CHECKPOINT_COOKIES
            || self.origins.len() > MAX_CHECKPOINT_ORIGINS
        {
            return Err(CheckpointError::Rejected);
        }
        let mut cookies = std::collections::BTreeSet::new();
        for cookie in &self.cookies {
            cookie.validate()?;
            if !cookies.insert((&cookie.domain, &cookie.path, &cookie.name)) {
                return Err(CheckpointError::Rejected);
            }
        }
        let mut origins = std::collections::BTreeSet::new();
        let mut count = 0usize;
        for storage in &self.origins {
            let origin = Origin::parse(&storage.origin).map_err(|_| CheckpointError::Rejected)?;
            if storage.origin.len() > MAX_ORIGIN_BYTES
                || origin.as_str() != storage.origin
                || !origins.insert(&storage.origin)
            {
                return Err(CheckpointError::Rejected);
            }
            count = count
                .checked_add(storage.local_storage.len())
                .ok_or(CheckpointError::Rejected)?;
            if count > MAX_CHECKPOINT_STORAGE_ENTRIES {
                return Err(CheckpointError::Rejected);
            }
            let mut names = std::collections::BTreeSet::new();
            for entry in &storage.local_storage {
                if entry.name.len() > MAX_NAME_BYTES
                    || entry.value.len() > MAX_STORAGE_VALUE_BYTES
                    || !names.insert(&entry.name)
                {
                    return Err(CheckpointError::Rejected);
                }
            }
        }
        serde_json::to_writer(CountWriter { count: 0 }, self)
            .map_err(|_| CheckpointError::Rejected)?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<f64>,
    pub http_only: bool,
    pub secure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    pub priority: String,
    pub source_scheme: String,
    pub source_port: i64,
}

impl CheckpointCookie {
    fn validate(&self) -> Result<(), CheckpointError> {
        if self.name.is_empty()
            || self.name.len() > MAX_NAME_BYTES
            || self.value.len() > MAX_COOKIE_VALUE_BYTES
            || self
                .name
                .bytes()
                .any(|byte| byte <= 0x20 || byte >= 0x7f || b"()<>@,;:\\\"/[]?={}".contains(&byte))
            || self
                .value
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f || byte == b';')
            || self.domain.is_empty()
            || self.domain.len() > MAX_NAME_BYTES
            || self.domain.chars().any(char::is_control)
            || self.path.len() > MAX_NAME_BYTES
            || !self.path.starts_with('/')
            || self.path.chars().any(char::is_control)
            || self
                .expires
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            || self
                .same_site
                .as_deref()
                .is_some_and(|value| !matches!(value, "Strict" | "Lax" | "None"))
            || !matches!(self.priority.as_str(), "Low" | "Medium" | "High")
            || !matches!(
                self.source_scheme.as_str(),
                "Unset" | "NonSecure" | "Secure"
            )
            || !(self.source_port == -1 || (1..=65535).contains(&self.source_port))
        {
            return Err(CheckpointError::Rejected);
        }
        let host = self.domain.strip_prefix('.').unwrap_or(&self.domain);
        if host.is_empty()
            || host.contains(['/', '@', '?', '#', '\\'])
            || url::Host::parse(host).is_err()
        {
            return Err(CheckpointError::Rejected);
        }
        Ok(())
    }
}

impl fmt::Debug for CheckpointCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointCookie([REDACTED])")
    }
}

impl Drop for CheckpointCookie {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
        self.domain.zeroize();
        self.path.zeroize();
        self.same_site.zeroize();
        self.priority.zeroize();
        self.source_scheme.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointOriginStorage {
    pub origin: String,
    pub local_storage: Vec<CheckpointStorageEntry>,
}

impl fmt::Debug for CheckpointOriginStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointOriginStorage([REDACTED])")
    }
}

impl Drop for CheckpointOriginStorage {
    fn drop(&mut self) {
        self.origin.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointStorageEntry {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for CheckpointStorageEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckpointStorageEntry([REDACTED])")
    }
}

impl Drop for CheckpointStorageEntry {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

pub struct LoadedCheckpoint {
    pub receipt: CheckpointRestoreReceipt,
    pub snapshot: CheckpointSnapshot,
}

impl fmt::Debug for LoadedCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedCheckpoint")
            .field("receipt", &self.receipt)
            .field("snapshot", &"[REDACTED]")
            .finish()
    }
}

pub trait CheckpointStore: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    fn save(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        action: &ActionId,
        snapshot: CheckpointSnapshot,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> Result<CheckpointRestoreReceipt, CheckpointError>;
    fn load(
        &self,
        tenant: &TenantId,
        checkpoint_ref: &str,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> Result<LoadedCheckpoint, CheckpointError>;
    fn cleanup_expired(&self, now_unix_ms: u64) -> Result<usize, CheckpointError>;
    fn discard(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        action: &ActionId,
        checkpoint_ref: &str,
    ) -> Result<(), CheckpointError>;
}

/// Limits may be tightened for a deployment; the security bounds cannot be raised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointStoreLimits {
    pub max_records: usize,
    pub max_bytes: u64,
    pub retention_ms: u64,
}

impl Default for CheckpointStoreLimits {
    fn default() -> Self {
        Self {
            max_records: MAX_RECORDS,
            max_bytes: MAX_STORE_BYTES,
            retention_ms: MAX_RETENTION_MS,
        }
    }
}

impl CheckpointStoreLimits {
    fn validate(self) -> Result<(), CheckpointError> {
        if self.max_records == 0
            || self.max_records > MAX_RECORDS
            || self.max_bytes == 0
            || self.max_bytes > MAX_STORE_BYTES
            || self.retention_ms == 0
            || self.retention_ms > MAX_RETENTION_MS
        {
            return Err(CheckpointError::Rejected);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredFence {
    worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}

impl From<&OwnershipFence> for StoredFence {
    fn from(fence: &OwnershipFence) -> Self {
        Self {
            worker_id: fence.worker_id().clone(),
            worker_epoch: fence.worker_epoch(),
            placement_version: fence.placement_version(),
            session_incarnation: fence.session_incarnation(),
        }
    }
}

impl StoredFence {
    fn validate(&self) -> Result<(), CheckpointError> {
        if self.worker_epoch == 0 || self.placement_version == 0 || self.session_incarnation == 0 {
            return Err(CheckpointError::Rejected);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointMetadata {
    schema_version: u32,
    checkpoint_ref: String,
    tenant_id: TenantId,
    source_session_id: SessionId,
    fence: StoredFence,
    action_id: ActionId,
    artifact_identity: ChromiumArtifactIdentity,
    created_unix_ms: u64,
    expires_unix_ms: u64,
}

impl CheckpointMetadata {
    fn validate(&self) -> Result<(), CheckpointError> {
        canonical_ref(&self.checkpoint_ref)?;
        self.fence.validate()?;
        self.artifact_identity
            .validate()
            .map_err(|_| CheckpointError::Rejected)?;
        if self.schema_version != STORE_SCHEMA
            || self.expires_unix_ms <= self.created_unix_ms
            || self.expires_unix_ms - self.created_unix_ms > MAX_RETENTION_MS
        {
            return Err(CheckpointError::Rejected);
        }
        Ok(())
    }

    fn receipt(&self) -> CheckpointRestoreReceipt {
        CheckpointRestoreReceipt {
            checkpoint_ref: self.checkpoint_ref.clone(),
            source_session_id: self.source_session_id.clone(),
        }
    }

    fn matches_action(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &StoredFence,
        action: &ActionId,
    ) -> bool {
        self.tenant_id == *tenant
            && self.source_session_id == *session
            && self.fence == *fence
            && self.action_id == *action
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEnvelope {
    metadata: CheckpointMetadata,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone)]
struct StoredRecord {
    metadata: CheckpointMetadata,
    identity: FileIdentity,
    bytes: u64,
    deletion_pending: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl From<&Metadata> for FileIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

struct PendingRecord {
    identity: Option<FileIdentity>,
    bytes: u64,
    // A partial encrypted write has no authenticated metadata. Its filesystem timestamp is
    // used only to reap this unpublished staging file, never to authorize loading state.
    created_unix_ms: u64,
}

#[derive(Default)]
struct StoreState {
    records: BTreeMap<String, StoredRecord>,
    pending: BTreeMap<String, PendingRecord>,
    bytes: u64,
    // If a created staging file cannot be identified, keep its full reservation and
    // stop further writes. A restart can recover the bounded directory read-only.
    admission_blocked: bool,
}

/// The root and encryption key are pinned at startup. No plaintext is cached or staged on disk.
/// An exclusive root-directory flock prevents cross-process quota and action-dedupe races.
pub struct FileCheckpointStore {
    root: Flock<File>,
    owner_uid: u32,
    key: LessSafeKey,
    random: SystemRandom,
    limits: CheckpointStoreLimits,
    state: Mutex<StoreState>,
    #[cfg(test)]
    fail_pending_sync: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_pending_retention_metadata: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_rename_after_effect: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for FileCheckpointStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileCheckpointStore([REDACTED])")
    }
}

impl FileCheckpointStore {
    pub fn open(root: &Path, key_file: &Path) -> Result<Self, CheckpointError> {
        Self::open_with_limits(root, key_file, CheckpointStoreLimits::default())
    }

    pub fn open_with_limits(
        root: &Path,
        key_file: &Path,
        limits: CheckpointStoreLimits,
    ) -> Result<Self, CheckpointError> {
        limits.validate()?;
        let owner_uid = nix::unistd::geteuid().as_raw();
        let root = private_directory(root, owner_uid)?;
        let root = Flock::lock(root, FlockArg::LockExclusiveNonblock)
            .map_err(|_| CheckpointError::Unavailable)?;
        let key_parent = key_file.parent().ok_or(CheckpointError::Rejected)?;
        let key_name = key_file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(CheckpointError::Rejected)?;
        let key_directory = private_directory(key_parent, owner_uid)?;
        let mut key_file = private_file(&key_directory, key_name, owner_uid)?;
        let key_metadata = key_file
            .metadata()
            .map_err(|_| CheckpointError::Unavailable)?;
        let deadline = Instant::now() + RECOVERY_TIMEOUT;
        let key_bytes = read_bounded(&mut key_file, 32, deadline)?;
        if key_bytes.len() != 32 {
            return Err(CheckpointError::Rejected);
        }
        let key = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, key_bytes.as_slice())
                .map_err(|_| CheckpointError::Rejected)?,
        );
        drop(key_bytes);
        let store = Self {
            root,
            owner_uid,
            key,
            random: SystemRandom::new(),
            limits,
            state: Mutex::new(StoreState::default()),
            #[cfg(test)]
            fail_pending_sync: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_pending_retention_metadata: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_rename_after_effect: std::sync::atomic::AtomicBool::new(false),
        };
        let same_key_directory = same_inode(
            &store
                .root
                .metadata()
                .map_err(|_| CheckpointError::Unavailable)?,
            &key_directory
                .metadata()
                .map_err(|_| CheckpointError::Unavailable)?,
        );
        let recovered = store.recover(
            if same_key_directory {
                Some((key_name, &key_metadata))
            } else {
                None
            },
            deadline,
        )?;
        *store
            .state
            .lock()
            .map_err(|_| CheckpointError::Unavailable)? = recovered;
        Ok(store)
    }

    fn recover(
        &self,
        key_entry: Option<(&str, &Metadata)>,
        deadline: Instant,
    ) -> Result<StoreState, CheckpointError> {
        let fd: OwnedFd = self
            .root
            .try_clone()
            .map_err(|_| CheckpointError::Unavailable)?
            .into();
        let mut directory = Dir::from_fd(fd).map_err(|_| CheckpointError::Unavailable)?;
        let mut state = StoreState::default();
        for entry in directory.iter() {
            check_deadline(deadline)?;
            let entry = entry.map_err(|_| CheckpointError::Unavailable)?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| CheckpointError::Rejected)?;
            if name == "." || name == ".." {
                continue;
            }
            if let Some((key_name, key_metadata)) = key_entry
                && name == key_name
            {
                let file = private_file(&self.root, name, self.owner_uid)?;
                if !same_inode(
                    &file.metadata().map_err(|_| CheckpointError::Unavailable)?,
                    key_metadata,
                ) {
                    return Err(CheckpointError::Rejected);
                }
                continue;
            }
            if state.records.len() + state.pending.len() >= self.limits.max_records {
                return Err(CheckpointError::Rejected);
            }
            if let Some(checkpoint_ref) = name.strip_suffix(".checkpoint") {
                canonical_ref(checkpoint_ref)?;
                let (record, plaintext, _) =
                    self.read_authenticated_record(checkpoint_ref, deadline)?;
                drop(plaintext);
                if state.records.values().any(|existing| {
                    existing.metadata.matches_action(
                        &record.metadata.tenant_id,
                        &record.metadata.source_session_id,
                        &record.metadata.fence,
                        &record.metadata.action_id,
                    )
                }) {
                    return Err(CheckpointError::Rejected);
                }
                state.bytes = state
                    .bytes
                    .checked_add(record.bytes)
                    .ok_or(CheckpointError::Rejected)?;
                state.records.insert(checkpoint_ref.to_owned(), record);
            } else if valid_pending_name(name) {
                let file = private_file(&self.root, name, self.owner_uid)?;
                let metadata = file.metadata().map_err(|_| CheckpointError::Unavailable)?;
                if metadata.len() > MAX_CHECKPOINT_FILE_BYTES as u64 {
                    return Err(CheckpointError::Rejected);
                }
                state.bytes = state
                    .bytes
                    .checked_add(metadata.len())
                    .ok_or(CheckpointError::Rejected)?;
                state.pending.insert(
                    name.to_owned(),
                    PendingRecord {
                        identity: Some(FileIdentity::from(&metadata)),
                        bytes: metadata.len(),
                        created_unix_ms: modified_unix_ms(&metadata)?,
                    },
                );
            } else {
                // This directory is exclusively the private checkpoint store; unrelated
                // entries must not silently escape its record and byte quotas.
                return Err(CheckpointError::Rejected);
            }
            if state.bytes > self.limits.max_bytes {
                return Err(CheckpointError::Rejected);
            }
        }
        check_deadline(deadline)?;
        Ok(state)
    }

    fn read_authenticated_record(
        &self,
        checkpoint_ref: &str,
        deadline: Instant,
    ) -> Result<(StoredRecord, Zeroizing<Vec<u8>>, usize), CheckpointError> {
        let mut file = private_file(&self.root, &record_name(checkpoint_ref), self.owner_uid)?;
        let metadata = file.metadata().map_err(|_| CheckpointError::Unavailable)?;
        let bytes = read_bounded(&mut file, MAX_CHECKPOINT_FILE_BYTES, deadline)?;
        let envelope: CheckpointEnvelope =
            serde_json::from_slice(bytes.as_slice()).map_err(|_| CheckpointError::Rejected)?;
        envelope.metadata.validate()?;
        if envelope.metadata.checkpoint_ref != checkpoint_ref {
            return Err(CheckpointError::Rejected);
        }
        let nonce_bytes = STANDARD
            .decode(&envelope.nonce)
            .map_err(|_| CheckpointError::Rejected)?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce_bytes
            .try_into()
            .map_err(|_| CheckpointError::Rejected)?;
        let mut ciphertext = Zeroizing::new(
            STANDARD
                .decode(&envelope.ciphertext)
                .map_err(|_| CheckpointError::Rejected)?,
        );
        if ciphertext.len() < STATE_TAG_BYTES
            || ciphertext.len() > MAX_CHECKPOINT_STATE_BYTES + STATE_TAG_BYTES
        {
            return Err(CheckpointError::Rejected);
        }
        let aad = metadata_aad(&envelope.metadata)?;
        check_deadline(deadline)?;
        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad.as_slice()),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| CheckpointError::Rejected)?;
        let plaintext_len = plaintext.len();
        check_deadline(deadline)?;
        Ok((
            StoredRecord {
                metadata: envelope.metadata,
                identity: FileIdentity::from(&metadata),
                bytes: bytes.len() as u64,
                deletion_pending: false,
            },
            ciphertext,
            plaintext_len,
        ))
    }

    fn verified_record(
        &self,
        expected: &StoredRecord,
        deadline: Instant,
    ) -> Result<(Zeroizing<Vec<u8>>, usize), CheckpointError> {
        let (record, plaintext, len) =
            self.read_authenticated_record(&expected.metadata.checkpoint_ref, deadline)?;
        if record.identity != expected.identity || record.metadata != expected.metadata {
            return Err(CheckpointError::Rejected);
        }
        Ok((plaintext, len))
    }

    fn remove_exact(&self, filename: &str, expected: FileIdentity) -> Result<(), CheckpointError> {
        check_directory(&self.root, self.owner_uid)?;
        match fstatat(&*self.root, filename, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(nix::errno::Errno::ENOENT) => {
                // Retry a prior unlink whose directory fsync was uncertain.
                return self
                    .root
                    .sync_all()
                    .map_err(|_| CheckpointError::OutcomeUncertain);
            }
            Err(_) => return Err(CheckpointError::Unavailable),
            Ok(at) if at.st_dev != expected.dev || at.st_ino != expected.ino => {
                return Err(CheckpointError::Rejected);
            }
            Ok(_) => {}
        }
        let file = private_file(&self.root, filename, self.owner_uid)?;
        let metadata = file.metadata().map_err(|_| CheckpointError::Unavailable)?;
        if FileIdentity::from(&metadata) != expected {
            return Err(CheckpointError::Rejected);
        }
        let at = fstatat(&*self.root, filename, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| CheckpointError::Unavailable)?;
        if at.st_dev != expected.dev || at.st_ino != expected.ino {
            return Err(CheckpointError::Rejected);
        }
        unlinkat(&*self.root, filename, UnlinkatFlags::NoRemoveDir)
            .map_err(|_| CheckpointError::Unavailable)?;
        self.root
            .sync_all()
            .map_err(|_| CheckpointError::OutcomeUncertain)
    }

    fn retain_pending(
        &self,
        state: &mut StoreState,
        filename: &str,
        pending: &File,
    ) -> Result<(), CheckpointError> {
        // Do not reopen by pathname: descriptor exhaustion must not lose the pre-create
        // reservation. Retain the full reserved bytes until exact deletion is durable.
        let metadata = {
            #[cfg(test)]
            let injected_failure = self
                .fail_pending_retention_metadata
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let injected_failure = false;
            if injected_failure {
                Err(CheckpointError::Unavailable)
            } else {
                pending.metadata().map_err(|_| CheckpointError::Unavailable)
            }
        };
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(error) => {
                state.admission_blocked = true;
                return Err(error);
            }
        };
        let record = state
            .pending
            .get_mut(filename)
            .ok_or(CheckpointError::Unavailable)?;
        if metadata.len() > record.bytes {
            state.admission_blocked = true;
            return Err(CheckpointError::Rejected);
        }
        record.identity = Some(FileIdentity::from(&metadata));
        Ok(())
    }

    fn remove_pending(
        &self,
        state: &mut StoreState,
        filename: &str,
    ) -> Result<(), CheckpointError> {
        let record = state
            .pending
            .get(filename)
            .ok_or(CheckpointError::Unavailable)?;
        let identity = record.identity.ok_or(CheckpointError::Unavailable)?;
        self.remove_exact(filename, identity)?;
        let record = state
            .pending
            .remove(filename)
            .ok_or(CheckpointError::Unavailable)?;
        state.bytes = state.bytes.saturating_sub(record.bytes);
        Ok(())
    }

    fn publish_record(
        &self,
        pending_name: &str,
        checkpoint_ref: &str,
    ) -> Result<(), nix::errno::Errno> {
        renameat2(
            &*self.root,
            pending_name,
            &*self.root,
            record_name(checkpoint_ref).as_str(),
            RenameFlags::RENAME_NOREPLACE,
        )?;
        #[cfg(test)]
        if self
            .fail_rename_after_effect
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(nix::errno::Errno::EIO);
        }
        Ok(())
    }

    fn reconcile_publication(
        &self,
        state: &mut StoreState,
        pending_name: &str,
        metadata: &CheckpointMetadata,
        expected: FileIdentity,
        deadline: Instant,
    ) -> Result<CheckpointRestoreReceipt, CheckpointError> {
        // A remote filesystem may complete rename and report an error. Its return value
        // alone never permits releasing the charge or retrying under a fresh UUID.
        let source = fstatat(&*self.root, pending_name, AtFlags::AT_SYMLINK_NOFOLLOW);
        let destination = fstatat(
            &*self.root,
            record_name(&metadata.checkpoint_ref).as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        );
        let final_owned = matches!(source, Err(nix::errno::Errno::ENOENT))
            && destination
                .is_ok_and(|stat| stat.st_dev == expected.dev && stat.st_ino == expected.ino);
        if !final_owned {
            state.admission_blocked = true;
            return Err(CheckpointError::OutcomeUncertain);
        }
        let authenticated = self.read_authenticated_record(&metadata.checkpoint_ref, deadline);
        let (record, plaintext, _) = match authenticated {
            Ok(record) => record,
            Err(_) => {
                state.admission_blocked = true;
                return Err(CheckpointError::OutcomeUncertain);
            }
        };
        drop(plaintext);
        if record.metadata != *metadata
            || record.identity.dev != expected.dev
            || record.identity.ino != expected.ino
            || state
                .pending
                .get(pending_name)
                .is_none_or(|reserved| reserved.bytes != record.bytes)
        {
            state.admission_blocked = true;
            return Err(CheckpointError::OutcomeUncertain);
        }
        // Retain the existing bytes charge while converting its slot from staging to
        // published authority, before any further fallible durability operation.
        if state.pending.remove(pending_name).is_none() {
            state.admission_blocked = true;
            return Err(CheckpointError::OutcomeUncertain);
        }
        state
            .records
            .insert(metadata.checkpoint_ref.clone(), record);
        self.root
            .sync_all()
            .map_err(|_| CheckpointError::OutcomeUncertain)?;
        check_deadline(deadline).map_err(|_| CheckpointError::OutcomeUncertain)?;
        Ok(metadata.receipt())
    }
}

impl CheckpointStore for FileCheckpointStore {
    fn save(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        action: &ActionId,
        snapshot: CheckpointSnapshot,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> Result<CheckpointRestoreReceipt, CheckpointError> {
        check_deadline(deadline)?;
        snapshot.validate()?;
        let fence = StoredFence::from(fence);
        fence.validate()?;
        check_directory(&self.root, self.owner_uid)?;
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| CheckpointError::Unavailable)?;
        if state.admission_blocked {
            return Err(CheckpointError::Unavailable);
        }
        if let Some(existing) = state.records.values().find(|record| {
            record
                .metadata
                .matches_action(tenant, session, &fence, action)
        }) {
            if existing.deletion_pending
                || now_unix_ms >= existing.metadata.expires_unix_ms
                || snapshot.artifact_identity != existing.metadata.artifact_identity
            {
                return Err(CheckpointError::Rejected);
            }
            drop(self.verified_record(existing, deadline)?);
            check_deadline(deadline)?;
            self.root
                .sync_all()
                .map_err(|_| CheckpointError::OutcomeUncertain)?;
            check_deadline(deadline).map_err(|_| CheckpointError::OutcomeUncertain)?;
            return Ok(existing.metadata.receipt());
        }
        if state.records.len() + state.pending.len() >= self.limits.max_records {
            return Err(CheckpointError::Rejected);
        }
        let checkpoint_ref = Uuid::new_v4().to_string();
        let metadata = CheckpointMetadata {
            schema_version: STORE_SCHEMA,
            checkpoint_ref: checkpoint_ref.clone(),
            tenant_id: tenant.clone(),
            source_session_id: session.clone(),
            fence,
            action_id: action.clone(),
            artifact_identity: snapshot.artifact_identity.clone(),
            created_unix_ms: now_unix_ms,
            expires_unix_ms: now_unix_ms
                .checked_add(self.limits.retention_ms)
                .ok_or(CheckpointError::Rejected)?,
        };
        metadata.validate()?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            MAX_CHECKPOINT_STATE_BYTES + STATE_TAG_BYTES,
        ));
        serde_json::to_writer(
            StateWriter {
                bytes: &mut plaintext,
            },
            &snapshot,
        )
        .map_err(|_| CheckpointError::Rejected)?;
        drop(snapshot);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.random
            .fill(&mut nonce_bytes)
            .map_err(|_| CheckpointError::Unavailable)?;
        let aad = metadata_aad(&metadata)?;
        check_deadline(deadline)?;
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad.as_slice()),
                &mut *plaintext,
            )
            .map_err(|_| CheckpointError::Unavailable)?;
        let envelope = CheckpointEnvelope {
            metadata: metadata.clone(),
            nonce: STANDARD.encode(nonce_bytes),
            ciphertext: STANDARD.encode(plaintext.as_slice()),
        };
        drop(plaintext);
        let bytes = serde_json::to_vec(&envelope).map_err(|_| CheckpointError::Unavailable)?;
        if bytes.len() > MAX_CHECKPOINT_FILE_BYTES
            || state
                .bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > self.limits.max_bytes)
        {
            return Err(CheckpointError::Rejected);
        }
        check_deadline(deadline)?;
        let pending_name = format!(".checkpoint-{}.pending", Uuid::new_v4());
        // Reserve a complete slot and the maximum bytes this write will create before
        // touching the filesystem. Every failure retains them unless deletion is fsynced.
        state.bytes += bytes.len() as u64;
        state.pending.insert(
            pending_name.clone(),
            PendingRecord {
                identity: None,
                bytes: bytes.len() as u64,
                created_unix_ms: now_unix_ms,
            },
        );
        let pending_fd = openat(
            &*self.root,
            pending_name.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(0o600),
        );
        let mut pending = match pending_fd {
            Ok(fd) => File::from(fd),
            Err(_) => {
                // No descriptor means there is no trustworthy inode to clean up. Keep
                // the reservation and fail closed rather than guess whether create ran.
                state.admission_blocked = true;
                return Err(CheckpointError::Unavailable);
            }
        };
        let writing = (|| {
            let file_metadata = pending
                .metadata()
                .map_err(|_| CheckpointError::Unavailable)?;
            check_file(&file_metadata, self.owner_uid)?;
            for chunk in bytes.chunks(4096) {
                check_deadline(deadline)?;
                pending
                    .write_all(chunk)
                    .map_err(|_| CheckpointError::Unavailable)?;
            }
            check_deadline(deadline)?;
            #[cfg(test)]
            if self
                .fail_pending_sync
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(CheckpointError::Unavailable);
            }
            pending
                .sync_all()
                .map_err(|_| CheckpointError::Unavailable)?;
            check_deadline(deadline)?;
            let current = pending
                .metadata()
                .map_err(|_| CheckpointError::Unavailable)?;
            check_file(&current, self.owner_uid)?;
            let named = fstatat(
                &*self.root,
                pending_name.as_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| CheckpointError::Unavailable)?;
            if current.len() != bytes.len() as u64
                || current.dev() != named.st_dev
                || current.ino() != named.st_ino
            {
                return Err(CheckpointError::Rejected);
            }
            Ok(FileIdentity::from(&current))
        })();
        let unpublished_identity = match writing {
            Ok(identity) => identity,
            Err(error) => {
                self.retain_pending(&mut state, &pending_name, &pending)?;
                let _ = self.remove_pending(&mut state, &pending_name);
                return Err(error);
            }
        };
        // Rename never overwrites a record. There is no link-count-two crash window.
        if self.publish_record(&pending_name, &checkpoint_ref).is_err() {
            return self.reconcile_publication(
                &mut state,
                &pending_name,
                &metadata,
                unpublished_identity,
                deadline,
            );
        }
        // From publication onward, every failure has an uncertain durable outcome. Keep
        // the index reservation even if fsync fails so retry cannot create a second ref.
        state
            .pending
            .remove(&pending_name)
            .ok_or(CheckpointError::OutcomeUncertain)?;
        state.records.insert(
            checkpoint_ref.clone(),
            StoredRecord {
                metadata: metadata.clone(),
                identity: unpublished_identity,
                bytes: bytes.len() as u64,
                deletion_pending: false,
            },
        );
        let file_metadata = pending
            .metadata()
            .map_err(|_| CheckpointError::OutcomeUncertain)?;
        state
            .records
            .get_mut(&checkpoint_ref)
            .ok_or(CheckpointError::OutcomeUncertain)?
            .identity = FileIdentity::from(&file_metadata);
        self.root
            .sync_all()
            .map_err(|_| CheckpointError::OutcomeUncertain)?;
        check_deadline(deadline).map_err(|_| CheckpointError::OutcomeUncertain)?;
        Ok(metadata.receipt())
    }

    fn load(
        &self,
        tenant: &TenantId,
        checkpoint_ref: &str,
        now_unix_ms: u64,
        deadline: Instant,
    ) -> Result<LoadedCheckpoint, CheckpointError> {
        check_deadline(deadline)?;
        canonical_ref(checkpoint_ref)?;
        check_directory(&self.root, self.owner_uid)?;
        let state = self
            .state
            .try_lock()
            .map_err(|_| CheckpointError::Unavailable)?;
        let record = state
            .records
            .get(checkpoint_ref)
            .ok_or(CheckpointError::Rejected)?;
        // Tenant and retention checks precede decryption; no foreign plaintext is resolved.
        if record.deletion_pending
            || record.metadata.tenant_id != *tenant
            || now_unix_ms >= record.metadata.expires_unix_ms
        {
            return Err(CheckpointError::Rejected);
        }
        let (plaintext, len) = self.verified_record(record, deadline)?;
        let snapshot: CheckpointSnapshot =
            serde_json::from_slice(&plaintext[..len]).map_err(|_| CheckpointError::Rejected)?;
        snapshot.validate()?;
        if snapshot.artifact_identity != record.metadata.artifact_identity {
            return Err(CheckpointError::Rejected);
        }
        check_deadline(deadline)?;
        Ok(LoadedCheckpoint {
            receipt: record.metadata.receipt(),
            snapshot,
        })
    }

    fn cleanup_expired(&self, now_unix_ms: u64) -> Result<usize, CheckpointError> {
        check_directory(&self.root, self.owner_uid)?;
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| CheckpointError::Unavailable)?;
        let expired: Vec<String> = state
            .records
            .iter()
            .filter(|(_, record)| now_unix_ms >= record.metadata.expires_unix_ms)
            .map(|(key, _)| key.clone())
            .collect();
        let mut removed = 0;
        for checkpoint_ref in expired {
            let record = state
                .records
                .get_mut(&checkpoint_ref)
                .ok_or(CheckpointError::Unavailable)?;
            if !record.deletion_pending {
                drop(self.verified_record(record, Instant::now() + RECOVERY_TIMEOUT)?);
            }
            record.deletion_pending = true;
            self.remove_exact(&record_name(&checkpoint_ref), record.identity)?;
            let record = state
                .records
                .remove(&checkpoint_ref)
                .ok_or(CheckpointError::Unavailable)?;
            state.bytes = state.bytes.saturating_sub(record.bytes);
            removed += 1;
        }
        let expired_pending: Vec<String> = state
            .pending
            .iter()
            .filter(|(_, record)| {
                now_unix_ms.saturating_sub(record.created_unix_ms) >= self.limits.retention_ms
            })
            .map(|(key, _)| key.clone())
            .collect();
        for name in expired_pending {
            self.remove_pending(&mut state, &name)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn discard(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        action: &ActionId,
        checkpoint_ref: &str,
    ) -> Result<(), CheckpointError> {
        canonical_ref(checkpoint_ref)?;
        check_directory(&self.root, self.owner_uid)?;
        // A failed rollback latches worker checkpoint degradation, so a concurrent save, load or
        // expiry sweep is waited out (bounded) instead of being reported as a failed rollback.
        let lock_deadline = Instant::now() + RECOVERY_TIMEOUT;
        let mut state = loop {
            match self.state.try_lock() {
                Ok(state) => break state,
                Err(TryLockError::WouldBlock) if Instant::now() < lock_deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return Err(CheckpointError::Unavailable),
            }
        };
        let Some(record) = state.records.get_mut(checkpoint_ref) else {
            return Ok(());
        };
        if !record
            .metadata
            .matches_action(tenant, session, &StoredFence::from(fence), action)
        {
            return Err(CheckpointError::Rejected);
        }
        if !record.deletion_pending {
            drop(self.verified_record(record, Instant::now() + RECOVERY_TIMEOUT)?);
        }
        record.deletion_pending = true;
        self.remove_exact(&record_name(checkpoint_ref), record.identity)?;
        let record = state
            .records
            .remove(checkpoint_ref)
            .ok_or(CheckpointError::Unavailable)?;
        state.bytes = state.bytes.saturating_sub(record.bytes);
        Ok(())
    }
}

/// Counts escaped JSON bytes without retaining another plaintext copy.
struct CountWriter {
    count: usize,
}

impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let count = self
            .count
            .checked_add(bytes.len())
            .filter(|count| *count <= MAX_CHECKPOINT_STATE_BYTES)
            .ok_or_else(|| std::io::Error::other("checkpoint state bound exceeded"))?;
        self.count = count;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct StateWriter<'a> {
    bytes: &'a mut Zeroizing<Vec<u8>>,
}

impl Write for StateWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|count| count > MAX_CHECKPOINT_STATE_BYTES)
        {
            return Err(std::io::Error::other("checkpoint state bound exceeded"));
        }
        // The complete maximum plus AEAD tag was reserved before any secret bytes.
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn canonical_ref(checkpoint_ref: &str) -> Result<(), CheckpointError> {
    if checkpoint_ref.len() != 36 {
        return Err(CheckpointError::Rejected);
    }
    let uuid = Uuid::parse_str(checkpoint_ref).map_err(|_| CheckpointError::Rejected)?;
    if uuid.get_version() != Some(Version::Random) || uuid.to_string() != checkpoint_ref {
        return Err(CheckpointError::Rejected);
    }
    Ok(())
}

fn record_name(checkpoint_ref: &str) -> String {
    format!("{checkpoint_ref}.checkpoint")
}

fn valid_pending_name(name: &str) -> bool {
    name.strip_prefix(".checkpoint-")
        .and_then(|name| name.strip_suffix(".pending"))
        .is_some_and(|checkpoint_ref| canonical_ref(checkpoint_ref).is_ok())
}

fn check_deadline(deadline: Instant) -> Result<(), CheckpointError> {
    if Instant::now() >= deadline {
        Err(CheckpointError::DeadlineBeforeDispatch)
    } else {
        Ok(())
    }
}

fn metadata_aad(metadata: &CheckpointMetadata) -> Result<Vec<u8>, CheckpointError> {
    let mut bytes = AAD_DOMAIN.to_vec();
    serde_json::to_writer(&mut bytes, metadata).map_err(|_| CheckpointError::Unavailable)?;
    Ok(bytes)
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn modified_unix_ms(metadata: &Metadata) -> Result<u64, CheckpointError> {
    u64::try_from(metadata.mtime())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|seconds| {
            u64::try_from(metadata.mtime_nsec())
                .ok()
                .and_then(|nanos| seconds.checked_add(nanos / 1_000_000))
        })
        .ok_or(CheckpointError::Rejected)
}

fn private_directory(path: &Path, owner_uid: u32) -> Result<File, CheckpointError> {
    if !path.is_absolute() {
        return Err(CheckpointError::Rejected);
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = File::from(
        open(Path::new("/"), flags, Mode::empty()).map_err(|_| CheckpointError::Unavailable)?,
    );
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    openat(&directory, Path::new(name), flags, Mode::empty())
                        .map_err(|_| CheckpointError::Rejected)?,
                );
            }
            _ => return Err(CheckpointError::Rejected),
        }
    }
    check_directory(&directory, owner_uid)?;
    Ok(directory)
}

fn check_directory(directory: &File, owner_uid: u32) -> Result<(), CheckpointError> {
    let metadata = directory
        .metadata()
        .map_err(|_| CheckpointError::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != owner_uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(CheckpointError::Rejected);
    }
    Ok(())
}

fn check_file(metadata: &Metadata, owner_uid: u32) -> Result<(), CheckpointError> {
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(CheckpointError::Rejected);
    }
    Ok(())
}

fn private_file(directory: &File, name: &str, owner_uid: u32) -> Result<File, CheckpointError> {
    let file = File::from(
        openat(
            directory,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| CheckpointError::Unavailable)?,
    );
    check_file(
        &file.metadata().map_err(|_| CheckpointError::Unavailable)?,
        owner_uid,
    )?;
    Ok(file)
}

fn read_bounded(
    file: &mut File,
    limit: usize,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, CheckpointError> {
    check_deadline(deadline)?;
    let before = file.metadata().map_err(|_| CheckpointError::Unavailable)?;
    if before.len() > limit as u64 {
        return Err(CheckpointError::Rejected);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        check_deadline(deadline)?;
        let count = file
            .read(chunk.as_mut())
            .map_err(|_| CheckpointError::Unavailable)?;
        check_deadline(deadline)?;
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|size| size > limit)
        {
            return Err(CheckpointError::Rejected);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let after = file.metadata().map_err(|_| CheckpointError::Unavailable)?;
    if FileIdentity::from(&before) != FileIdentity::from(&after)
        || bytes.len() as u64 != before.len()
    {
        return Err(CheckpointError::Rejected);
    }
    check_deadline(deadline)?;
    Ok(bytes)
}

#[cfg(test)]
#[path = "checkpoint_store_tests.rs"]
mod tests;
