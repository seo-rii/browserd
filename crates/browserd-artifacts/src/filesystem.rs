use std::collections::HashMap;
use std::io;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use browserd_core::{ArtifactId, SessionId, TenantId};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::streaming::object_generation_for_upload_id;
use crate::{
    ArtifactChecksum, ArtifactChunkReader, ArtifactContentMetadata, ArtifactDeleteOutcome,
    ArtifactKey, ArtifactMultipartStore, ArtifactNamespace, ArtifactObjectError,
    ArtifactObjectGeneration, ArtifactObjectStore, ArtifactReadLimits, ArtifactStoreError,
    ArtifactWriteReceipt, AuthorizedCleanupCandidate, CleanupCandidate, CleanupKind,
    CleanupOutcome, JanitorBackend, JanitorError, MultipartUploadId,
};

const COMMIT_MAGIC: &[u8; 8] = b"BRDART01";
const COMMIT_METADATA_BYTES: usize = 64;
const MAX_VERIFIED_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MULTIPART_SCAN_BATCH: usize = 256;

#[cfg(test)]
tokio::task_local! {
    static OPTIONAL_METADATA_STAT_PAUSE:
        Arc<std::sync::Mutex<Option<Arc<OneShotPause>>>>;
    static OPTIONAL_UPLOAD_LOCK_OPEN_PAUSE:
        Arc<std::sync::Mutex<Option<Arc<OneShotPause>>>>;
}

#[derive(Clone, Debug)]
pub struct FilesystemArtifactStore {
    root: Arc<PathBuf>,
    #[cfg(test)]
    test_hooks: Arc<FilesystemTestHooks>,
}

#[derive(Clone)]
pub struct FilesystemMultipartJanitor {
    store: FilesystemArtifactStore,
    namespace: ArtifactNamespace,
    abandoned_after: Duration,
    scan_batch: usize,
    scan_cursor: Arc<tokio::sync::Mutex<MultipartScanCursor>>,
    observations: Arc<std::sync::Mutex<HashMap<MultipartObservationKey, MultipartObservation>>>,
}

#[derive(Default)]
struct MultipartScanCursor {
    reader: Option<fs::ReadDir>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MultipartObservationKey {
    upload_id: String,
    generation: ArtifactObjectGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MultipartObservation {
    activity: MultipartActivity,
    cutoff: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MultipartActivity {
    last_modified: SystemTime,
    data_bytes: Option<u64>,
    receipt_bytes: Option<u64>,
    pending_receipt_bytes: Option<u64>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct FilesystemTestHooks {
    after_begin_stage_created: std::sync::Mutex<Option<Arc<OneShotPause>>>,
    after_delete_live_read: std::sync::Mutex<Option<Arc<OneShotPause>>>,
    after_complete_stage_exists: std::sync::Mutex<Option<Arc<OneShotPause>>>,
    after_complete_data_inspection: std::sync::Mutex<Option<Arc<OneShotPause>>>,
    after_complete_receipt_created: std::sync::Mutex<Option<Arc<OneShotPause>>>,
    after_complete_rename: std::sync::Mutex<Option<Arc<OneShotPause>>>,
    complete_parent_sync_failures: AtomicUsize,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct OneShotPause {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[cfg(test)]
impl OneShotPause {
    async fn pause(&self) {
        self.reached.notify_one();
        self.resume.notified().await;
    }

    async fn wait_until_reached(&self) {
        self.reached.notified().await;
    }

    fn resume(&self) {
        self.resume.notify_one();
    }
}

pub struct FilesystemArtifactReader {
    reader: BufReader<fs::File>,
    remaining_bytes: u64,
    max_chunk_bytes: usize,
    terminal: bool,
}

impl ArtifactChunkReader for FilesystemArtifactReader {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, ArtifactObjectError> {
        if self.terminal {
            return Ok(None);
        }
        if self.remaining_bytes == 0 {
            self.terminal = true;
            return Ok(None);
        }
        let remaining_bytes = match usize::try_from(self.remaining_bytes) {
            Ok(remaining_bytes) => remaining_bytes,
            Err(_) => self.max_chunk_bytes,
        };
        let read_limit = remaining_bytes.min(self.max_chunk_bytes);
        let mut chunk = vec![0_u8; read_limit];
        let read = match self.reader.read(&mut chunk).await {
            Ok(read) => read,
            Err(error) => {
                self.terminal = true;
                return Err(ArtifactObjectError::Store(store_error(
                    "read verified artifact chunk",
                    error,
                )));
            }
        };
        if read == 0 {
            self.terminal = true;
            return Err(ArtifactObjectError::IntegrityMismatch);
        }
        let read_bytes = u64::try_from(read).map_err(|_| ArtifactObjectError::IntegrityMismatch)?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(read_bytes)
            .ok_or(ArtifactObjectError::IntegrityMismatch)?;
        chunk.truncate(read);
        Ok(Some(Bytes::from(chunk)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    receipt: ArtifactWriteReceipt,
    bytes: Bytes,
}

impl VerifiedArtifact {
    #[must_use]
    pub const fn receipt(&self) -> &ArtifactWriteReceipt {
        &self.receipt
    }

    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommitMetadata {
    upload_id: Uuid,
    size_bytes: u64,
    checksum: ArtifactChecksum,
}

impl CommitMetadata {
    fn object_generation(self) -> ArtifactObjectGeneration {
        object_generation_for_upload_id(&self.upload_id.hyphenated().to_string())
    }
}

impl FilesystemArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ArtifactStoreError::new(
                "artifact root must be an absolute path",
            ));
        }
        let metadata = std::fs::symlink_metadata(root)
            .map_err(|error| store_error("inspect artifact root", error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ArtifactStoreError::new(
                "artifact root must be a real directory",
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ArtifactStoreError::new(
                "artifact root must not be accessible by group or other users",
            ));
        }
        let root = root
            .canonicalize()
            .map_err(|error| store_error("canonicalize artifact root", error))?;
        let mut created_child = false;
        for child in [".multipart", "objects", ".deleted"] {
            let path = root.join(child);
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    created_child = true;
                    #[cfg(unix)]
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| store_error("secure artifact directory", error))?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let child_metadata = std::fs::symlink_metadata(&path)
                        .map_err(|error| store_error("inspect artifact directory", error))?;
                    if !child_metadata.is_dir() || child_metadata.file_type().is_symlink() {
                        return Err(ArtifactStoreError::new(
                            "artifact store child must be a real directory",
                        ));
                    }
                    #[cfg(unix)]
                    if child_metadata.permissions().mode() & 0o077 != 0 {
                        return Err(ArtifactStoreError::new(
                            "artifact store child must not be accessible by group or other users",
                        ));
                    }
                }
                Err(error) => return Err(store_error("create artifact directory", error)),
            }
        }
        if created_child {
            std::fs::File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| store_error("sync artifact root directory", error))?;
        }
        Ok(Self {
            root: Arc::new(root),
            #[cfg(test)]
            test_hooks: Arc::new(FilesystemTestHooks::default()),
        })
    }

    #[cfg(test)]
    fn arm_begin_stage_created_pause(&self) -> Arc<OneShotPause> {
        arm_one_shot_pause(&self.test_hooks.after_begin_stage_created)
    }

    #[cfg(test)]
    fn arm_delete_live_read_pause(&self) -> Arc<OneShotPause> {
        arm_one_shot_pause(&self.test_hooks.after_delete_live_read)
    }

    #[cfg(test)]
    fn arm_complete_stage_exists_pause(&self) -> Arc<OneShotPause> {
        arm_one_shot_pause(&self.test_hooks.after_complete_stage_exists)
    }

    #[cfg(test)]
    fn arm_complete_data_inspection_pause(&self) -> Arc<OneShotPause> {
        arm_one_shot_pause(&self.test_hooks.after_complete_data_inspection)
    }

    #[cfg(test)]
    fn arm_complete_receipt_created_pause(&self) -> Arc<OneShotPause> {
        arm_one_shot_pause(&self.test_hooks.after_complete_receipt_created)
    }

    #[cfg(test)]
    fn arm_complete_rename_pause(&self) -> Arc<OneShotPause> {
        arm_one_shot_pause(&self.test_hooks.after_complete_rename)
    }

    #[cfg(test)]
    fn arm_complete_parent_sync_failures(&self, count: usize) {
        self.test_hooks
            .complete_parent_sync_failures
            .store(count, Ordering::SeqCst);
    }

    #[cfg(test)]
    async fn pause_after_delete_live_read(&self) {
        if let Some(pause) = take_one_shot_pause(&self.test_hooks.after_delete_live_read) {
            pause.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_after_begin_stage_created(&self) {
        if let Some(pause) = take_one_shot_pause(&self.test_hooks.after_begin_stage_created) {
            pause.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_after_complete_stage_exists(&self) {
        if let Some(pause) = take_one_shot_pause(&self.test_hooks.after_complete_stage_exists) {
            pause.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_after_complete_data_inspection(&self) {
        if let Some(pause) = take_one_shot_pause(&self.test_hooks.after_complete_data_inspection) {
            pause.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_after_complete_receipt_created(&self) {
        if let Some(pause) = take_one_shot_pause(&self.test_hooks.after_complete_receipt_created) {
            pause.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_after_complete_rename(&self) {
        if let Some(pause) = take_one_shot_pause(&self.test_hooks.after_complete_rename) {
            pause.pause().await;
        }
    }

    pub async fn read_verified(
        &self,
        key: &ArtifactKey,
    ) -> Result<Option<VerifiedArtifact>, ArtifactStoreError> {
        let Some((metadata, mut reader)) = self.open_committed_data(key).await? else {
            return Ok(None);
        };
        if metadata.size_bytes > MAX_VERIFIED_READ_BYTES {
            return Err(ArtifactStoreError::new(
                "artifact exceeds bounded verified read limit",
            ));
        }
        let (actual_size, actual_checksum) = inspect_reader(&mut reader).await?;
        if actual_size != metadata.size_bytes || actual_checksum != metadata.checksum {
            return Err(ArtifactStoreError::new(
                "committed artifact failed integrity verification",
            ));
        }
        reader
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|error| store_error("rewind committed artifact", error))?;
        let capacity = usize::try_from(metadata.size_bytes)
            .map_err(|_| ArtifactStoreError::new("artifact size exceeds usize"))?;
        let mut bytes = Vec::with_capacity(capacity);
        reader
            .take(metadata.size_bytes)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| store_error("read committed artifact", error))?;
        if bytes.len() != capacity {
            return Err(ArtifactStoreError::new(
                "committed artifact changed after integrity verification",
            ));
        }
        Ok(Some(VerifiedArtifact {
            receipt: ArtifactWriteReceipt {
                key: key.clone(),
                size_bytes: metadata.size_bytes,
                checksum: metadata.checksum,
                object_generation: metadata.object_generation(),
            },
            bytes: Bytes::from(bytes),
        }))
    }

    fn stage_path(&self, upload_id: &MultipartUploadId) -> Result<PathBuf, ArtifactStoreError> {
        let upload_id = parse_upload_id(upload_id)?;
        Ok(self.root.join(".multipart").join(upload_id.to_string()))
    }

    fn object_path(&self, key: &ArtifactKey) -> PathBuf {
        self.root
            .join("objects")
            .join(key.tenant_id().to_string())
            .join(key.session_id().to_string())
            .join(key.artifact_id().to_string())
    }

    fn deleted_key_path(&self, key: &ArtifactKey) -> PathBuf {
        self.root
            .join(".deleted")
            .join(key.tenant_id().to_string())
            .join(key.session_id().to_string())
            .join(key.artifact_id().to_string())
    }

    fn tombstone_path(&self, key: &ArtifactKey, generation: ArtifactObjectGeneration) -> PathBuf {
        self.deleted_key_path(key)
            .join(encode_generation(generation))
    }

    async fn open_committed_data(
        &self,
        key: &ArtifactKey,
    ) -> Result<Option<(CommitMetadata, BufReader<fs::File>)>, ArtifactStoreError> {
        let directory = self.object_path(key);
        let first_metadata = match read_commit_metadata(&directory).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(store_error("read committed artifact metadata", error)),
        };
        let file = fs::File::open(directory.join("data"))
            .await
            .map_err(|error| store_error("open committed artifact data", error))?;
        let second_metadata = read_commit_metadata(&directory)
            .await
            .map_err(|error| store_error("revalidate committed artifact metadata", error))?;
        if first_metadata != second_metadata {
            return Err(ArtifactStoreError::new(
                "committed artifact changed while opening",
            ));
        }
        Ok(Some((first_metadata, BufReader::new(file))))
    }

    async fn ensure_tombstone_parent(
        &self,
        key: &ArtifactKey,
    ) -> Result<PathBuf, ArtifactObjectError> {
        let deleted_root = self.root.join(".deleted");
        let tenant_directory = deleted_root.join(key.tenant_id().to_string());
        let session_directory = tenant_directory.join(key.session_id().to_string());
        let key_directory = session_directory.join(key.artifact_id().to_string());
        for directory in [&tenant_directory, &session_directory, &key_directory] {
            ensure_private_directory(directory, "artifact tombstone namespace").await?;
        }
        for directory in [
            &deleted_root,
            &tenant_directory,
            &session_directory,
            &key_directory,
        ] {
            sync_directory(directory).await?;
        }
        Ok(key_directory)
    }

    async fn exact_tombstone_exists(
        &self,
        key: &ArtifactKey,
        expected_generation: ArtifactObjectGeneration,
    ) -> Result<bool, ArtifactObjectError> {
        let Some(metadata) =
            read_optional_commit_metadata(&self.tombstone_path(key, expected_generation)).await?
        else {
            return Ok(false);
        };
        if metadata.object_generation() != expected_generation {
            return Err(ArtifactObjectError::IntegrityMismatch);
        }
        Ok(true)
    }

    async fn has_any_tombstone(&self, key: &ArtifactKey) -> Result<bool, ArtifactObjectError> {
        let directory = self.deleted_key_path(key);
        let mut entries = match fs::read_dir(&directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(ArtifactObjectError::Store(store_error(
                    "read artifact tombstone namespace",
                    error,
                )));
            }
        };
        if let Some(entry) = entries.next_entry().await.map_err(|error| {
            ArtifactObjectError::Store(store_error("read artifact tombstone entry", error))
        })? {
            let file_type = entry.file_type().await.map_err(|error| {
                ArtifactObjectError::Store(store_error("inspect artifact tombstone entry", error))
            })?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(ArtifactObjectError::IntegrityMismatch);
            }
            let metadata = read_optional_commit_metadata(&entry.path())
                .await?
                .ok_or(ArtifactObjectError::IntegrityMismatch)?;
            let expected_name = encode_generation(metadata.object_generation());
            if entry.file_name().to_str() != Some(expected_name.as_str()) {
                return Err(ArtifactObjectError::IntegrityMismatch);
            }
            return Ok(true);
        }
        Ok(false)
    }

    async fn resolve_absent_delete(
        &self,
        key: &ArtifactKey,
        expected_generation: ArtifactObjectGeneration,
    ) -> Result<ArtifactDeleteOutcome, ArtifactObjectError> {
        if self
            .exact_tombstone_exists(key, expected_generation)
            .await?
        {
            let object = self.object_path(key);
            let object_parent = object
                .parent()
                .ok_or_else(|| ArtifactStoreError::new("artifact object parent is missing"))?;
            let tombstone = self.tombstone_path(key, expected_generation);
            let tombstone_parent = tombstone
                .parent()
                .ok_or_else(|| ArtifactStoreError::new("artifact tombstone parent is missing"))?;
            self.compact_tombstone(&tombstone).await?;
            sync_directory(object_parent).await?;
            sync_directory(tombstone_parent).await?;
            return Ok(ArtifactDeleteOutcome::AlreadyDeleted);
        }
        if self.has_any_tombstone(key).await? {
            return Err(ArtifactObjectError::GenerationMismatch);
        }
        Err(ArtifactObjectError::NotAvailable)
    }

    async fn compact_tombstone(&self, tombstone: &Path) -> Result<(), ArtifactObjectError> {
        for name in ["data", "key"] {
            match fs::remove_file(tombstone.join(name)).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(ArtifactObjectError::Store(store_error(
                        "compact artifact tombstone",
                        error,
                    )));
                }
            }
        }
        sync_directory(tombstone).await?;
        Ok(())
    }

    async fn prune_tombstones_except(
        &self,
        key: &ArtifactKey,
        retained_generation: ArtifactObjectGeneration,
    ) -> Result<(), ArtifactObjectError> {
        let key_directory = self.deleted_key_path(key);
        let retained_name = encode_generation(retained_generation);
        let mut entries = fs::read_dir(&key_directory).await.map_err(|error| {
            ArtifactObjectError::Store(store_error("read artifact tombstones for pruning", error))
        })?;
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            ArtifactObjectError::Store(store_error("read artifact tombstone for pruning", error))
        })? {
            if entry.file_name().to_str() == Some(retained_name.as_str()) {
                continue;
            }
            let file_type = entry.file_type().await.map_err(|error| {
                ArtifactObjectError::Store(store_error(
                    "inspect artifact tombstone for pruning",
                    error,
                ))
            })?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(ArtifactObjectError::IntegrityMismatch);
            }
            for name in ["data", "key", "receipt", "receipt.pending", "lock"] {
                match fs::remove_file(entry.path().join(name)).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(ArtifactObjectError::Store(store_error(
                            "remove superseded artifact tombstone file",
                            error,
                        )));
                    }
                }
            }
            fs::remove_dir(entry.path()).await.map_err(|error| {
                ArtifactObjectError::Store(store_error(
                    "remove superseded artifact tombstone",
                    error,
                ))
            })?;
        }
        sync_directory(&key_directory).await?;
        Ok(())
    }
}

impl FilesystemMultipartJanitor {
    pub fn new(
        store: FilesystemArtifactStore,
        namespace: ArtifactNamespace,
        abandoned_after: Duration,
        scan_batch: usize,
    ) -> Result<Self, JanitorError> {
        if abandoned_after.is_zero() {
            return Err(JanitorError::new(
                "multipart abandonment threshold must be positive",
            ));
        }
        if scan_batch == 0 || scan_batch > MAX_MULTIPART_SCAN_BATCH {
            return Err(JanitorError::new(format!(
                "multipart scan batch must be between 1 and {MAX_MULTIPART_SCAN_BATCH}"
            )));
        }
        Ok(Self {
            store,
            namespace,
            abandoned_after,
            scan_batch,
            scan_cursor: Arc::new(tokio::sync::Mutex::new(MultipartScanCursor::default())),
            observations: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    fn lock_observations(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<MultipartObservationKey, MultipartObservation>> {
        match self.observations.lock() {
            Ok(observations) => observations,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn forget_observation(&self, key: &MultipartObservationKey) {
        self.lock_observations().remove(key);
    }
}

impl JanitorBackend for FilesystemMultipartJanitor {
    async fn scan(&self, now: DateTime<Utc>) -> Result<Vec<CleanupCandidate>, JanitorError> {
        let cutoff = SystemTime::from(now)
            .checked_sub(self.abandoned_after)
            .ok_or_else(|| JanitorError::new("multipart scan cutoff is outside system time"))?;
        let mut cursor = self.scan_cursor.lock().await;
        if cursor.reader.is_none() {
            cursor.reader = Some(
                fs::read_dir(self.store.root.join(".multipart"))
                    .await
                    .map_err(|error| janitor_error("open multipart scan", error))?,
            );
        }

        let mut candidates = Vec::new();
        for _ in 0..self.scan_batch {
            let next = match cursor.reader.as_mut() {
                Some(reader) => reader
                    .next_entry()
                    .await
                    .map_err(|error| janitor_error("read multipart scan entry", error))?,
                None => None,
            };
            let Some(entry) = next else {
                cursor.reader = None;
                break;
            };
            let file_type = entry
                .file_type()
                .await
                .map_err(|error| janitor_error("inspect multipart scan entry", error))?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(JanitorError::new(
                    "multipart scan entry must be a real directory",
                ));
            }
            let upload_id = entry
                .file_name()
                .into_string()
                .map_err(|_| JanitorError::new("multipart scan entry is not UTF-8"))?;
            let multipart_id = MultipartUploadId::new(upload_id.clone());
            parse_upload_id(&multipart_id)
                .map_err(|error| JanitorError::new(format!("scan multipart upload: {error}")))?;
            let stage = entry.path();
            let _upload_lock = match acquire_upload_file_lock(&stage).await {
                Ok(lock) => lock,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(janitor_error("lock multipart scan entry", error)),
            };
            if !fs::try_exists(&stage)
                .await
                .map_err(|error| janitor_error("reinspect multipart scan entry", error))?
            {
                continue;
            }
            let binding = match fs::read_to_string(stage.join("key")).await {
                Ok(binding) => binding,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(janitor_error("read multipart scan binding", error)),
            };
            let key = parse_key_binding(&binding)?;
            if self.namespace.authorize(&key).is_err() {
                continue;
            }
            let activity = multipart_activity(&stage).await?;
            if activity.last_modified > cutoff {
                continue;
            }
            let generation = object_generation_for_upload_id(&upload_id);
            self.lock_observations().insert(
                MultipartObservationKey {
                    upload_id: upload_id.clone(),
                    generation,
                },
                MultipartObservation { activity, cutoff },
            );
            candidates.push(CleanupCandidate::new(
                key,
                upload_id,
                CleanupKind::AbandonedMultipart,
                generation,
            ));
        }
        Ok(candidates)
    }

    async fn cleanup(
        &self,
        candidate: &AuthorizedCleanupCandidate,
    ) -> Result<CleanupOutcome, JanitorError> {
        if candidate.kind() != CleanupKind::AbandonedMultipart {
            return Err(JanitorError::new(
                "filesystem multipart janitor received another cleanup kind",
            ));
        }
        let upload_id = MultipartUploadId::new(candidate.id());
        parse_upload_id(&upload_id)
            .map_err(|error| JanitorError::new(format!("clean multipart upload: {error}")))?;
        let generation = object_generation_for_upload_id(upload_id.as_str());
        if generation != candidate.object_generation() {
            return Err(JanitorError::new(
                "multipart cleanup generation does not match upload",
            ));
        }
        let observation_key = MultipartObservationKey {
            upload_id: upload_id.as_str().to_owned(),
            generation,
        };
        let multipart_directory = self.store.root.join(".multipart");
        let stage = self
            .store
            .stage_path(&upload_id)
            .map_err(|error| JanitorError::new(format!("resolve multipart cleanup: {error}")))?;
        if !fs::try_exists(&stage)
            .await
            .map_err(|error| janitor_error("inspect multipart cleanup target", error))?
        {
            sync_directory(&multipart_directory)
                .await
                .map_err(|error| {
                    JanitorError::new(format!("sync completed multipart cleanup: {error}"))
                })?;
            self.forget_observation(&observation_key);
            return Ok(CleanupOutcome::AlreadyClean);
        }
        let upload_lock = match acquire_upload_file_lock(&stage).await {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                sync_directory(&multipart_directory)
                    .await
                    .map_err(|sync_error| {
                        JanitorError::new(format!(
                            "sync raced multipart cleanup after {error}: {sync_error}"
                        ))
                    })?;
                self.forget_observation(&observation_key);
                return Ok(CleanupOutcome::AlreadyClean);
            }
            Err(error) => return Err(janitor_error("lock multipart cleanup target", error)),
        };
        if !fs::try_exists(&stage)
            .await
            .map_err(|error| janitor_error("reinspect multipart cleanup target", error))?
        {
            sync_directory(&multipart_directory)
                .await
                .map_err(|error| {
                    JanitorError::new(format!("sync raced multipart cleanup: {error}"))
                })?;
            self.forget_observation(&observation_key);
            return Ok(CleanupOutcome::AlreadyClean);
        }
        let binding = fs::read_to_string(stage.join("key"))
            .await
            .map_err(|error| janitor_error("read multipart cleanup binding", error))?;
        let current_key = parse_key_binding(&binding)?;
        if &current_key != candidate.key() {
            self.forget_observation(&observation_key);
            return Err(JanitorError::new(
                "multipart cleanup ownership changed after scan",
            ));
        }
        let observation = self
            .lock_observations()
            .get(&observation_key)
            .copied()
            .ok_or_else(|| JanitorError::new("multipart cleanup has no scan observation"))?;
        let current_activity = multipart_activity(&stage).await?;
        if current_activity != observation.activity
            || current_activity.last_modified > observation.cutoff
        {
            self.forget_observation(&observation_key);
            return Err(JanitorError::new(
                "multipart upload became active after the cleanup scan",
            ));
        }
        remove_multipart_stage(&multipart_directory, &stage, upload_lock)
            .await
            .map_err(|error| JanitorError::new(format!("clean multipart upload: {error}")))?;
        self.forget_observation(&observation_key);
        Ok(CleanupOutcome::Cleaned)
    }
}

impl ArtifactObjectStore for FilesystemArtifactStore {
    type Reader = FilesystemArtifactReader;

    async fn open_read(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        expected_generation: ArtifactObjectGeneration,
        expected_metadata: &ArtifactContentMetadata,
        limits: ArtifactReadLimits,
    ) -> Result<Self::Reader, ArtifactObjectError> {
        namespace
            .authorize(key)
            .map_err(|_| ArtifactObjectError::NamespaceDenied)?;
        let Some((metadata, mut reader)) = self.open_committed_data(key).await? else {
            return Err(ArtifactObjectError::NotAvailable);
        };
        if metadata.object_generation() != expected_generation {
            return Err(ArtifactObjectError::GenerationMismatch);
        }
        if metadata.size_bytes != expected_metadata.size_bytes()
            || metadata.checksum != *expected_metadata.checksum()
        {
            return Err(ArtifactObjectError::IntegrityMismatch);
        }
        let (actual_size, actual_checksum) = inspect_reader(&mut reader).await?;
        if actual_size != metadata.size_bytes || actual_checksum != metadata.checksum {
            return Err(ArtifactObjectError::IntegrityMismatch);
        }
        reader
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|error| store_error("rewind verified artifact stream", error))?;
        Ok(FilesystemArtifactReader {
            reader,
            remaining_bytes: metadata.size_bytes,
            max_chunk_bytes: limits.max_chunk_bytes(),
            terminal: false,
        })
    }

    async fn delete_exact(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        expected_generation: ArtifactObjectGeneration,
    ) -> Result<ArtifactDeleteOutcome, ArtifactObjectError> {
        namespace
            .authorize(key)
            .map_err(|_| ArtifactObjectError::NamespaceDenied)?;
        let object = self.object_path(key);
        let preliminary_live = read_optional_commit_metadata(&object).await?;
        if let Some(live_metadata) = preliminary_live {
            if live_metadata.object_generation() != expected_generation {
                return Err(ArtifactObjectError::GenerationMismatch);
            }
        } else if !fs::try_exists(self.deleted_key_path(key))
            .await
            .map_err(|error| store_error("inspect artifact tombstone namespace", error))?
        {
            return Err(ArtifactObjectError::NotAvailable);
        }
        #[cfg(test)]
        self.pause_after_delete_live_read().await;

        let tombstone_parent = self.ensure_tombstone_parent(key).await?;
        let _artifact_lock = acquire_artifact_file_lock(&tombstone_parent)
            .await
            .map_err(|error| store_error("lock artifact object", error))?;
        let live_metadata = read_optional_commit_metadata(&object).await?;
        let Some(live_metadata) = live_metadata else {
            return self.resolve_absent_delete(key, expected_generation).await;
        };
        if live_metadata.object_generation() != expected_generation {
            return Err(ArtifactObjectError::GenerationMismatch);
        }
        let tombstone = self.tombstone_path(key, expected_generation);
        match fs::rename(&object, &tombstone).await {
            Ok(()) => {
                let object_parent = object
                    .parent()
                    .ok_or_else(|| ArtifactStoreError::new("artifact object parent is missing"))?;
                sync_directory(object_parent).await?;
                sync_directory(&tombstone_parent).await?;
                self.compact_tombstone(&tombstone).await?;
                self.prune_tombstones_except(key, expected_generation)
                    .await?;
                Ok(ArtifactDeleteOutcome::Deleted)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::AlreadyExists
                        | io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                let raced_live = read_optional_commit_metadata(&object).await?;
                if let Some(raced_live) = raced_live {
                    if raced_live.object_generation() != expected_generation {
                        return Err(ArtifactObjectError::GenerationMismatch);
                    }
                    if self
                        .exact_tombstone_exists(key, expected_generation)
                        .await?
                    {
                        return Err(ArtifactObjectError::IntegrityMismatch);
                    }
                    return Err(ArtifactObjectError::Store(store_error(
                        "delete exact artifact object",
                        error,
                    )));
                }
                self.resolve_absent_delete(key, expected_generation).await
            }
            Err(error) => Err(ArtifactObjectError::Store(store_error(
                "delete exact artifact object",
                error,
            ))),
        }
    }
}

impl ArtifactMultipartStore for FilesystemArtifactStore {
    async fn begin(&self, key: &ArtifactKey) -> Result<MultipartUploadId, ArtifactStoreError> {
        let upload_id = MultipartUploadId::new(Uuid::now_v7().to_string());
        let task_upload_id = upload_id.clone();
        let store = self.clone();
        let binding = key_binding(key);
        let task = tokio::spawn(async move {
            let stage = store.stage_path(&task_upload_id)?;
            let attempt = async {
                fs::create_dir(&stage)
                    .await
                    .map_err(|error| store_error("create multipart directory", error))?;
                #[cfg(test)]
                store.pause_after_begin_stage_created().await;
                #[cfg(unix)]
                fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700))
                    .await
                    .map_err(|error| store_error("secure multipart directory", error))?;

                let mut binding_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(stage.join("key"))
                    .await
                    .map_err(|error| store_error("create multipart key binding", error))?;
                binding_file
                    .write_all(binding.as_bytes())
                    .await
                    .map_err(|error| store_error("write multipart key binding", error))?;
                binding_file
                    .sync_all()
                    .await
                    .map_err(|error| store_error("sync multipart key binding", error))?;
                let data_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(stage.join("data"))
                    .await
                    .map_err(|error| store_error("create multipart data", error))?;
                data_file
                    .sync_all()
                    .await
                    .map_err(|error| store_error("sync multipart data", error))?;
                let lock_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(stage.join("lock"))
                    .await
                    .map_err(|error| store_error("create multipart lock", error))?;
                lock_file
                    .sync_all()
                    .await
                    .map_err(|error| store_error("sync multipart lock", error))?;
                sync_directory(&stage).await?;
                sync_directory(&store.root.join(".multipart")).await
            }
            .await;
            if let Err(operation) = attempt {
                if fs::try_exists(&stage)
                    .await
                    .map_err(|error| store_error("inspect failed multipart begin", error))?
                {
                    match acquire_upload_file_lock(&stage).await {
                        Ok(upload_lock) => {
                            if let Err(cleanup) = remove_multipart_stage(
                                &store.root.join(".multipart"),
                                &stage,
                                upload_lock,
                            )
                            .await
                            {
                                return Err(ArtifactStoreError::new(format!(
                                    "{operation}; failed multipart begin cleanup: {cleanup}"
                                )));
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(ArtifactStoreError::new(format!(
                                "{operation}; lock failed multipart begin cleanup: {error}"
                            )));
                        }
                    }
                }
                return Err(operation);
            }
            Ok(task_upload_id)
        });
        task.await.map_err(|error| {
            ArtifactStoreError::new(format!("multipart begin task failed: {error}"))
        })?
    }

    async fn append(
        &self,
        upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> Result<(), ArtifactStoreError> {
        let parsed_upload_id = parse_upload_id(upload_id)?;
        let stage = self
            .root
            .join(".multipart")
            .join(parsed_upload_id.to_string());
        let _upload_lock = acquire_upload_file_lock(&stage)
            .await
            .map_err(|error| store_error("lock multipart append", error))?;
        for marker in ["receipt", "receipt.pending"] {
            if fs::try_exists(stage.join(marker))
                .await
                .map_err(|error| store_error("inspect multipart completion marker", error))?
            {
                return Err(ArtifactStoreError::new(
                    "multipart upload is sealed for completion",
                ));
            }
        }
        let mut data = OpenOptions::new()
            .append(true)
            .open(stage.join("data"))
            .await
            .map_err(|error| store_error("open multipart data", error))?;
        data.write_all(&chunk)
            .await
            .map_err(|error| store_error("append multipart data", error))?;
        data.sync_data()
            .await
            .map_err(|error| store_error("sync multipart data", error))
    }

    async fn complete_verified(
        &self,
        upload_id: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError> {
        let parsed_upload_id = parse_upload_id(upload_id)?;
        if receipt.object_generation() != object_generation_for_upload_id(upload_id.as_str()) {
            return Err(ArtifactStoreError::new(
                "multipart completion generation does not match upload",
            ));
        }
        let stage = self.stage_path(upload_id)?;
        let destination = self.object_path(receipt.key());
        let tenant_directory = self
            .root
            .join("objects")
            .join(receipt.key().tenant_id().to_string());
        let session_directory = tenant_directory.join(receipt.key().session_id().to_string());
        let artifact_lock_directory =
            self.ensure_tombstone_parent(receipt.key())
                .await
                .map_err(|error| {
                    ArtifactStoreError::new(format!("prepare artifact object lock: {error}"))
                })?;
        #[cfg(test)]
        {
            let stage_exists = fs::try_exists(&stage)
                .await
                .map_err(|error| store_error("inspect multipart directory", error))?;
            if stage_exists {
                self.pause_after_complete_stage_exists().await;
            }
        }
        let _artifact_lock = acquire_artifact_file_lock(&artifact_lock_directory)
            .await
            .map_err(|error| store_error("lock artifact object", error))?;
        let mut published = false;
        let attempt = async {
            let _upload_lock = acquire_upload_file_lock(&stage)
                .await
                .map_err(|error| store_error("lock multipart completion", error))?;
            if !fs::try_exists(&stage)
                .await
                .map_err(|error| store_error("inspect multipart directory", error))?
            {
                return Err(ArtifactStoreError::new(
                    "multipart upload is not available for completion",
                ));
            }
            let binding = fs::read_to_string(stage.join("key"))
                .await
                .map_err(|error| store_error("read multipart key binding", error))?;
            if binding != key_binding(receipt.key()) {
                return Err(ArtifactStoreError::new(
                    "multipart upload belongs to another artifact",
                ));
            }
            let mut encoded = [0_u8; COMMIT_METADATA_BYTES];
            encoded[..8].copy_from_slice(COMMIT_MAGIC);
            encoded[8..24].copy_from_slice(parsed_upload_id.as_bytes());
            encoded[24..32].copy_from_slice(&receipt.size_bytes().to_be_bytes());
            encoded[32..64].copy_from_slice(receipt.checksum().as_bytes());
            match read_commit_metadata(&stage).await {
                Ok(existing) => {
                    if existing.upload_id != parsed_upload_id
                        || existing.size_bytes != receipt.size_bytes()
                        || existing.checksum != *receipt.checksum()
                    {
                        return Err(ArtifactStoreError::new(
                            "staged artifact receipt conflicts with completion",
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let pending_receipt = stage.join("receipt.pending");
                    let mut metadata_file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&pending_receipt)
                        .await
                        .map_err(|error| store_error("create pending artifact receipt", error))?;
                    #[cfg(test)]
                    self.pause_after_complete_receipt_created().await;
                    metadata_file
                        .write_all(&encoded)
                        .await
                        .map_err(|error| store_error("write artifact receipt", error))?;
                    metadata_file
                        .sync_all()
                        .await
                        .map_err(|error| store_error("sync artifact receipt", error))?;
                    fs::rename(&pending_receipt, stage.join("receipt"))
                        .await
                        .map_err(|error| store_error("publish artifact receipt", error))?;
                }
                Err(error) => return Err(store_error("read staged artifact receipt", error)),
            }
            sync_directory(&stage).await?;

            let (actual_size, actual_checksum) = inspect_data(&stage.join("data")).await?;
            if actual_size != receipt.size_bytes() || actual_checksum != *receipt.checksum() {
                return Err(ArtifactStoreError::new(
                    "multipart completion receipt does not match stored bytes",
                ));
            }
            #[cfg(test)]
            self.pause_after_complete_data_inspection().await;

            for directory in [&tenant_directory, &session_directory] {
                ensure_private_directory(directory, "artifact namespace").await?;
            }
            sync_directory(&tenant_directory).await?;
            sync_directory(&self.root.join("objects")).await?;

            fs::rename(&stage, &destination)
                .await
                .map_err(|error| store_error("commit multipart artifact", error))?;
            published = true;
            #[cfg(test)]
            self.pause_after_complete_rename().await;
            #[cfg(test)]
            if self
                .test_hooks
                .complete_parent_sync_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(ArtifactStoreError::new(
                    "injected post-publish parent sync failure",
                ));
            }
            sync_directory(&session_directory).await?;
            sync_directory(&self.root.join(".multipart")).await
        }
        .await;
        let operation = match attempt {
            Ok(()) => return Ok(()),
            Err(operation) => operation,
        };

        match read_commit_metadata(&destination).await {
            Ok(committed)
                if committed.upload_id == parsed_upload_id
                    && committed.size_bytes == receipt.size_bytes()
                    && committed.checksum == *receipt.checksum()
                    && committed.object_generation() == receipt.object_generation() =>
            {
                #[cfg(test)]
                if self
                    .test_hooks
                    .complete_parent_sync_failures
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok()
                {
                    return Err(ArtifactStoreError::completion_uncertain(
                        "injected completion recovery parent sync failure",
                    ));
                }
                sync_directory(&session_directory).await.map_err(|error| {
                    ArtifactStoreError::completion_uncertain(format!(
                        "reconcile published artifact session directory: {error}"
                    ))
                })?;
                sync_directory(&self.root.join(".multipart"))
                    .await
                    .map_err(|error| {
                        ArtifactStoreError::completion_uncertain(format!(
                            "reconcile published multipart directory: {error}"
                        ))
                    })?;
                Ok(())
            }
            Ok(_) => Err(ArtifactStoreError::new(
                "artifact was already committed by another upload",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !published => Err(operation),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(ArtifactStoreError::completion_uncertain(format!(
                    "published artifact disappeared during completion recovery: {operation}"
                )))
            }
            Err(error) => Err(ArtifactStoreError::completion_uncertain(format!(
                "inspect published artifact during completion recovery: {error}"
            ))),
        }
    }

    async fn abort(&self, upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        let parsed_upload_id = parse_upload_id(upload_id)?;
        let multipart_directory = self.root.join(".multipart");
        let stage = multipart_directory.join(parsed_upload_id.to_string());
        if !fs::try_exists(&stage)
            .await
            .map_err(|error| store_error("inspect multipart abort target", error))?
        {
            return sync_directory(&multipart_directory).await;
        }
        let upload_lock = match acquire_upload_file_lock(&stage).await {
            Ok(upload_lock) => upload_lock,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return sync_directory(&multipart_directory).await;
            }
            Err(error) => return Err(store_error("lock multipart abort", error)),
        };
        remove_multipart_stage(&multipart_directory, &stage, upload_lock).await
    }
}

fn parse_upload_id(upload_id: &MultipartUploadId) -> Result<Uuid, ArtifactStoreError> {
    let parsed = Uuid::parse_str(upload_id.as_str())
        .map_err(|_| ArtifactStoreError::new("multipart upload ID is invalid"))?;
    if parsed.get_version() != Some(uuid::Version::SortRand)
        || parsed.hyphenated().to_string() != upload_id.as_str()
    {
        return Err(ArtifactStoreError::new("multipart upload ID is invalid"));
    }
    Ok(parsed)
}

fn key_binding(key: &ArtifactKey) -> String {
    format!(
        "{}\n{}\n{}\n",
        key.tenant_id(),
        key.session_id(),
        key.artifact_id()
    )
}

fn parse_key_binding(binding: &str) -> Result<ArtifactKey, JanitorError> {
    let mut lines = binding.lines();
    let tenant_id = lines
        .next()
        .ok_or_else(|| JanitorError::new("multipart key binding has no tenant"))
        .and_then(|value| {
            TenantId::from_str(value)
                .map_err(|error| JanitorError::new(format!("parse multipart tenant: {error}")))
        })?;
    let session_id = lines
        .next()
        .ok_or_else(|| JanitorError::new("multipart key binding has no session"))
        .and_then(|value| {
            SessionId::from_str(value)
                .map_err(|error| JanitorError::new(format!("parse multipart session: {error}")))
        })?;
    let artifact_id = lines
        .next()
        .ok_or_else(|| JanitorError::new("multipart key binding has no artifact"))
        .and_then(|value| {
            ArtifactId::from_str(value)
                .map_err(|error| JanitorError::new(format!("parse multipart artifact: {error}")))
        })?;
    if lines.next().is_some() {
        return Err(JanitorError::new(
            "multipart key binding has trailing fields",
        ));
    }
    Ok(ArtifactKey::new(tenant_id, session_id, artifact_id))
}

async fn read_commit_metadata(directory: &Path) -> io::Result<CommitMetadata> {
    let encoded = fs::read(directory.join("receipt")).await?;
    if encoded.len() != COMMIT_METADATA_BYTES || &encoded[..8] != COMMIT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid artifact receipt",
        ));
    }
    let upload_id = Uuid::from_slice(&encoded[8..24])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid upload UUID"))?;
    let size_bytes = u64::from_be_bytes(
        encoded[24..32]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid artifact size"))?,
    );
    let checksum = ArtifactChecksum::new(
        encoded[32..64]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid checksum"))?,
    );
    Ok(CommitMetadata {
        upload_id,
        size_bytes,
        checksum,
    })
}

async fn read_optional_commit_metadata(
    directory: &Path,
) -> Result<Option<CommitMetadata>, ArtifactObjectError> {
    let directory_metadata = match fs::symlink_metadata(directory).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ArtifactObjectError::Store(store_error(
                "inspect artifact object directory",
                error,
            )));
        }
    };
    if !directory_metadata.is_dir() || directory_metadata.file_type().is_symlink() {
        return Err(ArtifactObjectError::IntegrityMismatch);
    }
    #[cfg(test)]
    if let Ok(Some(pause)) = OPTIONAL_METADATA_STAT_PAUSE.try_with(|slot| take_one_shot_pause(slot))
    {
        pause.pause().await;
    }
    match read_commit_metadata(directory).await {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::symlink_metadata(directory).await {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Ok(_) => Err(ArtifactObjectError::IntegrityMismatch),
                Err(error) => Err(ArtifactObjectError::Store(store_error(
                    "reinspect artifact object after missing metadata",
                    error,
                ))),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            Err(ArtifactObjectError::IntegrityMismatch)
        }
        Err(error) => Err(ArtifactObjectError::Store(store_error(
            "read artifact object metadata",
            error,
        ))),
    }
}

async fn ensure_private_directory(
    directory: &Path,
    description: &str,
) -> Result<(), ArtifactStoreError> {
    match fs::create_dir(directory).await {
        Ok(()) => {
            #[cfg(unix)]
            fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|error| store_error(&format!("secure {description}"), error))?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(directory)
                .await
                .map_err(|error| store_error(&format!("inspect {description}"), error))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ArtifactStoreError::new(format!(
                    "{description} must be a real directory"
                )));
            }
        }
        Err(error) => {
            return Err(store_error(&format!("create {description}"), error));
        }
    }
    Ok(())
}

fn encode_generation(generation: ArtifactObjectGeneration) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(ArtifactObjectGeneration::LENGTH * 2);
    for byte in generation.as_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

async fn inspect_data(path: &Path) -> Result<(u64, ArtifactChecksum), ArtifactStoreError> {
    let file = fs::File::open(path)
        .await
        .map_err(|error| store_error("open artifact data for verification", error))?;
    let mut reader = BufReader::new(file);
    inspect_reader(&mut reader).await
}

async fn inspect_reader(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<(u64, ArtifactChecksum), ArtifactStoreError> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut size_bytes = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| store_error("read artifact data for verification", error))?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| ArtifactStoreError::new("artifact size exceeds u64"))?,
            )
            .ok_or_else(|| ArtifactStoreError::new("artifact size exceeds u64"))?;
        hasher.update(&buffer[..read]);
    }
    Ok((size_bytes, ArtifactChecksum::new(hasher.finalize().into())))
}

async fn sync_directory(path: &Path) -> Result<(), ArtifactStoreError> {
    let directory = fs::File::open(path)
        .await
        .map_err(|error| store_error("open artifact directory for sync", error))?;
    directory
        .sync_all()
        .await
        .map_err(|error| store_error("sync artifact directory", error))
}

async fn multipart_activity(stage: &Path) -> Result<MultipartActivity, JanitorError> {
    let mut last_activity = fs::metadata(stage)
        .await
        .and_then(|metadata| metadata.modified())
        .map_err(|error| janitor_error("inspect multipart activity", error))?;
    let mut data_bytes = None;
    let mut receipt_bytes = None;
    let mut pending_receipt_bytes = None;
    for name in ["data", "key", "receipt", "receipt.pending"] {
        let metadata = match fs::metadata(stage.join(name)).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(janitor_error("inspect multipart file activity", error)),
        };
        let modified = metadata
            .modified()
            .map_err(|error| janitor_error("inspect multipart file activity", error))?;
        match name {
            "data" => data_bytes = Some(metadata.len()),
            "receipt" => receipt_bytes = Some(metadata.len()),
            "receipt.pending" => pending_receipt_bytes = Some(metadata.len()),
            _ => {}
        }
        last_activity = last_activity.max(modified);
    }
    Ok(MultipartActivity {
        last_modified: last_activity,
        data_bytes,
        receipt_bytes,
        pending_receipt_bytes,
    })
}

async fn remove_multipart_stage(
    multipart_directory: &Path,
    stage: &Path,
    upload_lock: std::fs::File,
) -> Result<(), ArtifactStoreError> {
    let multipart_directory = multipart_directory.to_path_buf();
    let stage = stage.to_path_buf();
    let cleanup = tokio::task::spawn_blocking(move || {
        let _upload_lock = upload_lock;
        for name in ["data", "key", "receipt", "receipt.pending", "lock"] {
            match std::fs::remove_file(stage.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        match std::fs::remove_dir(stage) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::File::open(multipart_directory)?.sync_all()
    })
    .await
    .map_err(|error| ArtifactStoreError::new(format!("multipart cleanup task failed: {error}")))?;
    cleanup.map_err(|error| store_error("remove multipart stage", error))
}

async fn acquire_upload_file_lock(stage: &Path) -> io::Result<std::fs::File> {
    let lock_path = stage.to_path_buf();
    let lock_file = tokio::task::spawn_blocking(move || std::fs::File::open(lock_path))
        .await
        .map_err(io::Error::other)??;
    #[cfg(test)]
    if let Ok(Some(pause)) =
        OPTIONAL_UPLOAD_LOCK_OPEN_PAUSE.try_with(|slot| take_one_shot_pause(slot))
    {
        pause.pause().await;
    }
    tokio::task::spawn_blocking(move || {
        lock_file.lock()?;
        Ok(lock_file)
    })
    .await
    .map_err(io::Error::other)?
}

async fn acquire_artifact_file_lock(directory: &Path) -> io::Result<std::fs::File> {
    let directory = directory.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let lock_file = std::fs::File::open(directory)?;
        lock_file.lock()?;
        Ok(lock_file)
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(test)]
fn arm_one_shot_pause(slot: &std::sync::Mutex<Option<Arc<OneShotPause>>>) -> Arc<OneShotPause> {
    let pause = Arc::new(OneShotPause::default());
    let mut armed = match slot.lock() {
        Ok(armed) => armed,
        Err(poisoned) => poisoned.into_inner(),
    };
    *armed = Some(Arc::clone(&pause));
    pause
}

#[cfg(test)]
fn take_one_shot_pause(
    slot: &std::sync::Mutex<Option<Arc<OneShotPause>>>,
) -> Option<Arc<OneShotPause>> {
    let mut armed = match slot.lock() {
        Ok(armed) => armed,
        Err(poisoned) => poisoned.into_inner(),
    };
    armed.take()
}

fn store_error(operation: &str, error: io::Error) -> ArtifactStoreError {
    ArtifactStoreError::new(format!("{operation}: {error}"))
}

fn janitor_error(operation: &str, error: io::Error) -> JanitorError {
    JanitorError::new(format!("{operation}: {error}"))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::time::Duration;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use browserd_core::{ArtifactId, SessionId, TenantId};

    use crate::{ArtifactQuota, QuotaLimits, StreamingArtifactWriter};

    use super::*;

    const RACE_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_store() -> (
        tempfile::TempDir,
        FilesystemArtifactStore,
        ArtifactNamespace,
        ArtifactKey,
    ) {
        let directory = tempfile::tempdir().expect("artifact directory should be created");
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("artifact directory should be private");
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let namespace = ArtifactNamespace::new(tenant_id.clone(), session_id.clone());
        let key = ArtifactKey::new(tenant_id, session_id, ArtifactId::new());
        let store = FilesystemArtifactStore::open(directory.path())
            .expect("absolute artifact root should open");
        (directory, store, namespace, key)
    }

    async fn begin_test_upload(
        store: &FilesystemArtifactStore,
        key: &ArtifactKey,
        bytes: Bytes,
    ) -> (MultipartUploadId, ArtifactWriteReceipt) {
        let upload_id = store
            .begin(key)
            .await
            .expect("multipart upload should begin");
        store
            .append(&upload_id, bytes.clone())
            .await
            .expect("multipart bytes should append");
        let size_bytes = u64::try_from(bytes.len()).expect("fixture length should fit u64");
        let receipt = ArtifactWriteReceipt {
            key: key.clone(),
            size_bytes,
            checksum: ArtifactChecksum::new(Sha256::digest(&bytes).into()),
            object_generation: object_generation_for_upload_id(upload_id.as_str()),
        };
        (upload_id, receipt)
    }

    async fn wait_for_pause(pause: &OneShotPause) {
        tokio::time::timeout(RACE_TIMEOUT, pause.wait_until_reached())
            .await
            .expect("racing operation should reach the deterministic pause");
    }

    #[tokio::test]
    async fn delete_loser_that_read_the_live_generation_before_the_winner_is_already_deleted() {
        let (_directory, store, namespace, key) = test_store();
        let (upload_id, receipt) =
            begin_test_upload(&store, &key, Bytes::from_static(b"delete-race")).await;
        store
            .complete_verified(&upload_id, &receipt)
            .await
            .expect("fixture should commit");

        let pause = store.arm_delete_live_read_pause();
        let paused_store = store.clone();
        let paused_namespace = namespace.clone();
        let paused_key = key.clone();
        let generation = receipt.object_generation();
        let paused_delete = tokio::spawn(async move {
            paused_store
                .delete_exact(&paused_namespace, &paused_key, generation)
                .await
        });
        wait_for_pause(&pause).await;

        let winner = tokio::time::timeout(
            RACE_TIMEOUT,
            store.delete_exact(&namespace, &key, generation),
        )
        .await
        .expect("winning delete should not block");
        pause.resume();
        let loser = tokio::time::timeout(RACE_TIMEOUT, paused_delete)
            .await
            .expect("paused delete should finish after resuming")
            .expect("paused delete task should join");

        assert_eq!(winner, Ok(ArtifactDeleteOutcome::Deleted));
        assert_eq!(loser, Ok(ArtifactDeleteOutcome::AlreadyDeleted));
    }

    #[tokio::test]
    async fn same_upload_completion_that_observed_the_stage_before_the_winner_is_idempotent() {
        let (_directory, store, _namespace, key) = test_store();
        let (upload_id, receipt) =
            begin_test_upload(&store, &key, Bytes::from_static(b"complete-race")).await;

        let pause = store.arm_complete_stage_exists_pause();
        let paused_store = store.clone();
        let paused_upload_id = upload_id.clone();
        let paused_receipt = receipt.clone();
        let paused_completion = tokio::spawn(async move {
            paused_store
                .complete_verified(&paused_upload_id, &paused_receipt)
                .await
        });
        wait_for_pause(&pause).await;

        let winner =
            tokio::time::timeout(RACE_TIMEOUT, store.complete_verified(&upload_id, &receipt))
                .await
                .expect("winning completion should not block");
        pause.resume();
        let loser = tokio::time::timeout(RACE_TIMEOUT, paused_completion)
            .await
            .expect("paused completion should finish after resuming")
            .expect("paused completion task should join");

        assert_eq!(winner, Ok(()));
        assert_eq!(loser, Ok(()));
    }

    #[tokio::test]
    async fn append_cannot_mutate_data_after_completion_verification() {
        let (_directory, store, _namespace, key) = test_store();
        let bytes = Bytes::from_static(b"verified-before-race");
        let (upload_id, receipt) = begin_test_upload(&store, &key, bytes.clone()).await;
        let pause = store.arm_complete_data_inspection_pause();
        let completing_store = store.clone();
        let completing_upload_id = upload_id.clone();
        let completing_receipt = receipt.clone();
        let completion = tokio::spawn(async move {
            completing_store
                .complete_verified(&completing_upload_id, &completing_receipt)
                .await
        });
        wait_for_pause(&pause).await;

        let appending_store = store.clone();
        let appending_upload_id = upload_id.clone();
        let mut append = tokio::spawn(async move {
            appending_store
                .append(&appending_upload_id, Bytes::from_static(b"-late"))
                .await
        });
        let early_append = tokio::time::timeout(Duration::from_millis(100), &mut append)
            .await
            .ok()
            .map(|joined| joined.expect("early append task should join"));
        pause.resume();
        let completion = tokio::time::timeout(RACE_TIMEOUT, completion)
            .await
            .expect("completion should finish after resuming")
            .expect("completion task should join");
        let append = match early_append {
            Some(result) => result,
            None => tokio::time::timeout(RACE_TIMEOUT, append)
                .await
                .expect("append should finish after completion")
                .expect("append task should join"),
        };

        assert_eq!(completion, Ok(()));
        assert!(
            append.is_err(),
            "an append racing after verification must not mutate a committed inode"
        );
        let committed = store
            .read_verified(&key)
            .await
            .expect("committed artifact should remain verifiable")
            .expect("committed artifact should exist");
        assert_eq!(committed.bytes(), &bytes);
    }

    #[tokio::test]
    async fn cancelled_completion_after_verification_keeps_the_upload_sealed() {
        let (_directory, store, _namespace, key) = test_store();
        let bytes = Bytes::from_static(b"sealed-completion");
        let (upload_id, receipt) = begin_test_upload(&store, &key, bytes.clone()).await;
        let pause = store.arm_complete_data_inspection_pause();
        let completing_store = store.clone();
        let completing_upload_id = upload_id.clone();
        let completing_receipt = receipt.clone();
        let completion = tokio::spawn(async move {
            completing_store
                .complete_verified(&completing_upload_id, &completing_receipt)
                .await
        });
        wait_for_pause(&pause).await;
        completion.abort();
        assert!(
            completion
                .await
                .expect_err("paused completion should be cancelled")
                .is_cancelled()
        );

        assert!(
            store
                .append(&upload_id, Bytes::from_static(b"-late"))
                .await
                .is_err(),
            "a completion attempt must seal its verified byte sequence"
        );
        store
            .complete_verified(&upload_id, &receipt)
            .await
            .expect("exact completion retry should publish the sealed bytes");
        let committed = store
            .read_verified(&key)
            .await
            .expect("sealed artifact should verify")
            .expect("sealed artifact should exist");
        assert_eq!(committed.bytes(), &bytes);
    }

    #[tokio::test]
    async fn reopened_store_cannot_append_after_another_instance_verifies_completion() {
        let (directory, store, _namespace, key) = test_store();
        let reopened = FilesystemArtifactStore::open(directory.path())
            .expect("same artifact root should reopen");
        let bytes = Bytes::from_static(b"cross-instance-verification");
        let (upload_id, receipt) = begin_test_upload(&store, &key, bytes.clone()).await;
        let pause = store.arm_complete_data_inspection_pause();
        let completing_store = store.clone();
        let completing_upload_id = upload_id.clone();
        let completing_receipt = receipt.clone();
        let completion = tokio::spawn(async move {
            completing_store
                .complete_verified(&completing_upload_id, &completing_receipt)
                .await
        });
        wait_for_pause(&pause).await;

        let appending_upload_id = upload_id.clone();
        let mut append = tokio::spawn(async move {
            reopened
                .append(&appending_upload_id, Bytes::from_static(b"-late"))
                .await
        });
        let early_append = tokio::time::timeout(Duration::from_millis(100), &mut append)
            .await
            .ok()
            .map(|joined| joined.expect("early cross-instance append task should join"));
        pause.resume();
        let completion = tokio::time::timeout(RACE_TIMEOUT, completion)
            .await
            .expect("cross-instance completion should finish")
            .expect("cross-instance completion task should join");
        let append = match early_append {
            Some(result) => result,
            None => tokio::time::timeout(RACE_TIMEOUT, append)
                .await
                .expect("cross-instance append should finish")
                .expect("cross-instance append task should join"),
        };

        assert_eq!(completion, Ok(()));
        assert!(
            append.is_err(),
            "reopened store must share the upload fence"
        );
        let committed = store
            .read_verified(&key)
            .await
            .expect("cross-instance artifact should verify")
            .expect("cross-instance artifact should exist");
        assert_eq!(committed.bytes(), &bytes);
    }

    #[tokio::test]
    async fn cancellation_after_receipt_creation_does_not_poison_exact_completion_retry() {
        let (_directory, store, _namespace, key) = test_store();
        let bytes = Bytes::from_static(b"receipt-cancellation");
        let (upload_id, receipt) = begin_test_upload(&store, &key, bytes.clone()).await;
        let pause = store.arm_complete_receipt_created_pause();
        let completing_store = store.clone();
        let completing_upload_id = upload_id.clone();
        let completing_receipt = receipt.clone();
        let completion = tokio::spawn(async move {
            completing_store
                .complete_verified(&completing_upload_id, &completing_receipt)
                .await
        });
        wait_for_pause(&pause).await;
        completion.abort();
        assert!(
            completion
                .await
                .expect_err("paused completion should be cancelled")
                .is_cancelled()
        );

        store
            .complete_verified(&upload_id, &receipt)
            .await
            .expect("exact completion retry should repair an abandoned pending receipt");
        let committed = store
            .read_verified(&key)
            .await
            .expect("committed artifact should verify")
            .expect("committed artifact should exist");
        assert_eq!(committed.bytes(), &bytes);
    }

    #[tokio::test]
    async fn cancelling_finish_after_publish_keeps_quota_owner_alive_until_commit() {
        let (_directory, store, namespace, key) = test_store();
        let bytes = Bytes::from_static(b"published-before-cancel");
        let byte_count = u64::try_from(bytes.len()).expect("fixture length should fit u64");
        let quota = ArtifactQuota::new(
            namespace,
            QuotaLimits {
                max_committed_bytes: 64,
                max_in_flight_bytes: 64,
            },
        );
        let reservation = quota
            .reserve(key.clone(), 64)
            .await
            .expect("quota reservation should succeed");
        let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
            .await
            .expect("writer should begin");
        writer
            .write_chunk(bytes.clone())
            .await
            .expect("fixture bytes should append");
        let pause = store.arm_complete_rename_pause();
        let finishing = tokio::spawn(async move { writer.finish().await });
        wait_for_pause(&pause).await;
        finishing.abort();
        assert!(
            finishing
                .await
                .expect_err("outer finish task should be cancelled")
                .is_cancelled()
        );
        let while_publish_is_paused = quota.snapshot().await;
        pause.resume();

        assert_eq!(while_publish_is_paused.reserved_bytes, 64);
        assert_eq!(while_publish_is_paused.actual_bytes_in_flight, byte_count);
        tokio::time::timeout(RACE_TIMEOUT, async {
            loop {
                let snapshot = quota.snapshot().await;
                if snapshot.committed_bytes == byte_count {
                    assert_eq!(snapshot.reserved_bytes, 0);
                    assert_eq!(snapshot.actual_bytes_in_flight, 0);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached finish should commit quota after durable publication");
        let committed = store
            .read_verified(&key)
            .await
            .expect("published artifact should verify")
            .expect("published artifact should exist");
        assert_eq!(committed.bytes(), &bytes);
    }

    #[tokio::test]
    async fn post_publish_sync_failure_retries_before_releasing_quota() {
        let (_directory, store, namespace, key) = test_store();
        let bytes = Bytes::from_static(b"durability-retry");
        let byte_count = u64::try_from(bytes.len()).expect("fixture length should fit u64");
        let quota = ArtifactQuota::new(
            namespace,
            QuotaLimits {
                max_committed_bytes: 64,
                max_in_flight_bytes: 64,
            },
        );
        let reservation = quota
            .reserve(key.clone(), 64)
            .await
            .expect("quota reservation should succeed");
        let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
            .await
            .expect("writer should begin");
        writer
            .write_chunk(bytes.clone())
            .await
            .expect("fixture bytes should append");
        store.arm_complete_parent_sync_failures(2);

        let receipt = writer
            .finish()
            .await
            .expect("post-publish uncertainty should retry exact completion");

        assert_eq!(receipt.size_bytes(), byte_count);
        let snapshot = quota.snapshot().await;
        assert_eq!(snapshot.committed_bytes, byte_count);
        assert_eq!(snapshot.reserved_bytes, 0);
        assert_eq!(snapshot.actual_bytes_in_flight, 0);
        let committed = store
            .read_verified(&key)
            .await
            .expect("retried artifact should verify")
            .expect("retried artifact should exist");
        assert_eq!(committed.bytes(), &bytes);
    }

    #[tokio::test]
    async fn delete_loser_paused_between_live_stat_and_receipt_read_is_already_deleted() {
        let (_directory, store, namespace, key) = test_store();
        let (upload_id, receipt) =
            begin_test_upload(&store, &key, Bytes::from_static(b"delete-stat-race")).await;
        store
            .complete_verified(&upload_id, &receipt)
            .await
            .expect("fixture should commit");
        let pause = Arc::new(OneShotPause::default());
        let pause_slot = Arc::new(std::sync::Mutex::new(Some(Arc::clone(&pause))));
        let losing_store = store.clone();
        let losing_namespace = namespace.clone();
        let losing_key = key.clone();
        let generation = receipt.object_generation();
        let loser = tokio::spawn(OPTIONAL_METADATA_STAT_PAUSE.scope(pause_slot, async move {
            losing_store
                .delete_exact(&losing_namespace, &losing_key, generation)
                .await
        }));
        wait_for_pause(&pause).await;

        assert_eq!(
            store.delete_exact(&namespace, &key, generation).await,
            Ok(ArtifactDeleteOutcome::Deleted)
        );
        pause.resume();
        let loser = tokio::time::timeout(RACE_TIMEOUT, loser)
            .await
            .expect("losing delete should finish after resuming")
            .expect("losing delete task should join");
        assert_eq!(loser, Ok(ArtifactDeleteOutcome::AlreadyDeleted));
    }

    #[tokio::test]
    async fn abort_waiter_with_an_open_lock_file_is_idempotent_after_completion_renames_stage() {
        let (_directory, store, _namespace, key) = test_store();
        let (upload_id, receipt) =
            begin_test_upload(&store, &key, Bytes::from_static(b"abort-lock-race")).await;
        let completion_pause = store.arm_complete_data_inspection_pause();
        let completing_store = store.clone();
        let completing_upload_id = upload_id.clone();
        let completion = tokio::spawn(async move {
            completing_store
                .complete_verified(&completing_upload_id, &receipt)
                .await
        });
        wait_for_pause(&completion_pause).await;

        let abort_pause = Arc::new(OneShotPause::default());
        let abort_pause_slot = Arc::new(std::sync::Mutex::new(Some(Arc::clone(&abort_pause))));
        let aborting_store = store.clone();
        let aborting_upload_id = upload_id.clone();
        let abort = tokio::spawn(
            OPTIONAL_UPLOAD_LOCK_OPEN_PAUSE.scope(abort_pause_slot, async move {
                aborting_store.abort(&aborting_upload_id).await
            }),
        );
        wait_for_pause(&abort_pause).await;

        completion_pause.resume();
        assert_eq!(
            tokio::time::timeout(RACE_TIMEOUT, completion)
                .await
                .expect("completion should finish after resuming")
                .expect("completion task should join"),
            Ok(())
        );
        abort_pause.resume();
        assert_eq!(
            tokio::time::timeout(RACE_TIMEOUT, abort)
                .await
                .expect("abort should finish after the winning completion")
                .expect("abort task should join"),
            Ok(())
        );
    }

    #[tokio::test]
    async fn exact_abort_retry_cleans_a_stage_left_without_its_lock_file() {
        let (_directory, store, _namespace, key) = test_store();
        let upload_id = store
            .begin(&key)
            .await
            .expect("multipart upload should begin");
        let stage = store
            .stage_path(&upload_id)
            .expect("fixture upload ID should resolve");
        fs::remove_file(stage.join("lock"))
            .await
            .expect("fixture should model cancellation after lock removal");

        store
            .abort(&upload_id)
            .await
            .expect("exact abort retry should complete cleanup");

        assert!(
            !fs::try_exists(stage)
                .await
                .expect("stage existence should be inspectable"),
            "successful retry must not leave a poisoned multipart stage"
        );
    }

    #[tokio::test]
    async fn cancelling_begin_after_stage_creation_leaves_a_well_formed_janitor_target() {
        let (_directory, store, _namespace, key) = test_store();
        let pause = store.arm_begin_stage_created_pause();
        let beginning_store = store.clone();
        let begin = tokio::spawn(async move { beginning_store.begin(&key).await });
        wait_for_pause(&pause).await;
        begin.abort();
        assert!(
            begin
                .await
                .expect_err("outer begin task should be cancelled")
                .is_cancelled()
        );
        let mut entries = fs::read_dir(store.root.join(".multipart"))
            .await
            .expect("multipart directory should be readable");
        let entry = entries
            .next_entry()
            .await
            .expect("multipart entry should be readable")
            .expect("paused begin should have created a stage");
        let upload_id = MultipartUploadId::new(
            entry
                .file_name()
                .into_string()
                .expect("generated upload ID should be UTF-8"),
        );
        pause.resume();

        tokio::time::timeout(RACE_TIMEOUT, async {
            loop {
                if matches!(fs::try_exists(entry.path().join("key")).await, Ok(true))
                    && matches!(fs::try_exists(entry.path().join("data")).await, Ok(true))
                    && matches!(fs::try_exists(entry.path().join("lock")).await, Ok(true))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached begin transaction should finish after caller cancellation");
        store
            .abort(&upload_id)
            .await
            .expect("well-formed abandoned begin should remain cleanable");
    }

    #[tokio::test]
    async fn repeated_recreation_retains_only_the_latest_tombstone_generation() {
        let (_directory, store, namespace, key) = test_store();
        for bytes in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            let (upload_id, receipt) =
                begin_test_upload(&store, &key, Bytes::copy_from_slice(bytes)).await;
            store
                .complete_verified(&upload_id, &receipt)
                .await
                .expect("fixture generation should commit");
            assert_eq!(
                store
                    .delete_exact(&namespace, &key, receipt.object_generation())
                    .await,
                Ok(ArtifactDeleteOutcome::Deleted)
            );
        }

        let mut entries = fs::read_dir(store.deleted_key_path(&key))
            .await
            .expect("tombstone namespace should be readable");
        let mut generations = 0_usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .expect("tombstone entry should be readable")
        {
            if entry
                .file_type()
                .await
                .expect("tombstone type should be readable")
                .is_dir()
            {
                generations += 1;
            }
        }
        assert_eq!(
            generations, 1,
            "successful key recreation must not retain unbounded generation inodes"
        );
    }

    #[tokio::test]
    async fn paused_stale_delete_cannot_remove_a_recreation_after_tombstone_pruning() {
        let (_directory, store, namespace, key) = test_store();
        let (first_upload, first_receipt) =
            begin_test_upload(&store, &key, Bytes::from_static(b"first")).await;
        store
            .complete_verified(&first_upload, &first_receipt)
            .await
            .expect("first generation should commit");
        let pause = store.arm_delete_live_read_pause();
        let stale_store = store.clone();
        let stale_namespace = namespace.clone();
        let stale_key = key.clone();
        let first_generation = first_receipt.object_generation();
        let stale_delete = tokio::spawn(async move {
            stale_store
                .delete_exact(&stale_namespace, &stale_key, first_generation)
                .await
        });
        wait_for_pause(&pause).await;

        assert_eq!(
            store.delete_exact(&namespace, &key, first_generation).await,
            Ok(ArtifactDeleteOutcome::Deleted)
        );
        let (second_upload, second_receipt) =
            begin_test_upload(&store, &key, Bytes::from_static(b"second")).await;
        store
            .complete_verified(&second_upload, &second_receipt)
            .await
            .expect("second generation should commit");
        assert_eq!(
            store
                .delete_exact(&namespace, &key, second_receipt.object_generation())
                .await,
            Ok(ArtifactDeleteOutcome::Deleted)
        );
        let third_bytes = Bytes::from_static(b"third");
        let (third_upload, third_receipt) =
            begin_test_upload(&store, &key, third_bytes.clone()).await;
        store
            .complete_verified(&third_upload, &third_receipt)
            .await
            .expect("third generation should commit");

        pause.resume();
        assert_eq!(
            tokio::time::timeout(RACE_TIMEOUT, stale_delete)
                .await
                .expect("stale delete should finish after resuming")
                .expect("stale delete task should join"),
            Err(ArtifactObjectError::GenerationMismatch)
        );
        let committed = store
            .read_verified(&key)
            .await
            .expect("third generation should verify")
            .expect("third generation should survive stale delete");
        assert_eq!(committed.bytes(), &third_bytes);
    }

    #[test]
    fn completion_and_abort_sync_the_multipart_parent_after_removing_stage_entries() {
        let source = include_str!("filesystem.rs");
        let completion = source
            .split("    async fn complete_verified(")
            .nth(1)
            .and_then(|tail| tail.split("    async fn abort(").next())
            .expect("completion source");
        let after_publish = completion
            .split("fs::rename(&stage, &destination)")
            .nth(1)
            .expect("completion publish source");
        assert!(
            after_publish.contains("sync_directory(&self.root.join(\".multipart\")).await"),
            "completion must durably remove the source directory entry"
        );
        let abort = source
            .split("    async fn abort(")
            .nth(1)
            .and_then(|tail| tail.split("fn parse_upload_id").next())
            .expect("abort source");
        assert!(
            abort
                .matches("sync_directory(&multipart_directory).await")
                .count()
                >= 2,
            "abort must sync both already-absent and newly-removed stage entries"
        );
    }
}
