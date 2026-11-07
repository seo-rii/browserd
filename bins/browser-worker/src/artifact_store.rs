//! Private filesystem artifacts with durable, conservative aggregate accounting.
//!
//! Charges precede all storage effects and survive restart. Session metadata is
//! separate from immutable durable publication; reopening never restores browser
//! sessions or adopts unpublished objects. Failed cleanup retains its charge.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_artifacts::{
    ArtifactChunkReader, ArtifactContentMetadata, ArtifactContentSource, ArtifactDeleteOutcome,
    ArtifactKey, ArtifactMultipartStore, ArtifactNamespace, ArtifactObjectError,
    ArtifactObjectStore, ArtifactQuota, ArtifactReadLimits, ArtifactStoreError,
    ArtifactWriteReceipt, FilesystemArtifactReader, FilesystemArtifactStore, MultipartUploadId,
    QuotaLimits, StreamingArtifactWriter,
};
use browserd_core::{ArtifactId, NotificationAck, NotificationArtifactState, SessionId, TenantId};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ArtifactPublication, ArtifactReadRequest, ArtifactReadStream, ArtifactScanAttestation,
    ArtifactScanVerdict, ArtifactScannerObservation, ArtifactStoreReceipt, ArtifactStoreRequest,
    DependencyError, GeneratedArtifactRequest, GeneratedArtifactSink,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;

use crate::RoutedArtifactStore;
use crate::artifact_scanner::ArtifactScanner;

mod publications;
mod quarantine;
mod retention;
use browserd_worker::{SystemWorkerClock, WorkerClock};
use publications::{Publications, StagedProvenance, StoredPublication};
pub use quarantine::ArtifactQuarantineConfig;
pub use retention::{ArtifactMaintenanceReport, ArtifactRetentionConfig};

const JOURNAL_HEADER: &[u8] = b"browserd-artifact-quota-v1\n";
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ArtifactStoreConfig {
    pub root: PathBuf,
    pub max_file_bytes: u64,
    pub max_worker_bytes: u64,
    pub max_worker_in_flight_bytes: u64,
    pub max_session_bytes: u64,
    pub max_session_in_flight_bytes: u64,
    pub max_retained_artifacts: usize,
    pub max_operations: usize,
    pub chunk_bytes: usize,
    pub operation_timeout: Duration,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum JournalRecord {
    Charge {
        tenant: TenantId,
        session: SessionId,
        artifact: ArtifactId,
        bytes: u64,
    },
    Resize {
        tenant: TenantId,
        session: SessionId,
        artifact: ArtifactId,
        bytes: u64,
    },
    Release {
        tenant: TenantId,
        session: SessionId,
        artifact: ArtifactId,
    },
}

struct Ledger {
    journal: File,
    journal_bytes: u64,
    healthy: bool,
    charges: HashMap<ArtifactKey, u64>,
    in_flight: HashMap<ArtifactNamespace, u64>,
    discarding: HashSet<ArtifactKey>,
    operations: usize,
    readers: HashMap<ArtifactKey, usize>,
    writers: HashSet<ArtifactKey>,
}

impl Ledger {
    fn append(&mut self, record: &JournalRecord) -> Result<(), DependencyError> {
        if !self.healthy {
            return Err(DependencyError::Unavailable);
        }
        let mut encoded = serde_json::to_vec(record).map_err(|_| DependencyError::Rejected)?;
        encoded.push(b'\n');
        let next = self
            .journal_bytes
            .checked_add(u64::try_from(encoded.len()).map_err(|_| DependencyError::Rejected)?)
            .ok_or(DependencyError::Rejected)?;
        if next > MAX_JOURNAL_BYTES {
            return Err(DependencyError::Rejected);
        }
        if self
            .journal
            .write_all(&encoded)
            .and_then(|()| self.journal.sync_all())
            .is_err()
        {
            self.healthy = false;
            return Err(DependencyError::OutcomeUncertain);
        }
        self.journal_bytes = next;
        Ok(())
    }

    fn release(&mut self, key: &ArtifactKey) -> Result<(), DependencyError> {
        if !self.charges.contains_key(key) {
            return Ok(());
        }
        self.append(&JournalRecord::Release {
            tenant: key.tenant_id().clone(),
            session: key.session_id().clone(),
            artifact: key.artifact_id().clone(),
        })?;
        self.charges.remove(key);
        Ok(())
    }

    fn resize(&mut self, key: &ArtifactKey, actual: u64) -> Result<(), DependencyError> {
        let reserved = self
            .charges
            .get(key)
            .copied()
            .ok_or(DependencyError::Rejected)?;
        if actual > reserved {
            return Err(DependencyError::Rejected);
        }
        if actual == reserved {
            return Ok(());
        }
        self.append(&JournalRecord::Resize {
            tenant: key.tenant_id().clone(),
            session: key.session_id().clone(),
            artifact: key.artifact_id().clone(),
            bytes: actual,
        })?;
        self.charges.insert(key.clone(), actual);
        Ok(())
    }
}

struct ActiveReservation {
    ledger: Arc<Mutex<Ledger>>,
    namespace: ArtifactNamespace,
    bytes: u64,
    key: ArtifactKey,
    writer: bool,
    runtime: Handle,
    root_owner: Arc<File>,
}

impl Drop for ActiveReservation {
    fn drop(&mut self) {
        let namespace = self.namespace.clone();
        let key = self.key.clone();
        let bytes = self.bytes;
        let writer = self.writer;
        let release = move |ledger: &mut Ledger| {
            if let Some(amount) = ledger.in_flight.get_mut(&namespace) {
                *amount = amount.saturating_sub(bytes);
            }
            if writer {
                ledger.writers.remove(&key);
            } else if let Some(readers) = ledger.readers.get_mut(&key) {
                *readers = readers.saturating_sub(1);
                if *readers == 0 {
                    ledger.readers.remove(&key);
                }
            }
            ledger.operations = ledger.operations.saturating_sub(1);
        };
        match self.ledger.try_lock() {
            Ok(mut ledger) => release(&mut ledger),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => release(&mut poisoned.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                let ledger = self.ledger.clone();
                let root = self.root_owner.clone();
                self.runtime.spawn_blocking(move || {
                    let _root = root;
                    release(&mut ledger.lock().unwrap_or_else(|p| p.into_inner()));
                });
            }
        }
    }
}

/// Excludes replacement writes until an exact deletion and its durable release settle.
/// The detached discard task retains this guard even if its caller times out.
struct DiscardOwnership {
    ledger: Arc<Mutex<Ledger>>,
    key: ArtifactKey,
    counted: bool,
    runtime: Handle,
    root_owner: Arc<File>,
}

impl Drop for DiscardOwnership {
    fn drop(&mut self) {
        release_operation(
            &self.ledger,
            &self.runtime,
            &self.root_owner,
            Some(self.key.clone()),
            self.counted,
        );
    }
}

// A caller can hold CP authority while this guard drops. Never wait there for
// another operation's quota fsync; the retained count/root pin owns deferred release.
fn release_operation(
    ledger: &Arc<Mutex<Ledger>>,
    runtime: &Handle,
    root_owner: &Arc<File>,
    key: Option<ArtifactKey>,
    counted: bool,
) {
    let release = move |ledger: &mut Ledger| {
        if let Some(key) = key {
            ledger.discarding.remove(&key);
        }
        if counted {
            ledger.operations = ledger.operations.saturating_sub(1);
        }
    };
    match ledger.try_lock() {
        Ok(mut ledger) => release(&mut ledger),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => release(&mut poisoned.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => {
            let ledger = ledger.clone();
            let root_owner = root_owner.clone();
            runtime.spawn_blocking(move || {
                let _root_owner = root_owner;
                let mut ledger = ledger
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                release(&mut ledger);
            });
        }
    }
}

/// The writer's detached completion/cleanup tasks also retain exclusive root ownership.
#[derive(Clone)]
struct OwnedFilesystem {
    store: FilesystemArtifactStore,
    _root_owner: Arc<File>,
    quarantine: bool,
}

impl ArtifactMultipartStore for OwnedFilesystem {
    async fn begin(&self, key: &ArtifactKey) -> Result<MultipartUploadId, ArtifactStoreError> {
        let owned = self.clone();
        let key = key.clone();
        // The filesystem begin owns another task. Keep the root locked until that
        // task settles even when the caller's timeout cancels this await.
        tokio::spawn(async move {
            let _root_owner = owned._root_owner;
            if owned.quarantine {
                owned.store.begin_quarantine(&key).await
            } else {
                owned.store.begin(&key).await
            }
        })
        .await
        .map_err(|_| ArtifactStoreError::new("owned multipart begin task failed"))?
    }
    async fn append(
        &self,
        upload: &MultipartUploadId,
        bytes: Bytes,
    ) -> Result<(), ArtifactStoreError> {
        let owned = self.clone();
        let upload = upload.clone();
        tokio::spawn(async move {
            let _root_owner = owned._root_owner;
            owned.store.append(&upload, bytes).await
        })
        .await
        .map_err(|_| ArtifactStoreError::new("owned multipart append task failed"))?
    }
    async fn complete_verified(
        &self,
        upload: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError> {
        let owned = self.clone();
        let upload = upload.clone();
        let receipt = receipt.clone();
        tokio::spawn(async move {
            let _root_owner = owned._root_owner;
            if owned.quarantine {
                owned
                    .store
                    .complete_quarantine_verified(&upload, &receipt)
                    .await
            } else {
                owned.store.complete_verified(&upload, &receipt).await
            }
        })
        .await
        .map_err(|_| ArtifactStoreError::new("owned multipart completion task failed"))?
    }
    async fn abort(&self, upload: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        let owned = self.clone();
        let upload = upload.clone();
        tokio::spawn(async move {
            let _root_owner = owned._root_owner;
            owned.store.abort(&upload).await
        })
        .await
        .map_err(|_| ArtifactStoreError::new("owned multipart abort task failed"))?
    }
}

type Writer = StreamingArtifactWriter<OwnedFilesystem>;

struct PendingWrite {
    key: ArtifactKey,
    writer: Writer,
    finishing: bool,
    quarantine: bool,
    _reservation: Option<ActiveReservation>,
}

struct PendingGuard {
    pending: Option<PendingWrite>,
    owner: Arc<Mutex<Vec<PendingWrite>>>,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let mut owner = match self.owner.lock() {
                Ok(owner) => owner,
                Err(poisoned) => poisoned.into_inner(),
            };
            owner.push(pending);
        }
    }
}

struct SharedStore {
    config: ArtifactStoreConfig,
    runtime: Handle,
    filesystem: OwnedFilesystem,
    ledger: Arc<Mutex<Ledger>>,
    pending: Arc<Mutex<Vec<PendingWrite>>>,
    publications: Arc<Mutex<Publications>>,
    retention: Arc<Mutex<retention::Retention>>,
    clock: Arc<dyn WorkerClock>,
    maintenance: Arc<std::sync::atomic::AtomicBool>,
    quarantine: Option<ArtifactQuarantineConfig>,
    quarantine_admissions: Arc<Mutex<HashMap<ArtifactKey, u64>>>,
}

pub struct ProductionArtifactStore {
    shared: Arc<SharedStore>,
    scanner: Option<Arc<dyn ArtifactScanner>>,
}

impl ProductionArtifactStore {
    pub fn open(
        config: ArtifactStoreConfig,
        runtime: Handle,
        scanner: Option<Arc<dyn ArtifactScanner>>,
    ) -> Result<Self, DependencyError> {
        Self::open_with_retention(
            config,
            runtime,
            scanner,
            ArtifactRetentionConfig::default(),
            Arc::new(SystemWorkerClock),
        )
    }
    pub fn open_with_retention(
        config: ArtifactStoreConfig,
        runtime: Handle,
        scanner: Option<Arc<dyn ArtifactScanner>>,
        retention_config: ArtifactRetentionConfig,
        clock: Arc<dyn WorkerClock>,
    ) -> Result<Self, DependencyError> {
        Self::open_with_quarantine(config, runtime, scanner, retention_config, clock, None)
    }
    pub fn open_with_quarantine(
        config: ArtifactStoreConfig,
        runtime: Handle,
        scanner: Option<Arc<dyn ArtifactScanner>>,
        retention_config: ArtifactRetentionConfig,
        clock: Arc<dyn WorkerClock>,
        quarantine: Option<ArtifactQuarantineConfig>,
    ) -> Result<Self, DependencyError> {
        if let Some(policy) = &quarantine {
            policy.validate_against(&config)?;
            if scanner.is_none() {
                return Err(DependencyError::Rejected);
            }
        }
        if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread
            || !config.root.is_absolute()
            || config.max_file_bytes == 0
            || config.max_worker_bytes == 0
            || config.max_worker_in_flight_bytes == 0
            || config.max_session_bytes == 0
            || config.max_session_in_flight_bytes == 0
            || config.max_operations == 0
            || config.max_retained_artifacts == 0
            || config.chunk_bytes == 0
            || config.chunk_bytes > ArtifactReadLimits::MAX_CHUNK_BYTES
            || config.operation_timeout.is_zero()
        {
            return Err(DependencyError::Rejected);
        }
        let metadata =
            fs::symlink_metadata(&config.root).map_err(|_| DependencyError::Unavailable)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        {
            return Err(DependencyError::Rejected);
        }
        let root_owner = Arc::new(
            OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(&config.root)
                .map_err(|_| DependencyError::Unavailable)?,
        );
        let pinned = root_owner
            .metadata()
            .map_err(|_| DependencyError::Unavailable)?;
        if pinned.dev() != metadata.dev() || pinned.ino() != metadata.ino() {
            return Err(DependencyError::Rejected);
        }
        root_owner
            .try_lock()
            .map_err(|_| DependencyError::Rejected)?;
        let mut ledger = open_ledger(&config.root, &root_owner)?;
        let mut publications =
            Publications::open(root_owner.clone(), config.max_retained_artifacts)?;
        let mut retention = retention::Retention::open(
            root_owner.clone(),
            config.max_retained_artifacts,
            retention_config,
        )?;
        retention::clear_temp(&root_owner, "quota.tmp")?;
        retention::clear_temp(&root_owner, "publications.tmp")?;
        let recovery_maximum = config
            .max_retained_artifacts
            .max(ledger.charges.len())
            .max(publications.records().len() + publications.quarantine_records().len())
            .max(retention.quarantine_entries().len());
        validate_retained_tree(&config.root, &ledger.charges, recovery_maximum)?;
        let filesystem = OwnedFilesystem {
            store: FilesystemArtifactStore::open(&config.root)
                .map_err(|_| DependencyError::Unavailable)?,
            _root_owner: root_owner,
            quarantine: false,
        };
        // Published authority must resolve to an exactly charged, verified object on startup.
        for publication in publications.published() {
            if ledger.charges.get(publication.key()) != Some(&publication.metadata().size_bytes()) {
                return Err(DependencyError::Rejected);
            }
            let owned = filesystem.clone();
            let publication = publication.clone();
            let limits = ArtifactReadLimits::new(config.chunk_bytes)
                .map_err(|_| DependencyError::Rejected)?;
            run(&runtime, async move {
                let verifying = tokio::spawn(async move {
                    let _root = owned._root_owner;
                    let reader = owned
                        .store
                        .open_read(
                            &publication.key().namespace(),
                            publication.key(),
                            publication.object_generation(),
                            publication.metadata(),
                            limits,
                        )
                        .await
                        .map_err(|_| DependencyError::Rejected)?;
                    reader.close().await;
                    Ok::<(), DependencyError>(())
                });
                tokio::time::timeout(config.operation_timeout, verifying)
                    .await
                    .map_err(|_| DependencyError::Unavailable)?
                    .map_err(|_| DependencyError::OutcomeUncertain)?
            })??;
        }
        let mut recovery_config = config.clone();
        recovery_config.max_retained_artifacts = recovery_maximum;
        recover_abandoned_writes(
            &recovery_config,
            &runtime,
            &filesystem,
            &mut ledger,
            &retention,
            &publications,
        )?;
        quarantine::recover(
            &recovery_config,
            &runtime,
            &filesystem,
            &mut ledger,
            &mut publications,
            &mut retention,
            clock.now().map_err(|_| DependencyError::Unavailable)?.get(),
        )?;
        retention::recover(
            &config,
            &runtime,
            &filesystem,
            &mut ledger,
            &mut publications,
            &mut retention,
            clock.now().map_err(|_| DependencyError::Unavailable)?.get(),
        )?;
        let quarantine_admissions = retention
            .quarantine_entries()
            .into_iter()
            .filter_map(|entry| {
                let key = entry.key();
                ledger.charges.get(&key).copied().map(|size| (key, size))
            })
            .collect();
        Ok(Self {
            shared: Arc::new(SharedStore {
                config,
                runtime,
                filesystem,
                ledger: Arc::new(Mutex::new(ledger)),
                pending: Arc::new(Mutex::new(Vec::new())),
                publications: Arc::new(Mutex::new(publications)),
                retention: Arc::new(Mutex::new(retention)),
                clock,
                maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                quarantine,
                quarantine_admissions: Arc::new(Mutex::new(quarantine_admissions)),
            }),
            scanner,
        })
    }

    pub fn pending_notifications(
        &self,
        cursor: Option<&str>,
        max_scopes: usize,
        max_descriptors: usize,
    ) -> Result<browserd_worker::WorkerNotificationPage, DependencyError> {
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .pending_notifications(cursor, max_scopes, max_descriptors)
    }

    pub fn acknowledge_notifications(&self, ack: &NotificationAck) -> Result<(), DependencyError> {
        let operation = metadata_operation(&self.shared)?;
        let shared = self.shared.clone();
        let ack = ack.clone();
        run(&self.shared.runtime, async move {
            let timeout = shared.config.operation_timeout;
            let committing = tokio::task::spawn_blocking(move || {
                let _operation = operation;
                let now = retention::now(&shared)?;
                shared
                    .publications
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .acknowledge_notifications(&ack, now)
            });
            tokio::time::timeout(timeout, committing)
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)?
        })?
    }

    /// Exact cleanup only; a failed abort/commit reconciliation remains charged and owned.
    pub fn reconcile_pending(&self) -> Result<usize, DependencyError> {
        let pending = {
            let mut owned = self
                .shared
                .pending
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            std::mem::take(&mut *owned)
        };
        if pending.is_empty() {
            return Ok(0);
        }
        let guards: Vec<_> = pending
            .into_iter()
            .map(|pending| PendingGuard {
                pending: Some(pending),
                owner: self.shared.pending.clone(),
            })
            .collect();
        run(&self.shared.runtime, async {
            let mut completed = 0;
            for mut guard in guards {
                let pending = guard
                    .pending
                    .as_mut()
                    .ok_or(DependencyError::OutcomeUncertain)?;
                if cleanup_write(&self.shared, pending, None).await.is_ok() {
                    guard.pending.take();
                    completed += 1;
                }
            }
            Ok(completed)
        })?
    }

    #[allow(clippy::too_many_arguments)]
    fn begin(
        &self,
        key: ArtifactKey,
        maximum: u64,
        content_type: String,
        source: ArtifactContentSource,
        scan_observation: Option<ArtifactScannerObservation>,
        fence: OwnershipFence,
        origin: String,
        reservation: ActiveReservation,
    ) -> Result<ArtifactSink, DependencyError> {
        let shared = self.shared.clone();
        run(&self.shared.runtime, async move {
            let timeout = shared.config.operation_timeout;
            // The complete begin owns the operation/writer pin. If the caller stops
            // waiting, the eventual unobserved sink drops into the cleanup queue.
            let beginning = tokio::spawn(async move {
                let quota = ArtifactQuota::new(
                    key.namespace(),
                    QuotaLimits {
                        max_committed_bytes: maximum,
                        max_in_flight_bytes: maximum,
                    },
                );
                let local = quota
                    .reserve(key.clone(), maximum)
                    .await
                    .map_err(|_| DependencyError::Rejected)?;
                let writer = StreamingArtifactWriter::begin(local, shared.filesystem.clone())
                    .await
                    .map_err(|_| DependencyError::OutcomeUncertain)?;
                Ok::<_, DependencyError>(ArtifactSink {
                    shared,
                    key,
                    content_type,
                    source,
                    scan_observation,
                    fence,
                    origin,
                    writer: Some(writer),
                    reservation: Some(reservation),
                    finishing: false,
                    receipt: None,
                    aborting: false,
                    aborted: false,
                })
            });
            tokio::time::timeout(timeout, beginning)
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)?
        })?
    }
}

impl RoutedArtifactStore for ProductionArtifactStore {
    fn pending_notifications(
        &self,
        cursor: Option<&str>,
        max_scopes: usize,
        max_descriptors: usize,
    ) -> Result<browserd_worker::WorkerNotificationPage, DependencyError> {
        ProductionArtifactStore::pending_notifications(self, cursor, max_scopes, max_descriptors)
    }
    fn acknowledge_notifications(&self, ack: &NotificationAck) -> Result<(), DependencyError> {
        ProductionArtifactStore::acknowledge_notifications(self, ack)
    }
    fn store(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        if request.expected_size_bytes() > request.max_bytes()
            || request.expected_size_bytes() > self.shared.config.max_file_bytes
        {
            return Err(DependencyError::Rejected);
        }
        if request.source() == ArtifactContentSource::BrowserDownload {
            // Only attributed owner bytes enter this API. Paths, names and CDP
            // event strings never authorize a storage namespace or publication.
            if request.origin() != "browserd-worker-download"
                || u64::try_from(request.bytes().len()).map_err(|_| DependencyError::Rejected)?
                    != request.expected_size_bytes()
                || &Sha256::digest(request.bytes())[..] != request.expected_checksum().as_bytes()
                || ArtifactContentMetadata::new(
                    request.expected_size_bytes(),
                    *request.expected_checksum(),
                    request.declared_content_type(),
                    request.source(),
                    request.origin(),
                )
                .is_err()
            {
                return Err(DependencyError::Rejected);
            }
        }
        if request.source() != ArtifactContentSource::Generated && self.scanner.is_none() {
            return Err(DependencyError::Rejected);
        }
        self.reconcile_pending()?;
        let reservation = reserve(
            &self.shared,
            request.key(),
            request.expected_size_bytes(),
            true,
        )?;
        let scan_observation = match request.source() {
            ArtifactContentSource::Generated => None,
            ArtifactContentSource::ClientUpload | ArtifactContentSource::BrowserDownload => {
                let scanner = self.scanner.as_ref().ok_or(DependencyError::Rejected)?;
                let result = run(&self.shared.runtime, async {
                    tokio::time::timeout(
                        self.shared.config.operation_timeout,
                        scanner.scan_with_observation(request.bytes()),
                    )
                    .await
                    .map_err(|_| DependencyError::Unavailable)?
                })?;
                let rejected_state = if result
                    .as_ref()
                    .is_ok_and(|result| result.verdict == ArtifactScanVerdict::Quarantined)
                {
                    NotificationArtifactState::Quarantined
                } else {
                    NotificationArtifactState::Rejected
                };
                let observed = result
                    .as_ref()
                    .ok()
                    .and_then(|result| result.observation.clone())
                    .filter(|observation| {
                        observation.scanned_size_bytes == request.bytes().len() as u64
                            && observation.scanned_checksum_sha256
                                == <[u8; 32]>::from(Sha256::digest(request.bytes()))
                            && retention::now(&self.shared)
                                .ok()
                                .is_some_and(|now| observation.validate_at(now).is_ok())
                    });
                if result
                    .as_ref()
                    .is_ok_and(|result| result.verdict != ArtifactScanVerdict::Clean)
                    && let Some(observation) = observed.clone()
                    && let Some(admission) = quarantine::admit(&self.shared, request)?
                {
                    quarantine::retain(&self.shared, request, observation, reservation, admission)?;
                    return Err(DependencyError::Rejected);
                }
                let observed = result
                    .ok()
                    .filter(|result| result.verdict == ArtifactScanVerdict::Clean)
                    .and_then(|result| result.observation)
                    .filter(|observation| {
                        observation.scanned_size_bytes == request.bytes().len() as u64
                            && observation.scanned_checksum_sha256
                                == <[u8; 32]>::from(Sha256::digest(request.bytes()))
                            && retention::now(&self.shared)
                                .ok()
                                .is_some_and(|now| observation.validate_at(now).is_ok())
                    });
                if observed.is_none() {
                    persist_rejection(&self.shared, request, rejected_state, reservation)?;
                    return Err(DependencyError::Rejected);
                }
                observed
            }
        };
        let content_type = if request.source() == ArtifactContentSource::Generated {
            request.declared_content_type().to_owned()
        } else {
            "application/octet-stream".to_owned()
        };
        let mut sink = self.begin(
            request.key().clone(),
            request.expected_size_bytes(),
            content_type,
            request.source(),
            scan_observation,
            request.fence().clone(),
            request.origin().to_owned(),
            reservation,
        )?;
        let result = run(&self.shared.runtime, async {
            for chunk in request.bytes().chunks(self.shared.config.chunk_bytes) {
                sink.write_chunk(chunk).await?;
            }
            sink.finish().await
        })?
        .and_then(|receipt| {
            if request.source() == ArtifactContentSource::BrowserDownload
                && (receipt.key() != request.key()
                    || receipt.source() != request.source()
                    || receipt.size_bytes() != request.expected_size_bytes()
                    || receipt.checksum() != request.expected_checksum()
                    || receipt.scan_verdict() != Some(ArtifactScanVerdict::Clean))
            {
                Err(DependencyError::Rejected)
            } else {
                Ok(receipt)
            }
        });
        if result.is_err() {
            let _ = run(&self.shared.runtime, sink.abort());
        }
        result
    }

    fn discard(&self, receipt: &ArtifactStoreReceipt) -> Result<(), DependencyError> {
        self.reconcile_pending()?;
        let key = receipt.key().clone();
        let ownership = exclusive(&self.shared, &key, true)?;
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .permit_delete(&key, Some(receipt.object_generation()))?;
        let shared = self.shared.clone();
        let generation = receipt.object_generation();
        run(&self.shared.runtime, async move {
            let timeout = shared.config.operation_timeout;
            let deleting = tokio::spawn(async move {
                let _ownership = ownership;
                retention::unpinned(&shared, &key, false)?;
                let intent_key = key.clone();
                let now = retention::now(&shared)?;
                retention::durable(&shared, None, move |registry| {
                    registry.intent(&intent_key, generation, now)
                })
                .await?;
                // A timeout stops waiting, not ownership of the filesystem effect.
                // Both guard and root lock outlive detached deletion and release.
                match shared
                    .filesystem
                    .store
                    .delete_exact(&key.namespace(), &key, generation)
                    .await
                {
                    // The backend persists this exact generation's tombstone.
                    // A retry after a detached completion (including restart)
                    // confirms AlreadyDeleted without adopting mere absence.
                    Ok(ArtifactDeleteOutcome::Deleted | ArtifactDeleteOutcome::AlreadyDeleted) => {}
                    Err(
                        ArtifactObjectError::GenerationMismatch
                        | ArtifactObjectError::NamespaceDenied
                        | ArtifactObjectError::NotAvailable,
                    ) => return Err(DependencyError::Rejected),
                    Err(_) => return Err(DependencyError::OutcomeUncertain),
                }
                let publications = shared.publications.clone();
                let retained = shared.retention.clone();
                let ledger = shared.ledger.clone();
                let root_owner = shared.filesystem._root_owner.clone();
                tokio::task::spawn_blocking(move || {
                    let _root_owner = root_owner;
                    ledger
                        .lock()
                        .map_err(|_| DependencyError::Unavailable)?
                        .release(&key)?;
                    publications
                        .try_lock()
                        .map_err(|_| DependencyError::Unavailable)?
                        .deleted(&key, Some(generation), now)?;
                    retained
                        .try_lock()
                        .map_err(|_| DependencyError::Unavailable)?
                        .cleaned(&key, generation, now)?;
                    Ok(())
                })
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
            });
            tokio::time::timeout(timeout, deleting)
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)?
        })?
    }

    fn begin_generated(
        &self,
        request: &GeneratedArtifactRequest,
    ) -> Result<Box<dyn GeneratedArtifactSink>, DependencyError> {
        if request.max_bytes() > self.shared.config.max_file_bytes {
            return Err(DependencyError::Rejected);
        }
        self.reconcile_pending()?;
        let reservation = reserve(&self.shared, request.key(), request.max_bytes(), true)?;
        self.begin(
            request.key().clone(),
            request.max_bytes(),
            request.content_type().to_owned(),
            ArtifactContentSource::Generated,
            None,
            request.fence().clone(),
            request.origin().to_owned(),
            reservation,
        )
        .map(|sink| Box::new(sink) as Box<dyn GeneratedArtifactSink>)
    }

    fn publish_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        publication
            .validate()
            .map_err(|_| DependencyError::Rejected)?;
        let ownership = exclusive(&self.shared, publication.key(), true)?;
        self.shared
            .retention
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .validate_publish(publication, retention::now(&self.shared)?)?;
        {
            let ledger = self
                .shared
                .ledger
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?;
            if ledger.charges.get(publication.key()) != Some(&publication.metadata().size_bytes()) {
                return Err(DependencyError::Rejected);
            }
        }
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .validate_publish(publication)?;
        // The owned verification retains the key/root until the actual FD drains.
        let owned = self.shared.clone();
        let checked = publication.clone();
        let verify_ownership = ownership.clone();
        run(&self.shared.runtime, async move {
            let timeout = owned.config.operation_timeout;
            let task = tokio::spawn(async move {
                let _ownership = verify_ownership;
                let reader = owned
                    .filesystem
                    .store
                    .open_read(
                        &checked.key().namespace(),
                        checked.key(),
                        checked.object_generation(),
                        checked.metadata(),
                        ArtifactReadLimits::new(owned.config.chunk_bytes)
                            .map_err(|_| DependencyError::Rejected)?,
                    )
                    .await
                    .map_err(|_| DependencyError::Rejected)?;
                reader.close().await;
                Ok::<(), DependencyError>(())
            });
            tokio::time::timeout(timeout, task)
                .await
                .map_err(|_| DependencyError::Unavailable)?
                .map_err(|_| DependencyError::OutcomeUncertain)?
        })??;
        write_publication(&self.shared, publication, ownership, false)
    }

    fn withdraw_artifact(&self, publication: &ArtifactPublication) -> Result<(), DependencyError> {
        publication
            .validate()
            .map_err(|_| DependencyError::Rejected)?;
        let ownership = exclusive(&self.shared, publication.key(), true)?;
        write_publication(&self.shared, publication, ownership, true)
    }

    fn get_retained_artifact(
        &self,
        key: &ArtifactKey,
        now: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        let _operation = metadata_operation(&self.shared)?;
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .get(key, now)
    }

    fn list_retained_artifacts(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        after: Option<&ArtifactId>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        let _operation = metadata_operation(&self.shared)?;
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .list(tenant, session, after, limit, now)
    }

    fn open_retained_artifact(
        &self,
        publication: &ArtifactPublication,
        limits: ArtifactReadLimits,
        now: u64,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        publication
            .validate()
            .map_err(|_| DependencyError::Rejected)?;
        if publication.metadata().size_bytes() > self.shared.config.max_file_bytes {
            return Err(DependencyError::Rejected);
        }
        let maximum = limits.max_chunk_bytes().min(self.shared.config.chunk_bytes);
        let reservation = reserve(&self.shared, publication.key(), maximum as u64, false)?;
        let _ownership = exclusive(&self.shared, publication.key(), false)?;
        if self
            .shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .get(publication.key(), now)?
            .as_ref()
            != Some(publication)
        {
            return Err(DependencyError::Rejected);
        }
        let reader = open_owned_reader(
            &self.shared,
            publication.key().clone(),
            publication.object_generation(),
            publication.metadata().clone(),
            maximum,
            reservation,
        )?;
        Ok(Box::new(RetainedReader {
            inner: reader,
            registry: self.shared.publications.clone(),
            publication: publication.clone(),
            opened_at: now,
            elapsed: std::time::Instant::now(),
        }))
    }

    fn open_read(
        &self,
        request: &ArtifactReadRequest,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        if request.metadata().size_bytes() > self.shared.config.max_file_bytes {
            return Err(DependencyError::Rejected);
        }
        let maximum = request
            .limits()
            .max_chunk_bytes()
            .min(self.shared.config.chunk_bytes);
        let reservation = reserve(
            &self.shared,
            request.key(),
            u64::try_from(maximum).map_err(|_| DependencyError::Rejected)?,
            false,
        )?;
        Ok(Box::new(open_owned_reader(
            &self.shared,
            request.key().clone(),
            request.generation(),
            request.metadata().clone(),
            maximum,
            reservation,
        )?))
    }
}

fn open_owned_reader(
    shared: &Arc<SharedStore>,
    key: ArtifactKey,
    generation: browserd_artifacts::ArtifactObjectGeneration,
    metadata: ArtifactContentMetadata,
    maximum: usize,
    reservation: ActiveReservation,
) -> Result<ArtifactReader, DependencyError> {
    let owned = shared.clone();
    run(&shared.runtime, async move {
        let timeout = owned.config.operation_timeout;
        let opening = tokio::spawn(async move {
            let reader = owned
                .filesystem
                .store
                .open_read(
                    &key.namespace(),
                    &key,
                    generation,
                    &metadata,
                    ArtifactReadLimits::new(maximum).map_err(|_| DependencyError::Rejected)?,
                )
                .await
                .map_err(|_| DependencyError::Rejected)?;
            Ok::<_, DependencyError>(ArtifactReader {
                reader: Some(reader),
                runtime: owned.runtime.clone(),
                timeout: owned.config.operation_timeout,
                _reservation: Some(reservation),
                _root_owner: owned.filesystem._root_owner.clone(),
            })
        });
        tokio::time::timeout(timeout, opening)
            .await
            .map_err(|_| DependencyError::Unavailable)?
            .map_err(|_| DependencyError::OutcomeUncertain)?
    })?
}

struct ArtifactReader {
    reader: Option<FilesystemArtifactReader>,
    runtime: Handle,
    timeout: Duration,
    _reservation: Option<ActiveReservation>,
    _root_owner: Arc<File>,
}

impl Drop for ArtifactReader {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            let reservation = self._reservation.take();
            let root = self._root_owner.clone();
            self.runtime.spawn(async move {
                reader.close().await;
                drop(reservation);
                drop(root);
            });
        }
    }
}

impl ArtifactReadStream for ArtifactReader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
        if self.reader.is_none() {
            return Ok(None);
        }
        let chunk = run(&self.runtime, async {
            tokio::time::timeout(
                self.timeout,
                self.reader
                    .as_mut()
                    .ok_or(DependencyError::Rejected)?
                    .next_chunk(),
            )
            .await
            .map_err(|_| DependencyError::Unavailable)?
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|_| DependencyError::Unavailable)
        })??;
        if chunk.is_none() {
            if let Some(reader) = self.reader.take() {
                run(&self.runtime, reader.close())?;
            }
            self._reservation.take();
        }
        Ok(chunk)
    }
}

struct ArtifactSink {
    shared: Arc<SharedStore>,
    key: ArtifactKey,
    content_type: String,
    source: ArtifactContentSource,
    scan_observation: Option<ArtifactScannerObservation>,
    fence: OwnershipFence,
    origin: String,
    writer: Option<Writer>,
    reservation: Option<ActiveReservation>,
    finishing: bool,
    receipt: Option<ArtifactStoreReceipt>,
    aborting: bool,
    aborted: bool,
}

impl Drop for ArtifactSink {
    fn drop(&mut self) {
        if self.receipt.is_some() {
            return;
        }
        if let Some(writer) = self.writer.take() {
            let pending = PendingWrite {
                key: self.key.clone(),
                writer,
                finishing: self.finishing,
                quarantine: false,
                _reservation: self.reservation.take(),
            };
            let mut owned = match self.shared.pending.lock() {
                Ok(owned) => owned,
                Err(poisoned) => poisoned.into_inner(),
            };
            owned.push(pending);
        }
    }
}

#[async_trait]
impl GeneratedArtifactSink for ArtifactSink {
    fn max_chunk_bytes(&self) -> usize {
        self.shared.config.chunk_bytes
    }

    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DependencyError> {
        if self.finishing || self.aborting || chunk.len() > self.shared.config.chunk_bytes {
            return Err(DependencyError::Rejected);
        }
        let writer = self.writer.as_mut().ok_or(DependencyError::Rejected)?;
        tokio::time::timeout(
            self.shared.config.operation_timeout,
            writer.write_chunk(Bytes::copy_from_slice(chunk)),
        )
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)?
        .map_err(|_| DependencyError::Unavailable)
    }

    async fn finish(&mut self) -> Result<ArtifactStoreReceipt, DependencyError> {
        if self.aborting {
            return Err(DependencyError::Rejected);
        }
        if let Some(receipt) = &self.receipt {
            return Ok(receipt.clone());
        }
        self.finishing = true;
        let writer = self.writer.as_mut().ok_or(DependencyError::Rejected)?;
        let written =
            match tokio::time::timeout(self.shared.config.operation_timeout, writer.finish()).await
            {
                Ok(Ok(written)) => written,
                Ok(Err(_)) => {
                    self.finishing = false;
                    return Err(DependencyError::Unavailable);
                }
                Err(_) => return Err(DependencyError::OutcomeUncertain),
            };
        let ledger = self.shared.ledger.clone();
        let root_owner = self.shared.filesystem._root_owner.clone();
        let key = self.key.clone();
        let size = written.size_bytes();
        tokio::task::spawn_blocking(move || {
            let _root_owner = root_owner;
            ledger
                .lock()
                .map_err(|_| DependencyError::Unavailable)?
                .resize(&key, size)
        })
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)??;
        let receipt = match self.source {
            ArtifactContentSource::Generated => ArtifactStoreReceipt::new_generated(
                written.key().clone(),
                written.size_bytes(),
                *written.checksum(),
                self.content_type.clone(),
                written.object_generation(),
            ),
            ArtifactContentSource::ClientUpload => ArtifactStoreReceipt::new(
                written.key().clone(),
                written.size_bytes(),
                *written.checksum(),
                self.content_type.clone(),
                written.object_generation(),
                ArtifactScanVerdict::Clean,
            ),
            ArtifactContentSource::BrowserDownload => ArtifactStoreReceipt::new_browser_download(
                written.key().clone(),
                written.size_bytes(),
                *written.checksum(),
                self.content_type.clone(),
                written.object_generation(),
                ArtifactScanVerdict::Clean,
            ),
        }
        .map_err(|_| DependencyError::Rejected)?;
        let receipt = if self.source != ArtifactContentSource::Generated {
            let attestation = ArtifactScanAttestation::new(
                written.key(),
                &self.fence,
                self.source,
                written.object_generation(),
                written.size_bytes(),
                *written.checksum(),
                self.scan_observation
                    .clone()
                    .ok_or(DependencyError::Rejected)?,
            )
            .map_err(|_| DependencyError::Rejected)?;
            attestation
                .validate_at(retention::now(&self.shared)?)
                .map_err(|_| DependencyError::Rejected)?;
            receipt
                .with_scan_attestation(attestation)
                .map_err(|_| DependencyError::Rejected)?
        } else {
            receipt
        };
        let observed = written.clone();
        let shared = self.shared.clone();
        tokio::task::spawn_blocking(move || {
            let now = retention::now(&shared)?;
            shared
                .retention
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?
                .observe(&observed, now)
        })
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)??;
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .stage(
                self.key.clone(),
                StagedProvenance {
                    fence: self.fence.clone(),
                    metadata: ArtifactContentMetadata::new(
                        receipt.size_bytes(),
                        *receipt.checksum(),
                        receipt.detected_content_type(),
                        receipt.source(),
                        &self.origin,
                    )
                    .map_err(|_| DependencyError::Rejected)?,
                    generation: receipt.object_generation(),
                    scan: receipt.scan_verdict(),
                    scan_attestation: receipt.scan_attestation().cloned(),
                },
            )?;
        self.reservation.take();
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    async fn abort(&mut self) -> Result<(), DependencyError> {
        if self.aborted {
            return Ok(());
        }
        self.shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .permit_delete(
                &self.key,
                self.receipt
                    .as_ref()
                    .map(ArtifactStoreReceipt::object_generation),
            )?;
        self.aborting = true;
        self.receipt = None;
        let writer = self
            .writer
            .take()
            .ok_or(DependencyError::OutcomeUncertain)?;
        let mut guard = PendingGuard {
            pending: Some(PendingWrite {
                key: self.key.clone(),
                writer,
                finishing: self.finishing,
                quarantine: false,
                _reservation: self.reservation.take(),
            }),
            owner: self.shared.pending.clone(),
        };
        let result = cleanup_write(
            &self.shared,
            guard
                .pending
                .as_mut()
                .ok_or(DependencyError::OutcomeUncertain)?,
            None,
        )
        .await;
        let pending = guard
            .pending
            .take()
            .ok_or(DependencyError::OutcomeUncertain)?;
        if result.is_err() {
            self.writer = Some(pending.writer);
            self.reservation = pending._reservation;
            self.finishing = pending.finishing;
        } else {
            self.aborted = true;
        }
        result
    }
}

async fn cleanup_write(
    shared: &SharedStore,
    pending: &mut PendingWrite,
    deadline: Option<std::time::Instant>,
) -> Result<(), DependencyError> {
    if pending.quarantine {
        return quarantine::cleanup_pending(shared, pending, deadline).await;
    }
    retention::check_deadline(deadline)?;
    let ownership = exclusive(shared, &pending.key, pending._reservation.is_none())?;
    retention::unpinned(shared, &pending.key, pending._reservation.is_some())?;
    let mut completed_generation = None;
    shared
        .publications
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?
        .permit_delete(&pending.key, None)?;
    if pending.finishing {
        match tokio::time::timeout(shared.config.operation_timeout, pending.writer.finish()).await {
            Ok(Ok(receipt)) => {
                let generation = receipt.object_generation();
                completed_generation = Some(generation);
                let registry = shared.retention.clone();
                let observed = receipt.clone();
                let key = pending.key.clone();
                let now = retention::now(shared)?;
                let root = shared.filesystem._root_owner.clone();
                tokio::task::spawn_blocking(move || {
                    retention::check_deadline(deadline)?;
                    let _root = root;
                    let mut registry = registry
                        .try_lock()
                        .map_err(|_| DependencyError::Unavailable)?;
                    if !registry.contains(&key) {
                        registry.observe(&observed, now)?;
                    }
                    registry.intent(&key, generation, now)
                })
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)??;
                shared
                    .publications
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .permit_delete(&pending.key, Some(receipt.object_generation()))?;
                let owned = shared.filesystem.clone();
                let delete_ownership = ownership.clone();
                let key = pending.key.clone();
                retention::check_deadline(deadline)?;
                let deleting = tokio::spawn(async move {
                    let _root_owner = owned._root_owner;
                    let _ownership = delete_ownership;
                    owned
                        .store
                        .delete_exact(&key.namespace(), &key, receipt.object_generation())
                        .await
                });
                tokio::time::timeout(shared.config.operation_timeout, deleting)
                    .await
                    .map_err(|_| DependencyError::OutcomeUncertain)?
                    .map_err(|_| DependencyError::OutcomeUncertain)?
                    .map_err(|_| DependencyError::OutcomeUncertain)?;
            }
            Ok(Err(_)) => {
                pending.finishing = false;
                retention::check_deadline(deadline)?;
                tokio::time::timeout(shared.config.operation_timeout, pending.writer.abort())
                    .await
                    .map_err(|_| DependencyError::OutcomeUncertain)?
                    .map_err(|_| DependencyError::OutcomeUncertain)?;
            }
            Err(_) => return Err(DependencyError::OutcomeUncertain),
        }
    } else {
        retention::check_deadline(deadline)?;
        tokio::time::timeout(shared.config.operation_timeout, pending.writer.abort())
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?
            .map_err(|_| DependencyError::OutcomeUncertain)?;
    }
    let ledger = shared.ledger.clone();
    let publications = shared.publications.clone();
    let retained = shared.retention.clone();
    let now = retention::now(shared)?;
    let root_owner = shared.filesystem._root_owner.clone();
    let key = pending.key.clone();
    tokio::task::spawn_blocking(move || {
        retention::check_deadline(deadline)?;
        let _root_owner = root_owner;
        let _ownership = ownership;
        ledger
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .release(&key)?;
        publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .deleted(&key, completed_generation, now)?;
        if let Some(generation) = completed_generation {
            retained
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?
                .cleaned(&key, generation, now)?;
        }
        Ok(())
    })
    .await
    .map_err(|_| DependencyError::OutcomeUncertain)?
}

struct MetadataOperation {
    ledger: Arc<Mutex<Ledger>>,
    runtime: Handle,
    root_owner: Arc<File>,
}
impl Drop for MetadataOperation {
    fn drop(&mut self) {
        release_operation(&self.ledger, &self.runtime, &self.root_owner, None, true);
    }
}
fn metadata_operation(shared: &SharedStore) -> Result<MetadataOperation, DependencyError> {
    let mut ledger = shared
        .ledger
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?;
    retention::validate_quota(&ledger, &shared.filesystem._root_owner)?;
    shared
        .retention
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?
        .healthy()?;
    if !ledger.healthy || ledger.operations >= shared.config.max_operations {
        return Err(DependencyError::Rejected);
    }
    ledger.operations += 1;
    Ok(MetadataOperation {
        ledger: shared.ledger.clone(),
        runtime: shared.runtime.clone(),
        root_owner: shared.filesystem._root_owner.clone(),
    })
}

fn persist_rejection(
    shared: &Arc<SharedStore>,
    request: &ArtifactStoreRequest,
    state: NotificationArtifactState,
    reservation: ActiveReservation,
) -> Result<(), DependencyError> {
    let owned = shared.clone();
    let key = request.key().clone();
    let fence = request.fence().clone();
    run(&shared.runtime, async move {
        let timeout = owned.config.operation_timeout;
        let committing = tokio::task::spawn_blocking(move || {
            // The admitted operation and root pin survive a disconnected caller.
            let _reservation = reservation;
            let now = retention::now(&owned)?;
            let result = owned
                .publications
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)
                .and_then(|mut registry| registry.reject(&key, &fence, state, now));
            // Scanning preceded every filesystem payload effect; release this exact charge.
            let release = owned
                .ledger
                .lock()
                .map_err(|_| DependencyError::Unavailable)?
                .release(&key);
            result?;
            release
        });
        tokio::time::timeout(timeout, committing)
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?
            .map_err(|_| DependencyError::OutcomeUncertain)?
    })?
}

fn write_publication(
    shared: &Arc<SharedStore>,
    publication: &ArtifactPublication,
    ownership: Arc<DiscardOwnership>,
    withdraw: bool,
) -> Result<(), DependencyError> {
    let owned = shared.clone();
    let publication = publication.clone();
    run(&shared.runtime, async move {
        let timeout = owned.config.operation_timeout;
        let writing = tokio::task::spawn_blocking(move || {
            let _ownership = ownership;
            let charged = owned
                .ledger
                .lock()
                .map_err(|_| DependencyError::Unavailable)?
                .charges
                .contains_key(publication.key());
            let mut registry = owned
                .publications
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?;
            let now = retention::now(&owned)?;
            if withdraw {
                registry.ensure_healthy()?;
                let mut retained = owned
                    .retention
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?;
                if registry.record(publication.key()).is_none() {
                    retained.validate_absent_withdraw(&publication, charged, now)?;
                }
                registry.withdraw(&publication, charged, now)?;
                drop(registry);
                if !charged {
                    retained.vacant(&publication, now)
                } else {
                    retained.intent(publication.key(), publication.object_generation(), now)
                }
            } else {
                owned
                    .retention
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .validate_publish(&publication, now)?;
                if registry.validate_publish(&publication)?
                    && let Some(attestation) = publication.scan_attestation()
                {
                    attestation
                        .validate_at(now)
                        .map_err(|_| DependencyError::Rejected)?;
                }
                registry.publish(&publication, now)?;
                drop(registry);
                owned
                    .retention
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .publish(&publication, now)
            }
        });
        tokio::time::timeout(timeout, writing)
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?
            .map_err(|_| DependencyError::OutcomeUncertain)?
    })?
}

struct RetainedReader {
    inner: ArtifactReader,
    registry: Arc<Mutex<Publications>>,
    publication: ArtifactPublication,
    opened_at: u64,
    elapsed: std::time::Instant,
}
impl RetainedReader {
    fn validate_current(&self) -> Result<(), DependencyError> {
        let now = self
            .opened_at
            .checked_add(
                u64::try_from(self.elapsed.elapsed().as_millis())
                    .map_err(|_| DependencyError::Rejected)?,
            )
            .ok_or(DependencyError::Rejected)?;
        if self
            .registry
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .get(self.publication.key(), now)?
            .as_ref()
            != Some(&self.publication)
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
}
impl ArtifactReadStream for RetainedReader {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
        self.validate_current()?;
        let chunk = self.inner.next_chunk()?;
        self.validate_current()?;
        Ok(chunk)
    }
}

fn exclusive(
    shared: &SharedStore,
    key: &ArtifactKey,
    counted: bool,
) -> Result<Arc<DiscardOwnership>, DependencyError> {
    let mut ledger = shared
        .ledger
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?;
    retention::validate_quota(&ledger, &shared.filesystem._root_owner)?;
    shared
        .retention
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?
        .healthy()?;
    if !ledger.healthy
        || (counted && ledger.operations >= shared.config.max_operations)
        || ledger.discarding.contains(key)
    {
        return Err(DependencyError::Rejected);
    }
    ledger.discarding.insert(key.clone());
    if counted {
        ledger.operations += 1;
    }
    Ok(Arc::new(DiscardOwnership {
        ledger: shared.ledger.clone(),
        key: key.clone(),
        counted,
        runtime: shared.runtime.clone(),
        root_owner: shared.filesystem._root_owner.clone(),
    }))
}

fn reserve(
    shared: &SharedStore,
    key: &ArtifactKey,
    bytes: u64,
    new_charge: bool,
) -> Result<ActiveReservation, DependencyError> {
    let namespace = key.namespace();
    let mut ledger = shared
        .ledger
        .lock()
        .map_err(|_| DependencyError::Unavailable)?;
    retention::validate_quota(&ledger, &shared.filesystem._root_owner)?;
    shared
        .retention
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?
        .healthy()?;
    if !ledger.healthy
        || ledger.operations >= shared.config.max_operations
        || ledger.discarding.contains(key)
    {
        return Err(DependencyError::Rejected);
    }
    let worker_flight = ledger
        .in_flight
        .values()
        .try_fold(bytes, |total, value| total.checked_add(*value))
        .ok_or(DependencyError::Rejected)?;
    let session_flight = ledger
        .in_flight
        .get(&namespace)
        .copied()
        .unwrap_or(0)
        .checked_add(bytes)
        .ok_or(DependencyError::Rejected)?;
    if worker_flight > shared.config.max_worker_in_flight_bytes
        || session_flight > shared.config.max_session_in_flight_bytes
    {
        return Err(DependencyError::Rejected);
    }
    if new_charge {
        let registry = shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?;
        registry.ensure_healthy()?;
        if registry.record(key).is_some() || registry.quarantine_record(key).is_some() {
            return Err(DependencyError::Rejected);
        }
        drop(registry);
        shared
            .retention
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .can_admit(key)?;
        if ledger.charges.contains_key(key)
            || ledger.charges.len() >= shared.config.max_retained_artifacts
        {
            return Err(DependencyError::Rejected);
        }
        let worker_total = ledger
            .charges
            .values()
            .try_fold(bytes, |total, value| total.checked_add(*value))
            .ok_or(DependencyError::Rejected)?;
        let session_total = ledger
            .charges
            .iter()
            .filter(|(key, _)| key.namespace() == namespace)
            .try_fold(bytes, |total, (_, value)| total.checked_add(*value))
            .ok_or(DependencyError::Rejected)?;
        if worker_total > shared.config.max_worker_bytes
            || session_total > shared.config.max_session_bytes
        {
            return Err(DependencyError::Rejected);
        }
        ledger.append(&JournalRecord::Charge {
            tenant: key.tenant_id().clone(),
            session: key.session_id().clone(),
            artifact: key.artifact_id().clone(),
            bytes,
        })?;
        ledger.charges.insert(key.clone(), bytes);
    } else if !ledger.charges.contains_key(key) {
        return Err(DependencyError::Rejected);
    }
    ledger.in_flight.insert(namespace.clone(), session_flight);
    ledger.operations += 1;
    if new_charge {
        ledger.writers.insert(key.clone());
    } else {
        *ledger.readers.entry(key.clone()).or_insert(0) += 1;
    }
    Ok(ActiveReservation {
        ledger: shared.ledger.clone(),
        namespace,
        bytes,
        key: key.clone(),
        writer: new_charge,
        runtime: shared.runtime.clone(),
        root_owner: shared.filesystem._root_owner.clone(),
    })
}

fn run<F, T>(runtime: &Handle, future: F) -> Result<T, DependencyError>
where
    F: Future<Output = T> + Send,
    T: Send,
{
    if Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            scope
                .spawn(|| runtime.block_on(future))
                .join()
                .map_err(|_| DependencyError::OutcomeUncertain)
        })
    } else {
        Ok(runtime.block_on(future))
    }
}

fn open_ledger(root: &Path, root_owner: &File) -> Result<Ledger, DependencyError> {
    let path = root.join("quota.journal");
    let mut journal = match OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if fs::read_dir(root)
                .map_err(|_| DependencyError::Unavailable)?
                .next()
                .is_some()
            {
                return Err(DependencyError::Rejected);
            }
            let mut file = OpenOptions::new()
                .read(true)
                .append(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| DependencyError::Unavailable)?;
            file.write_all(JOURNAL_HEADER)
                .and_then(|()| file.sync_all())
                .and_then(|()| root_owner.sync_all())
                .map_err(|_| DependencyError::OutcomeUncertain)?;
            file
        }
        Err(_) => return Err(DependencyError::Unavailable),
    };
    let metadata = journal
        .metadata()
        .map_err(|_| DependencyError::Unavailable)?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_JOURNAL_BYTES
    {
        return Err(DependencyError::Rejected);
    }
    journal
        .seek(SeekFrom::Start(0))
        .map_err(|_| DependencyError::Unavailable)?;
    let mut bytes = Vec::new();
    journal
        .read_to_end(&mut bytes)
        .map_err(|_| DependencyError::Unavailable)?;
    if !bytes.starts_with(JOURNAL_HEADER) || !bytes.ends_with(b"\n") {
        return Err(DependencyError::Rejected);
    }
    let mut charges = HashMap::new();
    for line in bytes[JOURNAL_HEADER.len()..]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice::<JournalRecord>(line)
            .map_err(|_| DependencyError::Rejected)?
        {
            JournalRecord::Charge {
                tenant,
                session,
                artifact,
                bytes,
            } => {
                if charges
                    .insert(ArtifactKey::new(tenant, session, artifact), bytes)
                    .is_some()
                {
                    return Err(DependencyError::Rejected);
                }
            }
            JournalRecord::Resize {
                tenant,
                session,
                artifact,
                bytes,
            } => {
                let value = charges
                    .get_mut(&ArtifactKey::new(tenant, session, artifact))
                    .ok_or(DependencyError::Rejected)?;
                if bytes > *value {
                    return Err(DependencyError::Rejected);
                }
                *value = bytes;
            }
            JournalRecord::Release {
                tenant,
                session,
                artifact,
            } => {
                if charges
                    .remove(&ArtifactKey::new(tenant, session, artifact))
                    .is_none()
                {
                    return Err(DependencyError::Rejected);
                }
            }
        }
    }
    Ok(Ledger {
        journal,
        journal_bytes: metadata.len(),
        healthy: true,
        charges,
        in_flight: HashMap::new(),
        discarding: HashSet::new(),
        operations: 0,
        readers: HashMap::new(),
        writers: HashSet::new(),
    })
}

/// Exclusive root ownership establishes that every remaining multipart writer
/// belongs to an earlier, stopped adapter. The backend validates the immutable
/// upload UUID and removes precisely that stage under its upload lock. Completed
/// objects are retained: live session publication metadata is not reconstructed.
fn recover_abandoned_writes(
    config: &ArtifactStoreConfig,
    runtime: &Handle,
    filesystem: &OwnedFilesystem,
    ledger: &mut Ledger,
    retention: &retention::Retention,
    publications: &Publications,
) -> Result<(), DependencyError> {
    for entry in
        fs::read_dir(config.root.join(".multipart")).map_err(|_| DependencyError::Unavailable)?
    {
        let entry = entry.map_err(|_| DependencyError::Unavailable)?;
        let stage = entry.path();
        let binding = stage.join("key");
        match fs::symlink_metadata(&binding) {
            Ok(_) => {
                let key = read_key_binding(&binding)?;
                if !ledger.charges.contains_key(&key) {
                    return Err(DependencyError::Rejected);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // An interrupted begin can leave an empty directory; interrupted
                // abort deletes data before key/metadata. No unidentified payload
                // may be removed or have its charge released.
                if stage
                    .join("data")
                    .try_exists()
                    .map_err(|_| DependencyError::Unavailable)?
                {
                    return Err(DependencyError::Rejected);
                }
            }
            Err(_) => return Err(DependencyError::Unavailable),
        }
        let upload = MultipartUploadId::new(
            entry
                .file_name()
                .into_string()
                .map_err(|_| DependencyError::Rejected)?,
        );
        run(runtime, async {
            tokio::time::timeout(config.operation_timeout, filesystem.abort(&upload))
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)
        })??;
    }
    let retained =
        validate_retained_tree(&config.root, &ledger.charges, config.max_retained_artifacts)?;
    let released: Vec<_> = ledger
        .charges
        .keys()
        .filter(|key| {
            !retained.contains(*key)
                && !retention.contains(key)
                && publications.record(key).is_none()
                && publications.quarantine_record(key).is_none()
        })
        .cloned()
        .collect();
    for key in released {
        // No old writer can recreate a payload while this root lock is held.
        // The abort's directory sync precedes this durable accounting release.
        ledger.release(&key)?;
    }
    Ok(())
}

fn read_key_binding(path: &Path) -> Result<ArtifactKey, DependencyError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DependencyError::Rejected)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 256 {
        return Err(DependencyError::Rejected);
    }
    let binding = fs::read_to_string(path).map_err(|_| DependencyError::Rejected)?;
    let parts: Vec<_> = binding.lines().collect();
    if parts.len() != 3 {
        return Err(DependencyError::Rejected);
    }
    Ok(ArtifactKey::new(
        parts[0].parse().map_err(|_| DependencyError::Rejected)?,
        parts[1].parse().map_err(|_| DependencyError::Rejected)?,
        parts[2].parse().map_err(|_| DependencyError::Rejected)?,
    ))
}

/// Reject unaccounted payloads and symlinks instead of silently adopting a populated root.
fn validate_retained_tree(
    root: &Path,
    charges: &HashMap<ArtifactKey, u64>,
    maximum_objects: usize,
) -> Result<HashSet<ArtifactKey>, DependencyError> {
    let mut queue = vec![root.to_owned()];
    let mut retained = HashSet::new();
    let mut retained_bytes = HashMap::<ArtifactKey, u64>::new();
    let maximum_entries = maximum_objects
        .checked_mul(16)
        .and_then(|value| value.checked_add(64))
        .ok_or(DependencyError::Rejected)?;
    let mut entries = 0_usize;
    while let Some(directory) = queue.pop() {
        for entry in fs::read_dir(directory).map_err(|_| DependencyError::Unavailable)? {
            let entry = entry.map_err(|_| DependencyError::Unavailable)?;
            entries += 1;
            if entries > maximum_entries {
                return Err(DependencyError::Rejected);
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| DependencyError::Unavailable)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| DependencyError::Rejected)?;
            let components: Vec<_> = relative
                .iter()
                .map(|part| part.to_string_lossy().into_owned())
                .collect();
            if metadata.file_type().is_symlink() || components.len() > 6 {
                return Err(DependencyError::Rejected);
            }
            if components.len() == 1
                && (components[0] == "quota.journal"
                    || components[0] == publications::JOURNAL_NAME
                    || components[0] == "retention.journal")
            {
                continue;
            }
            if !matches!(
                components[0].as_str(),
                "objects" | ".deleted" | ".multipart" | ".quarantine"
            ) {
                return Err(DependencyError::Rejected);
            }
            if metadata.is_dir() {
                if components[0] == ".quarantine" && metadata.mode() & 0o777 != 0o700 {
                    return Err(DependencyError::Rejected);
                }
                if components[0] == "objects" && components.len() == 4 {
                    let key = ArtifactKey::new(
                        components[1]
                            .parse()
                            .map_err(|_| DependencyError::Rejected)?,
                        components[2]
                            .parse()
                            .map_err(|_| DependencyError::Rejected)?,
                        components[3]
                            .parse()
                            .map_err(|_| DependencyError::Rejected)?,
                    );
                    if !charges.contains_key(&key) {
                        return Err(DependencyError::Rejected);
                    }
                    retained.insert(key);
                }
                queue.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(DependencyError::Rejected);
            }
            if components[0] == ".quarantine"
                && (metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1)
            {
                return Err(DependencyError::Rejected);
            }
            if entry.file_name() != "data" {
                if metadata.len() > 4096
                    || !matches!(
                        entry.file_name().to_str(),
                        Some("key" | "receipt" | "receipt.pending" | "lock")
                    )
                {
                    return Err(DependencyError::Rejected);
                }
                continue;
            }
            let key = if components[0] == ".multipart" && components.len() == 3 {
                read_key_binding(&path.with_file_name("key"))?
            } else if (components[0] == "objects" && components.len() == 5)
                || (components[0] == ".deleted" && components.len() == 6)
                || (components[0] == ".quarantine" && components.len() == 6)
            {
                ArtifactKey::new(
                    components[1]
                        .parse()
                        .map_err(|_| DependencyError::Rejected)?,
                    components[2]
                        .parse()
                        .map_err(|_| DependencyError::Rejected)?,
                    components[3]
                        .parse()
                        .map_err(|_| DependencyError::Rejected)?,
                )
            } else {
                return Err(DependencyError::Rejected);
            };
            let total = retained_bytes.entry(key.clone()).or_default();
            *total = total
                .checked_add(metadata.len())
                .ok_or(DependencyError::Rejected)?;
            if charges.get(&key).is_none_or(|charged| *total > *charged) {
                return Err(DependencyError::Rejected);
            }
            retained.insert(key);
        }
    }
    Ok(retained)
}
