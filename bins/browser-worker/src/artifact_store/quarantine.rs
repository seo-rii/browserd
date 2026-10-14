//! Opt-in private nonclean bytes; immutable authority is committed with its notification.
use super::*;
use browserd_artifacts::ArtifactObjectGeneration;
use browserd_core::WorkerId;

const DAY: u64 = 86_400_000;
#[derive(Clone, Debug)]
pub struct ArtifactQuarantineConfig {
    retention: Duration,
    max_file_bytes: u64,
    max_worker_bytes: u64,
    max_session_bytes: u64,
    max_retained_artifacts: usize,
}
impl ArtifactQuarantineConfig {
    pub fn new(
        retention: Duration,
        max_file_bytes: u64,
        max_worker_bytes: u64,
        max_session_bytes: u64,
        max_retained_artifacts: usize,
    ) -> Result<Self, DependencyError> {
        if retention.is_zero()
            || retention > Duration::from_millis(DAY)
            || !retention.subsec_nanos().is_multiple_of(1_000_000)
            || max_file_bytes == 0
            || max_file_bytes > max_worker_bytes
            || max_file_bytes > max_session_bytes
            || max_retained_artifacts == 0
        {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            retention,
            max_file_bytes,
            max_worker_bytes,
            max_session_bytes,
            max_retained_artifacts,
        })
    }
    pub(super) fn validate_against(
        &self,
        config: &ArtifactStoreConfig,
    ) -> Result<(), DependencyError> {
        if self.max_file_bytes > config.max_file_bytes
            || self.max_worker_bytes > config.max_worker_bytes
            || self.max_session_bytes > config.max_session_bytes
            || self.max_retained_artifacts > config.max_retained_artifacts
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Phase {
    Retained,
    DeleteIntent,
    Deleted { at: u64 },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub tenant: TenantId,
    pub session: SessionId,
    pub artifact: ArtifactId,
    pub worker: WorkerId,
    pub epoch: u64,
    pub placement: u64,
    pub incarnation: u64,
    pub generation: [u8; 32],
    pub size: u64,
    pub checksum: [u8; 32],
    pub source: u8,
    pub observation: ArtifactScannerObservation,
    pub admitted_at: u64,
    pub expires_at: u64,
    pub phase: Phase,
}
impl Record {
    pub fn key(&self) -> ArtifactKey {
        ArtifactKey::new(
            self.tenant.clone(),
            self.session.clone(),
            self.artifact.clone(),
        )
    }
    pub fn fence(&self) -> OwnershipFence {
        OwnershipFence::new(
            self.worker.clone(),
            self.epoch,
            self.placement,
            self.incarnation,
        )
    }
    pub fn generation(&self) -> ArtifactObjectGeneration {
        ArtifactObjectGeneration::new(self.generation)
    }
    pub fn matches(&self, receipt: &ArtifactWriteReceipt) -> bool {
        self.key() == *receipt.key()
            && self.generation() == receipt.object_generation()
            && self.size == receipt.size_bytes()
            && self.checksum == *receipt.checksum().as_bytes()
    }
    pub fn validate(&self) -> Result<(), DependencyError> {
        if self.epoch == 0
            || self.placement == 0
            || self.incarnation == 0
            || !matches!(self.source, 1 | 2)
            || self.generation == [0; 32]
            || self.expires_at <= self.admitted_at
            || self.expires_at - self.admitted_at > DAY
            || self.observation.scanned_size_bytes != self.size
            || self.observation.scanned_checksum_sha256 != self.checksum
            || matches!(self.phase, Phase::Deleted { at } if at < self.expires_at)
        {
            return Err(DependencyError::Rejected);
        }
        self.observation
            .validate_at(self.admitted_at)
            .map_err(|_| DependencyError::Rejected)
    }
    pub fn same_object(&self, other: &Self) -> bool {
        let mut copy = other.clone();
        copy.phase = self.phase;
        *self == copy
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    Upsert { record: Record },
    Checkpoint { record: Record },
    Retire { record: Record, before: u64 },
    Watermark { before: u64 },
}

pub(super) struct Admission;
pub(super) fn admit(
    shared: &Arc<SharedStore>,
    request: &ArtifactStoreRequest,
) -> Result<Option<Admission>, DependencyError> {
    let Some(config) = &shared.quarantine else {
        return Ok(None);
    };
    let ledger = shared
        .ledger
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?;
    let registry = shared
        .publications
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?;
    registry.ensure_healthy()?;
    let mut pending = shared
        .quarantine_admissions
        .lock()
        .map_err(|_| DependencyError::Unavailable)?;
    // A sealed orphan still owns private capacity even if its registry append was rejected.
    // Only the positively released durable quota charge permits forgetting this classification.
    pending.retain(|key, _| ledger.charges.contains_key(key));
    let count = pending.len();
    let mut worker = 0u64;
    let mut session = 0u64;
    for (key, size) in pending.iter() {
        worker = worker.checked_add(*size).ok_or(DependencyError::Rejected)?;
        if key.namespace() == request.key().namespace() {
            session = session
                .checked_add(*size)
                .ok_or(DependencyError::Rejected)?;
        }
    }
    let size = request.expected_size_bytes();
    if count >= config.max_retained_artifacts
        || size == 0
        || size > config.max_file_bytes
        || size != request.bytes().len() as u64
        || request.expected_checksum().as_bytes()
            != &<[u8; 32]>::from(Sha256::digest(request.bytes()))
        || worker
            .checked_add(size)
            .is_none_or(|n| n > config.max_worker_bytes)
        || session
            .checked_add(size)
            .is_none_or(|n| n > config.max_session_bytes)
        || pending.contains_key(request.key())
    {
        return Ok(None);
    }
    pending.insert(request.key().clone(), size);
    Ok(Some(Admission))
}

pub(super) fn retain(
    shared: &Arc<SharedStore>,
    request: &ArtifactStoreRequest,
    observation: ArtifactScannerObservation,
    reservation: ActiveReservation,
    admission: Admission,
) -> Result<(), DependencyError> {
    let owned = shared.clone();
    let key = request.key().clone();
    let fence = request.fence().clone();
    let bytes = Bytes::copy_from_slice(request.bytes());
    let source = request.source();
    let duration = shared
        .quarantine
        .as_ref()
        .ok_or(DependencyError::Rejected)?
        .retention;
    run(&shared.runtime, async move {
        let timeout = owned.config.operation_timeout;
        let task = tokio::spawn(async move {
            let _admission = admission;
            let quota = ArtifactQuota::new(
                key.namespace(),
                QuotaLimits {
                    max_committed_bytes: bytes.len() as u64,
                    max_in_flight_bytes: bytes.len() as u64,
                },
            );
            let local = quota
                .reserve(key.clone(), bytes.len() as u64)
                .await
                .map_err(|_| DependencyError::Rejected)?;
            let mut filesystem = owned.filesystem.clone();
            filesystem.quarantine = true;
            let writer = StreamingArtifactWriter::begin(local, filesystem)
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?;
            let mut guard = PendingGuard {
                pending: Some(PendingWrite {
                    key: key.clone(),
                    writer,
                    finishing: false,
                    quarantine: true,
                    _reservation: Some(reservation),
                }),
                owner: owned.pending.clone(),
            };
            let pending = guard
                .pending
                .as_mut()
                .ok_or(DependencyError::OutcomeUncertain)?;
            for chunk in bytes.chunks(owned.config.chunk_bytes) {
                tokio::time::timeout(
                    timeout,
                    pending.writer.write_chunk(Bytes::copy_from_slice(chunk)),
                )
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)?;
            }
            pending.finishing = true;
            let receipt = tokio::time::timeout(timeout, pending.writer.finish())
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)?
                .map_err(|_| DependencyError::OutcomeUncertain)?;
            let now = retention::now(&owned)?;
            let record = Record {
                tenant: key.tenant_id().clone(),
                session: key.session_id().clone(),
                artifact: key.artifact_id().clone(),
                worker: fence.worker_id().clone(),
                epoch: fence.worker_epoch(),
                placement: fence.placement_version(),
                incarnation: fence.session_incarnation(),
                generation: *receipt.object_generation().as_bytes(),
                size: receipt.size_bytes(),
                checksum: *receipt.checksum().as_bytes(),
                source: match source {
                    ArtifactContentSource::ClientUpload => 1,
                    ArtifactContentSource::BrowserDownload => 2,
                    ArtifactContentSource::Generated => return Err(DependencyError::Rejected),
                },
                observation,
                admitted_at: now,
                expires_at: now
                    .checked_add(duration.as_millis() as u64)
                    .ok_or(DependencyError::Rejected)?,
                phase: Phase::Retained,
            };
            let authority = record.clone();
            let registry = owned.publications.clone();
            let root = owned.filesystem._root_owner.clone();
            tokio::task::spawn_blocking(move || {
                let _root = root;
                registry
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .retain_quarantine(authority, now)
            })
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)??;
            let due = record.expires_at;
            retention::durable(&owned, None, move |r| {
                r.observe_quarantine(&receipt, now, due)
            })
            .await?;
            guard.pending.take();
            Ok(())
        });
        tokio::time::timeout(timeout, task)
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?
            .map_err(|_| DependencyError::OutcomeUncertain)?
    })?
}

pub(super) async fn cleanup_pending(
    shared: &SharedStore,
    pending: &mut PendingWrite,
    deadline: Option<std::time::Instant>,
) -> Result<(), DependencyError> {
    retention::check_deadline(deadline)?;
    shared
        .publications
        .try_lock()
        .map_err(|_| DependencyError::Unavailable)?
        .ensure_healthy()?;
    if pending.finishing {
        match tokio::time::timeout(shared.config.operation_timeout, pending.writer.finish()).await {
            Ok(Ok(receipt)) => {
                let authority = shared
                    .publications
                    .try_lock()
                    .map_err(|_| DependencyError::Unavailable)?
                    .quarantine_record(&pending.key);
                let now = retention::now(shared)?;
                let due = if let Some(record) = authority {
                    if !record.matches(&receipt) {
                        return Err(DependencyError::Rejected);
                    }
                    record.expires_at
                } else {
                    now.checked_add(
                        shared
                            .retention
                            .try_lock()
                            .map_err(|_| DependencyError::Unavailable)?
                            .config
                            .orphan_grace
                            .as_millis() as u64,
                    )
                    .ok_or(DependencyError::Rejected)?
                };
                let registry = shared.retention.clone();
                let root = shared.filesystem._root_owner.clone();
                tokio::task::spawn_blocking(move || {
                    let _root = root;
                    retention::check_deadline(deadline)?;
                    registry
                        .try_lock()
                        .map_err(|_| DependencyError::Unavailable)?
                        .observe_quarantine(&receipt, now, due)
                })
                .await
                .map_err(|_| DependencyError::OutcomeUncertain)??;
                return Ok(());
            }
            Ok(Err(_)) | Err(_) => return Err(DependencyError::OutcomeUncertain),
        }
    }
    tokio::time::timeout(shared.config.operation_timeout, pending.writer.abort())
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)?
        .map_err(|_| DependencyError::OutcomeUncertain)?;
    let ledger = shared.ledger.clone();
    let key = pending.key.clone();
    let root = shared.filesystem._root_owner.clone();
    tokio::task::spawn_blocking(move || {
        let _root = root;
        retention::check_deadline(deadline)?;
        ledger
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .release(&key)
    })
    .await
    .map_err(|_| DependencyError::OutcomeUncertain)?
}

pub(super) async fn sweep(
    shared: &Arc<SharedStore>,
    entry: retention::Entry,
    now: u64,
    deadline: std::time::Instant,
) -> Result<bool, DependencyError> {
    retention::check_deadline(Some(deadline))?;
    let key = entry.key();
    let generation = entry.generation();
    let _ownership = exclusive(shared, &key, true)?;
    retention::unpinned(shared, &key, false)?;
    let authority = {
        let registry = shared
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?;
        registry.quarantine_unpinned(&key)?;
        registry.quarantine_record(&key)
    };
    if let Some(record) = &authority {
        if record.generation() != generation {
            return Err(DependencyError::Rejected);
        }
        if now < record.expires_at {
            return Err(DependencyError::Unavailable);
        }
    }
    if matches!(
        entry.phase,
        retention::Phase::Cleaned { .. } | retention::Phase::Retired | retention::Phase::Vacant
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
        let retire_key = key.clone();
        retention::durable(shared, Some(deadline), move |r| {
            r.retire(&retire_key, generation, now)
        })
        .await?;
        shared
            .filesystem
            .store
            .prune_quarantine_delete_receipt(&key.namespace(), &key, generation)
            .await
            .map_err(|_| DependencyError::OutcomeUncertain)?;
        let registry = shared.publications.clone();
        let retired_key = key.clone();
        let root = shared.filesystem._root_owner.clone();
        tokio::task::spawn_blocking(move || {
            let _root = root;
            retention::check_deadline(Some(deadline))?;
            registry
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?
                .retire_quarantine(&retired_key, generation, now)
        })
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)??;
        retention::durable(shared, Some(deadline), move |r| r.forget(&key, generation)).await?;
        return Ok(true);
    }
    if let Some(mut record) = authority
        && record.phase == Phase::Retained
    {
        record.phase = Phase::DeleteIntent;
        let registry = shared.publications.clone();
        let root = shared.filesystem._root_owner.clone();
        tokio::task::spawn_blocking(move || {
            let _root = root;
            retention::check_deadline(Some(deadline))?;
            registry
                .try_lock()
                .map_err(|_| DependencyError::Unavailable)?
                .update_quarantine(record, now)
        })
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)??;
    }
    let intent_key = key.clone();
    retention::durable(shared, Some(deadline), move |r| {
        r.intent(&intent_key, generation, now)
    })
    .await?;
    retention::check_deadline(Some(deadline))?;
    shared
        .filesystem
        .store
        .delete_quarantine_exact(&key.namespace(), &key, generation)
        .await
        .map_err(|_| DependencyError::OutcomeUncertain)?;
    let owned = shared.clone();
    let released_key = key.clone();
    tokio::task::spawn_blocking(move || {
        retention::check_deadline(Some(deadline))?;
        let mut registry = owned
            .publications
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if let Some(mut record) = registry.quarantine_record(&released_key) {
            if record.generation() != generation {
                return Err(DependencyError::Rejected);
            }
            record.phase = Phase::Deleted { at: now };
            registry.update_quarantine(record, now)?;
        }
        drop(registry);
        owned
            .ledger
            .try_lock()
            .map_err(|_| DependencyError::Unavailable)?
            .release(&released_key)
    })
    .await
    .map_err(|_| DependencyError::OutcomeUncertain)??;
    retention::durable(shared, Some(deadline), move |r| {
        r.cleaned(&key, generation, now)
    })
    .await?;
    Ok(false)
}

pub(super) fn recover(
    config: &ArtifactStoreConfig,
    runtime: &Handle,
    filesystem: &OwnedFilesystem,
    ledger: &mut Ledger,
    publications: &mut Publications,
    retained: &mut retention::Retention,
    now: u64,
) -> Result<(), DependencyError> {
    // Retired durable authority permits finishing an interrupted marker prune, never quota release.
    for entry in retained
        .quarantine_entries()
        .into_iter()
        .filter(|e| e.phase == retention::Phase::Retired)
    {
        let key = entry.key();
        let generation = entry.generation();
        if ledger.charges.contains_key(&key) {
            return Err(DependencyError::Rejected);
        }
        let store = filesystem.store.clone();
        let owned_key = key.clone();
        run(runtime, async move {
            store
                .prune_quarantine_delete_receipt(&owned_key.namespace(), &owned_key, generation)
                .await
        })?
        .map_err(|_| DependencyError::Rejected)?;
        publications.retire_quarantine(&key, generation, now)?;
        retained.forget(&key, generation)?;
    }
    let store = filesystem.store.clone();
    let maximum = config.max_retained_artifacts;
    let inventory = run(
        runtime,
        async move { store.quarantine_inventory(maximum).await },
    )?
    .map_err(|_| DependencyError::Rejected)?;
    let mut seen = HashSet::new();
    for (receipt, deleted) in inventory {
        let key = receipt.key().clone();
        let generation = receipt.object_generation();
        if !seen.insert(key.clone()) {
            return Err(DependencyError::Rejected);
        }
        let authority = publications.quarantine_record(&key);
        if let Some(record) = &authority {
            record.validate()?;
            if !record.matches(&receipt) {
                return Err(DependencyError::Rejected);
            }
            if !deleted && matches!(record.phase, Phase::Deleted { .. }) {
                return Err(DependencyError::Rejected);
            }
            if deleted && record.phase == Phase::Retained {
                return Err(DependencyError::Rejected);
            }
        }
        if !deleted {
            if ledger.charges.get(&key) != Some(&receipt.size_bytes()) {
                return Err(DependencyError::Rejected);
            }
            let due = authority.as_ref().map_or_else(
                || now.saturating_add(retained.config.orphan_grace.as_millis() as u64),
                |r| r.expires_at,
            );
            retained.observe_quarantine(&receipt, now, due)?;
            continue;
        }
        publications.quarantine_unpinned(&key)?;
        let store = filesystem.store.clone();
        let delete_key = key.clone();
        run(runtime, async move {
            store
                .delete_quarantine_exact(&delete_key.namespace(), &delete_key, generation)
                .await
        })?
        .map_err(|_| DependencyError::Rejected)?;
        if let Some(mut record) = authority {
            let at = match record.phase {
                Phase::Deleted { at } => at,
                _ => now,
            };
            record.phase = Phase::Deleted { at };
            publications.update_quarantine(record, now)?;
        }
        if !retained.contains(&key) {
            retained.observe_quarantine(&receipt, now, now)?;
        }
        retained.intent(&key, generation, now)?;
        ledger.release(&key)?;
        retained.cleaned(&key, generation, now)?;
    }
    for record in publications.quarantine_records() {
        if !seen.contains(&record.key()) {
            return Err(DependencyError::Rejected);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use browserd_session::SessionTime;
    use browserd_worker::WorkerError;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Clock(AtomicU64);
    impl WorkerClock for Clock {
        fn now(&self) -> Result<SessionTime, WorkerError> {
            Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
        }
    }
    struct Harness {
        root: tempfile::TempDir,
        runtime: tokio::runtime::Runtime,
        clock: Arc<Clock>,
    }
    impl Harness {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("private root");
            Self {
                root,
                runtime: tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("runtime"),
                clock: Arc::new(Clock(AtomicU64::new(1000))),
            }
        }
        fn open(&self) -> ProductionArtifactStore {
            ProductionArtifactStore::open_with_retention(
                ArtifactStoreConfig {
                    root: self.root.path().to_owned(),
                    max_file_bytes: 16,
                    max_worker_bytes: 64,
                    max_worker_in_flight_bytes: 16,
                    max_session_bytes: 64,
                    max_session_in_flight_bytes: 16,
                    max_retained_artifacts: 16,
                    max_operations: 4,
                    chunk_bytes: 4,
                    operation_timeout: Duration::from_secs(2),
                },
                self.runtime.handle().clone(),
                None,
                retention::ArtifactRetentionConfig {
                    orphan_grace: Duration::from_millis(100),
                    cleaned_retry: Duration::from_millis(DAY),
                    compact_at_bytes: 1,
                },
                self.clock.clone(),
            )
            .expect("store")
        }
        fn request(&self, tenant: TenantId, session: SessionId) -> ArtifactStoreRequest {
            ArtifactStoreRequest::new(
                tenant,
                session,
                ArtifactId::new(),
                OwnershipFence::new(
                    WorkerId::new("quarantine-boundary").expect("worker"),
                    1,
                    2,
                    3,
                ),
                b"found".to_vec(),
                "text/plain",
                16,
            )
            .expect("request")
        }
        fn seal(
            &self,
            store: &ProductionArtifactStore,
            request: &ArtifactStoreRequest,
        ) -> ArtifactWriteReceipt {
            let mut filesystem = store.shared.filesystem.clone();
            filesystem.quarantine = true;
            let key = request.key().clone();
            let bytes = Bytes::copy_from_slice(request.bytes());
            self.runtime.block_on(async move {
                let quota = ArtifactQuota::new(
                    key.namespace(),
                    QuotaLimits {
                        max_committed_bytes: 16,
                        max_in_flight_bytes: 16,
                    },
                );
                let local = quota
                    .reserve(key, bytes.len() as u64)
                    .await
                    .expect("local quota");
                let mut writer = StreamingArtifactWriter::begin(local, filesystem)
                    .await
                    .expect("private begin");
                writer.write_chunk(bytes).await.expect("write");
                writer.finish().await.expect("durable private seal")
            })
        }
        fn observation(&self, bytes: &[u8]) -> ArtifactScannerObservation {
            ArtifactScannerObservation {
                schema_version: 1,
                program_version: "boundary-fixture".to_owned(),
                database_version: 1,
                database_built_at_unix_millis: 1000,
                observed_before_unix_millis: 1000,
                observed_after_unix_millis: 1000,
                expected_peer_uid: 1000,
                peer_uid: 1000,
                version_metadata_sha256: [7; 32],
                scanned_size_bytes: bytes.len() as u64,
                scanned_checksum_sha256: Sha256::digest(bytes).into(),
                max_database_age_millis: 500,
                max_future_skew_millis: 0,
            }
        }
        fn record(&self, request: &ArtifactStoreRequest, receipt: &ArtifactWriteReceipt) -> Record {
            Record {
                tenant: request.key().tenant_id().clone(),
                session: request.key().session_id().clone(),
                artifact: request.key().artifact_id().clone(),
                worker: request.fence().worker_id().clone(),
                epoch: 1,
                placement: 2,
                incarnation: 3,
                generation: *receipt.object_generation().as_bytes(),
                size: receipt.size_bytes(),
                checksum: *receipt.checksum().as_bytes(),
                source: 1,
                observation: self.observation(request.bytes()),
                admitted_at: 1000,
                expires_at: 1100,
                phase: Phase::Retained,
            }
        }
    }

    #[test]
    fn sealed_without_registry_is_charged_private_orphan_and_recovered_without_public_adoption() {
        let harness = Harness::new();
        let store = harness.open();
        let request = harness.request(TenantId::new(), SessionId::new());
        let reservation =
            reserve(&store.shared, request.key(), 5, true).expect("durable charge first");
        let receipt = harness.seal(&store, &request);
        drop(reservation);
        drop(store);
        let reopened = harness.open();
        assert_eq!(
            reopened
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .get(request.key()),
            Some(&5)
        );
        assert_eq!(
            reopened
                .shared
                .quarantine_admissions
                .lock()
                .expect("private accounting")
                .get(request.key()),
            Some(&5)
        );
        assert!(
            reopened
                .pending_notifications(None, 32, 8)
                .expect("no invented event")
                .commits
                .is_empty()
        );
        assert!(
            reopened
                .get_retained_artifact(request.key(), 1000)
                .expect("public lookup")
                .is_none()
        );
        harness.clock.0.store(1101, Ordering::SeqCst);
        assert_eq!(
            reopened.maintain(1).expect("orphan grace cleanup").cleaned,
            1
        );
        assert!(
            !reopened
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .contains_key(request.key())
        );
        assert!(
            harness
                .runtime
                .block_on(reopened.shared.filesystem.store.inspect_quarantine(
                    &request.key().namespace(),
                    request.key(),
                    receipt.object_generation()
                ))
                .expect("positive tombstone")
                .expect("proof")
                .1
        );
    }

    #[test]
    fn durable_authority_before_cleanup_index_recovers_old_scan_and_ack_then_releases_charge() {
        let harness = Harness::new();
        let store = harness.open();
        let request = harness.request(TenantId::new(), SessionId::new());
        let reservation = reserve(&store.shared, request.key(), 5, true).expect("charge");
        let receipt = harness.seal(&store, &request);
        store
            .shared
            .publications
            .lock()
            .expect("registry")
            .retain_quarantine(harness.record(&request, &receipt), 1000)
            .expect("atomic authority plus notification");
        let commit = store
            .pending_notifications(None, 32, 8)
            .expect("notification")
            .commits[0]
            .clone();
        assert!(
            store
                .shared
                .retention
                .lock()
                .expect("retention")
                .quarantine_entries()
                .is_empty()
        );
        drop(reservation);
        drop(store);
        harness.clock.0.store(3000, Ordering::SeqCst);
        let reopened = harness.open();
        assert_eq!(
            reopened
                .pending_notifications(None, 32, 8)
                .expect("stable pending")
                .commits,
            vec![commit.clone()]
        );
        assert_eq!(
            reopened
                .maintain(1)
                .expect("pending ACK pins expired bytes")
                .cleaned,
            0
        );
        reopened
            .acknowledge_notifications(&commit.ack())
            .expect("durable ACK");
        // The bounded maintenance cursor finishes its current pass before revisiting
        // the entry that was pinned on the preceding tick.
        let continuation = reopened
            .maintain(1)
            .expect("finish the current cursor pass");
        assert_eq!(continuation.scanned, 0);
        assert_eq!(continuation.cleaned, 0);
        assert_eq!(
            reopened
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .get(request.key()),
            Some(&5)
        );
        assert_eq!(reopened.maintain(1).expect("positive cleanup").cleaned, 1);
        assert!(
            !reopened
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .contains_key(request.key())
        );
        drop(reopened);
        let again = harness.open();
        again
            .acknowledge_notifications(&commit.ack())
            .expect("lost ACK reply exact retry");
        assert!(matches!(
            again
                .shared
                .publications
                .lock()
                .expect("registry")
                .quarantine_record(request.key())
                .expect("private terminal authority")
                .phase,
            Phase::Deleted { .. }
        ));
    }

    #[test]
    fn private_seal_with_failed_authority_append_keeps_its_capacity_until_positive_delete() {
        let harness = Harness::new();
        let mut store = harness.open();
        Arc::get_mut(&mut store.shared)
            .expect("exclusive fixture")
            .quarantine = Some(
            ArtifactQuarantineConfig::new(Duration::from_millis(100), 5, 5, 5, 1)
                .expect("private caps"),
        );
        let tenant = TenantId::new();
        let session = SessionId::new();
        let first = harness.request(tenant.clone(), session.clone());
        let reservation =
            reserve(&store.shared, first.key(), 5, true).expect("charge before private admission");
        let admission = admit(&store.shared, &first)
            .expect("private admission")
            .expect("allowed");
        let held = store
            .shared
            .publications
            .lock()
            .expect("healthy registry blocked by another metadata operation");
        assert_eq!(
            retain(
                &store.shared,
                &first,
                harness.observation(first.bytes()),
                reservation,
                admission
            ),
            Err(DependencyError::Unavailable)
        );
        drop(held);
        assert!(
            store
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .writers
                .contains(first.key())
        );
        store
            .reconcile_pending()
            .expect("sealed orphan cleanup scheduling");
        assert_eq!(
            store
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .get(first.key()),
            Some(&5)
        );
        let second = harness.request(tenant, session);
        let second_reservation =
            reserve(&store.shared, second.key(), 5, true).expect("general caps still available");
        assert!(
            admit(&store.shared, &second)
                .expect("healthy private preflight")
                .is_none()
        );
        harness.clock.0.store(1101, Ordering::SeqCst);
        assert_eq!(
            store
                .maintain(1)
                .expect("positive private orphan cleanup")
                .cleaned,
            1
        );
        assert!(
            admit(&store.shared, &second)
                .expect("positive deletion reopens private capacity")
                .is_some()
        );
        drop(second_reservation);
    }

    #[test]
    fn delete_proof_before_registry_and_quota_release_reconciles_exactly_on_restart() {
        let harness = Harness::new();
        let store = harness.open();
        let request = harness.request(TenantId::new(), SessionId::new());
        let reservation = reserve(&store.shared, request.key(), 5, true).expect("charge");
        let receipt = harness.seal(&store, &request);
        let mut record = harness.record(&request, &receipt);
        store
            .shared
            .publications
            .lock()
            .expect("registry")
            .retain_quarantine(record.clone(), 1000)
            .expect("authority");
        store
            .shared
            .retention
            .lock()
            .expect("retention")
            .observe_quarantine(&receipt, 1000, 1100)
            .expect("cleanup authority");
        let commit = store
            .pending_notifications(None, 32, 8)
            .expect("notification")
            .commits[0]
            .clone();
        store
            .acknowledge_notifications(&commit.ack())
            .expect("source ACK");
        harness.clock.0.store(1101, Ordering::SeqCst);
        record.phase = Phase::DeleteIntent;
        store
            .shared
            .publications
            .lock()
            .expect("registry")
            .update_quarantine(record, 1101)
            .expect("durable intent");
        store
            .shared
            .retention
            .lock()
            .expect("retention")
            .intent(request.key(), receipt.object_generation(), 1101)
            .expect("cleanup intent");
        harness
            .runtime
            .block_on(store.shared.filesystem.store.delete_quarantine_exact(
                &request.key().namespace(),
                request.key(),
                receipt.object_generation(),
            ))
            .expect("actual positive byte deletion");
        assert_eq!(
            store
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .get(request.key()),
            Some(&5)
        );
        drop(reservation);
        drop(store);
        let reopened = harness.open();
        assert!(
            !reopened
                .shared
                .ledger
                .lock()
                .expect("ledger")
                .charges
                .contains_key(request.key())
        );
        assert!(matches!(
            reopened
                .shared
                .publications
                .lock()
                .expect("registry")
                .quarantine_record(request.key())
                .expect("terminal authority")
                .phase,
            Phase::Deleted { at: 1101 }
        ));
        assert!(
            reopened
                .pending_notifications(None, 32, 8)
                .expect("no duplicate public cleanup events")
                .commits
                .is_empty()
        );
        reopened
            .acknowledge_notifications(&commit.ack())
            .expect("restart exact ACK replay");
    }
}
