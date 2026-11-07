use std::io::Read;

use crate::{
    Artifact, ArtifactContentMetadata, ArtifactContentSource, ArtifactEvent, ArtifactId,
    ArtifactRecord, ArtifactScanVerdict, ArtifactState, ArtifactStoreRequest, AuthenticatedPeer,
    BrowserDownloadCompletion, ChromiumDriver, OwnershipFence, PendingDownloadRollback,
    SandboxClient, SessionId, SessionLifecycle, WorkerArtifactSnapshot, WorkerControlPlane,
    WorkerError, validate_fence,
};

const MAX_COMPLETIONS_PER_PASS: usize = 4;
const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    /// Maintenance publishes bounded completed downloads independently of client polling.
    /// One rejected download does not prevent other sessions from being reconciled.
    pub fn reconcile_browser_downloads_due(
        &self,
        peer: &AuthenticatedPeer,
    ) -> Result<usize, WorkerError> {
        self.authorize(peer)?;
        let sessions = self
            .lock_worker()?
            .sessions
            .iter()
            .map(|(id, executor)| (id.clone(), executor.clone()))
            .collect::<Vec<_>>();
        let mut completed = 0;
        let mut first_error = None;
        for (session_id, executor) in sessions {
            let snapshot = {
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                (session.machine.snapshot().lifecycle == SessionLifecycle::Ready)
                    .then(|| session.machine.snapshot())
            };
            if let Some(snapshot) = snapshot {
                match self.reconcile_browser_downloads(peer, &session_id, &snapshot.owner_fence) {
                    Ok(count) => completed += count,
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                }
            }
        }
        first_error.map_or(Ok(completed), Err)
    }

    /// Reconciles completed downloads without replaying the action that started them.
    /// Exact owner metadata stays pending until publication and scratch cleanup are acknowledged.
    pub fn reconcile_browser_downloads(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<usize, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _cleanup = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let tenant_id = {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            session.tenant_id.clone()
        };
        self.retry_download_rollbacks(&executor, None)?;
        if executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?
            .machine
            .snapshot()
            .lifecycle
            != SessionLifecycle::Ready
        {
            return Err(WorkerError::DependencyUnavailable);
        }
        let completions = self
            .driver
            .pending_browser_downloads(session_id, fence, MAX_COMPLETIONS_PER_PASS)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        if completions.len() > MAX_COMPLETIONS_PER_PASS {
            return Err(WorkerError::DependencyUnavailable);
        }
        let mut completed = 0;
        for completion in completions {
            if completion.tenant_id != tenant_id
                || &completion.session_id != session_id
                || &completion.fence != fence
            {
                return Err(WorkerError::StaleFence);
            }
            // An interrupted ACK never causes a second store or a new ArtifactId.
            let already_published = {
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                match session.artifacts.get(&completion.artifact_id) {
                    Some(record) => {
                        self.validate_artifact_record_publication(record, fence)?;
                        let metadata = record
                            .artifact
                            .content_metadata()
                            .ok_or(WorkerError::StateUnavailable)?;
                        if metadata.source() != ArtifactContentSource::BrowserDownload
                            || metadata.size_bytes() != completion.expected_size_bytes
                            || record.artifact.state() != ArtifactState::Available
                        {
                            return Err(WorkerError::DependencyUnavailable);
                        }
                        true
                    }
                    None => false,
                }
            };
            if already_published {
                self.driver
                    .ack_browser_download(&completion)
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                completed += 1;
                continue;
            }
            let size = completion.expected_size_bytes;
            let maximum = self
                .config
                .artifact_limits
                .max_file_bytes
                .min(MAX_DOWNLOAD_BYTES);
            let capacity = {
                let mut session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                let reserved = session
                    .artifact_reserved_bytes
                    .checked_add(size)
                    .ok_or(WorkerError::CapacityExceeded)?;
                let total = session
                    .artifact_committed_bytes
                    .checked_add(reserved)
                    .ok_or(WorkerError::CapacityExceeded)?;
                if size > maximum
                    || reserved > self.config.artifact_limits.max_in_flight_bytes
                    || total > self.config.artifact_limits.max_committed_bytes
                {
                    false
                } else {
                    session.artifact_reserved_bytes = reserved;
                    true
                }
            };
            if !capacity {
                self.driver
                    .reject_browser_download(&completion)
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                return Err(WorkerError::CapacityExceeded);
            }
            let result = self.publish_browser_download(&executor, &completion, maximum);
            {
                let mut session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                if !session
                    .pending_download_rollbacks
                    .contains_key(&completion.artifact_id)
                {
                    session.artifact_reserved_bytes =
                        session.artifact_reserved_bytes.saturating_sub(size);
                }
            }
            result?;
            completed += 1;
        }
        Ok(completed)
    }

    fn publish_browser_download(
        &self,
        executor: &crate::SessionExecutor,
        completion: &BrowserDownloadCompletion,
        maximum: u64,
    ) -> Result<(), WorkerError> {
        let prepared = (|| {
            let pinned = self
                .driver
                .open_browser_download(completion)
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            if pinned.completion() != completion
                || pinned.size_bytes() != completion.expected_size_bytes
            {
                return Err(WorkerError::DependencyUnavailable);
            }
            pinned
                .validate_unchanged()
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            let mut bytes = Vec::new();
            pinned
                .file()
                .take(maximum.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            pinned
                .validate_unchanged()
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            if bytes.len() as u64 != completion.expected_size_bytes || bytes.len() as u64 > maximum
            {
                return Err(WorkerError::CapacityExceeded);
            }
            ArtifactStoreRequest::new_browser_download(
                completion.tenant_id.clone(),
                completion.session_id.clone(),
                completion.artifact_id.clone(),
                completion.fence.clone(),
                bytes,
                "application/octet-stream",
                maximum,
            )
        })();
        let request = match prepared {
            Ok(request) => request,
            Err(error) => {
                self.driver
                    .reject_browser_download(completion)
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                return Err(error);
            }
        };
        let receipt = match self.sandbox.store_artifact(&request) {
            Ok(receipt) => receipt,
            Err(_) => {
                self.driver
                    .reject_browser_download(completion)
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                return Err(WorkerError::DependencyUnavailable);
            }
        };
        let mut attempted_publication = None;
        let registered = (|| {
            if receipt.key() != request.key()
                || receipt.source() != ArtifactContentSource::BrowserDownload
                || receipt.size_bytes() != request.expected_size_bytes()
                || receipt.checksum() != request.expected_checksum()
                || receipt.scan_verdict() != Some(ArtifactScanVerdict::Clean)
                || receipt
                    .object_generation()
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0)
            {
                return Err(WorkerError::DependencyUnavailable);
            }
            let metadata = ArtifactContentMetadata::new(
                receipt.size_bytes(),
                *receipt.checksum(),
                receipt.detected_content_type(),
                ArtifactContentSource::BrowserDownload,
                request.origin(),
            )
            .map_err(|_| WorkerError::DependencyUnavailable)?;
            let evidence = receipt
                .scan_attestation()
                .ok_or(WorkerError::DependencyUnavailable)?;
            evidence
                .validate_for(
                    request.key(),
                    &completion.fence,
                    &metadata,
                    receipt.object_generation(),
                )
                .and_then(|()| evidence.validate_at(self.clock.now()?.get()))
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            let mut artifact = Artifact::new_upload(request.key().clone());
            artifact
                .apply_materialized(ArtifactEvent::UploadStored, metadata.clone())
                .and_then(|_| artifact.apply(ArtifactEvent::ScanStarted))
                .and_then(|_| artifact.apply(ArtifactEvent::ScanPassed))
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, &completion.fence)?;
            if session.machine.snapshot().lifecycle != SessionLifecycle::Ready
                || session.artifacts.contains_key(&completion.artifact_id)
            {
                return Err(WorkerError::DependencyUnavailable);
            }
            let committed = session
                .artifact_committed_bytes
                .checked_add(receipt.size_bytes())
                .ok_or(WorkerError::CapacityExceeded)?;
            let publication = self.new_artifact_publication(
                request.key().clone(),
                completion.fence.clone(),
                metadata,
                receipt.object_generation(),
                receipt.scan_verdict(),
                None,
                receipt.scan_attestation().cloned(),
            )?;
            attempted_publication = Some(publication.clone());
            self.publish_authorized_artifact(&publication)?;
            session.artifacts.insert(
                completion.artifact_id.clone(),
                ArtifactRecord {
                    publication: Some(publication),
                    artifact,
                    object_generation: receipt.object_generation(),
                    display_filename: None,
                },
            );
            session.artifact_committed_bytes = committed;
            Ok(())
        })();
        if let Err(error) = registered {
            if receipt.key() != request.key() {
                if let Ok(mut session) = executor.state.lock() {
                    session.durability_degraded = true;
                    session.pending_download_rollbacks.insert(
                        completion.artifact_id.clone(),
                        PendingDownloadRollback {
                            completion: completion.clone(),
                            receipt,
                            object_discarded: false,
                            publication: attempted_publication.clone(),
                        },
                    );
                }
                return Err(WorkerError::DependencyUnavailable);
            }
            // Keep the exact receipt and its quota reservation until both deletion and
            // scratch cleanup are confirmed. A retry must never store the object again.
            executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?
                .pending_download_rollbacks
                .insert(
                    completion.artifact_id.clone(),
                    PendingDownloadRollback {
                        completion: completion.clone(),
                        receipt,
                        object_discarded: false,
                        publication: attempted_publication.clone(),
                    },
                );
            self.retry_download_rollbacks(executor, Some(&completion.artifact_id))?;
            return Err(error);
        }
        self.driver
            .ack_browser_download(completion)
            .map_err(|_| WorkerError::DependencyUnavailable)
    }

    fn retry_download_rollbacks(
        &self,
        executor: &crate::SessionExecutor,
        current_reservation: Option<&ArtifactId>,
    ) -> Result<(), WorkerError> {
        let pending = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?
            .pending_download_rollbacks
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for rollback in pending {
            let expected_key = crate::ArtifactKey::new(
                rollback.completion.tenant_id.clone(),
                rollback.completion.session_id.clone(),
                rollback.completion.artifact_id.clone(),
            );
            if rollback.receipt.key() != &expected_key {
                return Err(WorkerError::DependencyUnavailable);
            }
            if !rollback.object_discarded {
                if let Some(publication) = &rollback.publication {
                    self.sandbox
                        .withdraw_artifact(publication)
                        .map_err(|_| WorkerError::DependencyUnavailable)?;
                }
                self.sandbox
                    .discard_artifact(&rollback.receipt, &rollback.completion.fence)
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?
                    .pending_download_rollbacks
                    .get_mut(&rollback.completion.artifact_id)
                    .ok_or(WorkerError::StateUnavailable)?
                    .object_discarded = true;
            }
            self.driver
                .reject_browser_download(&rollback.completion)
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            if session
                .pending_download_rollbacks
                .remove(&rollback.completion.artifact_id)
                .is_some()
                && current_reservation != Some(&rollback.completion.artifact_id)
            {
                session.artifact_reserved_bytes = session
                    .artifact_reserved_bytes
                    .saturating_sub(rollback.completion.expected_size_bytes);
            }
        }
        Ok(())
    }

    /// Stable ID-ordered, tenant/session-fenced listing also publishes completed downloads.
    pub fn list_artifacts(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        after: Option<&ArtifactId>,
        limit: usize,
    ) -> Result<Vec<WorkerArtifactSnapshot>, WorkerError> {
        if !(1..=101).contains(&limit) {
            return Err(WorkerError::InvalidConfiguration);
        }
        self.reconcile_browser_downloads(peer, session_id, fence)?;
        let executor = self.session(session_id)?;
        let ids = {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            let mut ids: Vec<_> = session
                .artifacts
                .iter()
                .filter(|(id, record)| {
                    after.is_none_or(|after| *id > after)
                        && self
                            .validate_artifact_record_publication(record, fence)
                            .is_ok()
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.sort();
            ids.truncate(limit);
            ids
        };
        ids.iter()
            .map(|id| self.get_artifact(peer, session_id, id, fence))
            .collect()
    }
}
