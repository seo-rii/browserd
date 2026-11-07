//! Resolve stored artifact IDs into verified bytes before a browser file-input effect.

use crate::{
    ActionExecutionResult, Arc, ArtifactChecksum, ArtifactId, ArtifactKey, ArtifactReadRequest,
    ArtifactState, BTreeSet, BrowserFileAttachment, ChromiumDriver, Digest, Instant,
    OwnershipFence, PageId, SandboxClient, SessionExecutor, SessionId, SessionLifecycle, Sha256,
    WorkerControlPlane, valid_artifact_display_filename, validate_fence,
};

const MAX_FILES: usize = 128;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_file_attachments(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        artifact_ids: &[ArtifactId],
        deadline: Instant,
        executor: &Arc<SessionExecutor>,
    ) -> ActionExecutionResult {
        if Instant::now() >= deadline {
            return ActionExecutionResult::FailedKnown("action_timeout".to_owned());
        }
        // Close and publication cannot replace this session's artifacts while
        // preparation or the driver effect owns this guard.
        let Ok(_cleanup_owner) = executor.cleanup_owner.lock() else {
            return ActionExecutionResult::FailedKnown("files_unavailable".to_owned());
        };
        let prepared = self.prepare_file_attachments(
            session_id,
            page_id,
            fence,
            node_ref,
            artifact_ids,
            deadline,
            executor,
        );
        match prepared {
            Ok(files) => self.driver.execute_file_attachment_until(
                session_id, page_id, fence, node_ref, files, deadline,
            ),
            Err(reason) => ActionExecutionResult::FailedKnown(reason.to_owned()),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_file_attachments(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        node_ref: &str,
        artifact_ids: &[ArtifactId],
        deadline: Instant,
        executor: &SessionExecutor,
    ) -> Result<Vec<BrowserFileAttachment>, &'static str> {
        if Instant::now() >= deadline {
            return Err("action_timeout");
        }
        if artifact_ids.is_empty()
            || artifact_ids.len() > MAX_FILES
            || node_ref.is_empty()
            || node_ref.len() > 1024
            || node_ref.chars().any(char::is_control)
        {
            return Err("files_rejected");
        }
        let mut distinct = BTreeSet::new();
        let max_file_bytes = MAX_BYTES.min(self.config.artifact_limits.max_file_bytes);
        let max_total_bytes = MAX_BYTES.min(self.config.artifact_limits.max_in_flight_bytes);
        let mut total_bytes = 0_u64;
        let snapshots = {
            let session = executor.state.lock().map_err(|_| "files_unavailable")?;
            validate_fence(&session, fence).map_err(|_| "files_rejected")?;
            if session.machine.session_id() != session_id
                || session.machine.lifecycle() != SessionLifecycle::Ready
                || !session.pages.contains(page_id)
                || session.closing_pages.contains(page_id)
            {
                return Err("files_rejected");
            }
            let mut snapshots = Vec::with_capacity(artifact_ids.len());
            for id in artifact_ids {
                if !distinct.insert(id) {
                    return Err("files_rejected");
                }
                let record = session.artifacts.get(id).ok_or("files_rejected")?;
                self.validate_artifact_record_publication(record, fence)
                    .map_err(|_| "files_rejected")?;
                let expected_key =
                    ArtifactKey::new(session.tenant_id.clone(), session_id.clone(), id.clone());
                if record.artifact.key() != &expected_key
                    || record.artifact.state() != ArtifactState::Available
                    || record
                        .object_generation
                        .as_bytes()
                        .iter()
                        .all(|byte| *byte == 0)
                {
                    return Err("files_rejected");
                }
                let metadata = record
                    .artifact
                    .content_metadata()
                    .cloned()
                    .ok_or("files_rejected")?;
                if metadata.size_bytes() > max_file_bytes {
                    return Err("files_rejected");
                }
                total_bytes = total_bytes
                    .checked_add(metadata.size_bytes())
                    .ok_or("files_rejected")?;
                if total_bytes > max_total_bytes {
                    return Err("files_rejected");
                }
                let filename = record
                    .display_filename
                    .clone()
                    .unwrap_or_else(|| format!("{id}.bin"));
                if !valid_artifact_display_filename(&filename) {
                    return Err("files_rejected");
                }
                let request = ArtifactReadRequest::new(
                    expected_key,
                    fence.clone(),
                    metadata,
                    record.object_generation,
                    READ_CHUNK_BYTES,
                )
                .map_err(|_| "files_rejected")?;
                snapshots.push((request, record.display_filename.clone(), filename));
            }
            snapshots
        };
        let mut files = Vec::with_capacity(snapshots.len());
        for (request, _, filename) in &snapshots {
            if Instant::now() >= deadline {
                return Err("action_timeout");
            }
            let mut stream = self
                .sandbox
                .open_artifact(request)
                .map_err(|_| "files_unavailable")?;
            if Instant::now() >= deadline {
                return Err("action_timeout");
            }
            let expected =
                usize::try_from(request.metadata().size_bytes()).map_err(|_| "files_rejected")?;
            let mut bytes = Vec::with_capacity(expected);
            let mut digest = Sha256::new();
            loop {
                if Instant::now() >= deadline {
                    return Err("action_timeout");
                }
                let next = stream.next_chunk();
                if Instant::now() >= deadline {
                    return Err("action_timeout");
                }
                let Some(chunk) = next.map_err(|_| "files_unavailable")? else {
                    break;
                };
                let length = bytes
                    .len()
                    .checked_add(chunk.len())
                    .ok_or("files_integrity_mismatch")?;
                if chunk.is_empty() || chunk.len() > READ_CHUNK_BYTES || length > expected {
                    return Err("files_integrity_mismatch");
                }
                digest.update(&chunk);
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len() != expected
                || ArtifactChecksum::new(digest.finalize().into()) != *request.metadata().checksum()
            {
                return Err("files_integrity_mismatch");
            }
            files.push(BrowserFileAttachment::verified(
                request.key().clone(),
                fence.clone(),
                request.generation(),
                *request.metadata().checksum(),
                filename.clone(),
                Arc::from(bytes),
            ));
        }
        // Reads may have yielded or blocked. Revalidate the exact publication
        // snapshot without holding state across I/O or Chromium dispatch.
        {
            let session = executor.state.lock().map_err(|_| "files_unavailable")?;
            validate_fence(&session, fence).map_err(|_| "files_rejected")?;
            if session.machine.session_id() != session_id
                || session.machine.lifecycle() != SessionLifecycle::Ready
                || !session.pages.contains(page_id)
                || session.closing_pages.contains(page_id)
            {
                return Err("files_rejected");
            }
            for (request, original_name, _) in &snapshots {
                let record = session
                    .artifacts
                    .get(request.key().artifact_id())
                    .ok_or("files_rejected")?;
                self.validate_artifact_record_publication(record, fence)
                    .map_err(|_| "files_rejected")?;
                if record.artifact.key() != request.key()
                    || request.key().tenant_id() != &session.tenant_id
                    || record.artifact.state() != ArtifactState::Available
                    || record.object_generation != request.generation()
                    || record.artifact.content_metadata() != Some(request.metadata())
                    || &record.display_filename != original_name
                {
                    return Err("files_rejected");
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("action_timeout");
        }
        Ok(files)
    }
}
