//! Session-retained, exact-generation file inputs beneath the authenticated scratch mount.
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

use browserd_artifacts::{ArtifactChecksum, ArtifactKey, ArtifactObjectGeneration};
use browserd_sandbox::{SANDBOX_SCRATCH_PATH, SandboxScratch};
use browserd_session::OwnershipFence;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, fchmod, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    ChromiumOwnerActor, GuardedPageExecution, NodeFunctionCall, OwnerActorError, PageExecutionFence,
};
use crate::{BrowserFileAttachment, TargetManagerDrain, valid_artifact_display_filename};

const MAX_FILES: usize = 128;
const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 8 * 1024 * 1024;
const COPY_CHUNK: usize = 64 * 1024;
const FILE_INPUT_PREFLIGHT: &str = "function (count) { const el = this; const doc = el.ownerDocument; return !!(el.isConnected && doc === document && doc && doc.defaultView && doc.defaultView === doc.defaultView.top && el.tagName === 'INPUT' && el.type === 'file' && !el.disabled && !el.matches(':disabled') && !el.webkitdirectory && (count === 1 || el.multiple)); }";
const FILE_INPUT_SELECTION: &str = "function () { const doc = this.ownerDocument; if (!this.isConnected || doc !== document || !doc || !doc.defaultView || doc.defaultView !== doc.defaultView.top || this.tagName !== 'INPUT' || this.type !== 'file') return null; return Array.from(this.files || [], f => ({name:f.name,size:f.size})); }";

#[cfg(test)]
#[path = "../../tests/common/bounded_scratch.rs"]
pub(super) mod bounded_scratch;
#[cfg(test)]
use super::live_chromium;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    fn read(file: &File) -> Result<Self, OwnerActorError> {
        let metadata = file
            .metadata()
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_ACTION_BYTES as u64
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

struct Entry {
    context: String,
    key: ArtifactKey,
    fence: OwnershipFence,
    generation: ArtifactObjectGeneration,
    checksum: ArtifactChecksum,
    filename: String,
    reserved_bytes: usize,
    directory_name: String,
    directory: Option<File>,
    file: Option<File>,
    identity: Option<Identity>,
    ready: bool,
    file_removed: bool,
}

#[derive(Default)]
pub(super) struct UploadState {
    root: Option<File>,
    directory: Option<File>,
    entries: Vec<Entry>,
    retained_bytes: usize,
}

impl UploadState {
    pub(super) fn new(scratch: Option<&SandboxScratch>) -> Result<Self, OwnerActorError> {
        let root = scratch
            .map(|scratch| {
                // Atomic CLOEXEC prevents another process spawn from inheriting this capability.
                let fd = scratch
                    .directory()
                    .try_clone_to_owned()
                    .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                Ok::<_, OwnerActorError>(File::from(fd))
            })
            .transpose()?;
        Ok(Self {
            root,
            ..Self::default()
        })
    }

    fn validate_request(files: &[BrowserFileAttachment]) -> Result<(), OwnerActorError> {
        if files.is_empty() || files.len() > MAX_FILES {
            return Err(OwnerActorError::Rejected);
        }
        let mut bytes = 0_usize;
        for (index, file) in files.iter().enumerate() {
            bytes = bytes
                .checked_add(file.bytes().len())
                .ok_or(OwnerActorError::Rejected)?;
            if bytes > MAX_ACTION_BYTES
                || !valid_artifact_display_filename(file.display_filename())
                || files[..index].iter().any(|other| other.key() == file.key())
                || Sha256::digest(file.bytes()).as_slice() != file.checksum().as_bytes()
            {
                return Err(OwnerActorError::Rejected);
            }
        }
        Ok(())
    }

    fn validate_directory(parent: &File, name: &str, pinned: &File) -> Result<(), OwnerActorError> {
        let expected = pinned
            .metadata()
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let current = File::from(
            openat(
                parent,
                name,
                OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| OwnerActorError::OutcomeUncertain)?,
        );
        let actual = current
            .metadata()
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        if !expected.is_dir()
            || expected.mode() & 0o7777 != 0o700
            || expected.nlink() < 2
            || expected.dev() != actual.dev()
            || expected.ino() != actual.ino()
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    fn validate_cached(
        directory: &File,
        entry: &Entry,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        Self::validate_directory(
            directory,
            &entry.directory_name,
            entry
                .directory
                .as_ref()
                .ok_or(OwnerActorError::OutcomeUncertain)?,
        )?;
        let file = entry
            .file
            .as_ref()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let identity = entry
            .identity
            .as_ref()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if !entry.ready
            || entry.file_removed
            || &Identity::read(file)? != identity
            || file
                .metadata()
                .map_err(|_| OwnerActorError::OutcomeUncertain)?
                .mode()
                & 0o7777
                != 0o400
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let path = openat(
            entry
                .directory
                .as_ref()
                .ok_or(OwnerActorError::OutcomeUncertain)?,
            entry.filename.as_str(),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let path = File::from(path);
        if &Identity::read(&path)? != identity {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let mut digest = Sha256::new();
        let mut reader = (&path).take(MAX_ACTION_BYTES as u64 + 1);
        let mut chunk = [0_u8; COPY_CHUNK];
        loop {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(OwnerActorError::DeadlineBeforeDispatch);
            }
            let read = reader
                .read(&mut chunk)
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            if read == 0 {
                break;
            }
            digest.update(&chunk[..read]);
        }
        if digest.finalize().as_slice() != entry.checksum.as_bytes()
            || &Identity::read(&path)? != identity
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        context: &str,
        files: &[BrowserFileAttachment],
        deadline: Option<Instant>,
    ) -> Result<Vec<String>, OwnerActorError> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(OwnerActorError::DeadlineBeforeDispatch);
        }
        Self::validate_request(files)?;
        let root = self.root.as_ref().ok_or(OwnerActorError::Rejected)?;
        let new_files = files
            .iter()
            .filter(|file| {
                !self
                    .entries
                    .iter()
                    .any(|entry| &entry.key == file.key() && entry.generation == file.generation())
            })
            .collect::<Vec<_>>();
        let added_bytes = new_files
            .iter()
            .try_fold(0_usize, |sum, file| sum.checked_add(file.bytes().len()))
            .ok_or(OwnerActorError::Rejected)?;
        if self.entries.len() + new_files.len() > MAX_FILES
            || self
                .retained_bytes
                .checked_add(added_bytes)
                .is_none_or(|bytes| bytes > MAX_CACHE_BYTES)
        {
            return Err(OwnerActorError::Rejected);
        }
        if self.directory.is_none() {
            mkdirat(root, "uploads", Mode::from_bits_truncate(0o700))
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            self.directory = Some(File::from(
                openat(
                    root,
                    "uploads",
                    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| OwnerActorError::OutcomeUncertain)?,
            ));
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        Self::validate_directory(root, "uploads", directory)?;
        let mut paths = Vec::with_capacity(files.len());
        for file in files {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(OwnerActorError::DeadlineBeforeDispatch);
            }
            let index = if let Some(index) = self
                .entries
                .iter()
                .position(|entry| &entry.key == file.key() && entry.generation == file.generation())
            {
                let entry = &self.entries[index];
                if entry.context != context
                    || &entry.fence != file.fence()
                    || &entry.checksum != file.checksum()
                    || entry.filename != file.display_filename()
                    || entry.reserved_bytes != file.bytes().len()
                {
                    return Err(OwnerActorError::Rejected);
                }
                Self::validate_cached(directory, entry, deadline)?;
                index
            } else {
                // Reserve before any filesystem effect; a partial failure retains the slot and
                // all pinned capabilities until exact context cleanup or sandbox termination.
                let index = self.entries.len();
                self.retained_bytes += file.bytes().len();
                self.entries.push(Entry {
                    context: context.to_owned(),
                    key: file.key().clone(),
                    fence: file.fence().clone(),
                    generation: file.generation(),
                    checksum: *file.checksum(),
                    filename: file.display_filename().to_owned(),
                    reserved_bytes: file.bytes().len(),
                    directory_name: uuid::Uuid::new_v4().to_string(),
                    directory: None,
                    file: None,
                    identity: None,
                    ready: false,
                    file_removed: false,
                });
                let entry = &mut self.entries[index];
                mkdirat(
                    directory,
                    entry.directory_name.as_str(),
                    Mode::from_bits_truncate(0o700),
                )
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                entry.directory = Some(File::from(
                    openat(
                        directory,
                        entry.directory_name.as_str(),
                        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|_| OwnerActorError::OutcomeUncertain)?,
                ));
                let pinned_directory = entry
                    .directory
                    .as_ref()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                let writer = File::from(
                    openat(
                        pinned_directory,
                        entry.filename.as_str(),
                        OFlag::O_WRONLY
                            | OFlag::O_CREAT
                            | OFlag::O_EXCL
                            | OFlag::O_CLOEXEC
                            | OFlag::O_NOFOLLOW,
                        Mode::from_bits_truncate(0o600),
                    )
                    .map_err(|_| OwnerActorError::OutcomeUncertain)?,
                );
                // Pin the exact inode before copying so deterministic partial writes remain
                // eligible for exact cleanup after context disposal.
                entry.file = Some(writer);
                let writer = entry
                    .file
                    .as_mut()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                for chunk in file.bytes().chunks(COPY_CHUNK) {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(OwnerActorError::DeadlineBeforeDispatch);
                    }
                    writer
                        .write_all(chunk)
                        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                }
                fchmod(&*writer, Mode::from_bits_truncate(0o400))
                    .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                let identity = Identity::read(writer)?;
                entry.file = Some(File::from(
                    openat(
                        pinned_directory,
                        entry.filename.as_str(),
                        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
                        Mode::empty(),
                    )
                    .map_err(|_| OwnerActorError::OutcomeUncertain)?,
                ));
                entry.identity = Some(identity);
                entry.ready = true;
                Self::validate_cached(directory, entry, deadline)?;
                index
            };
            let entry = &self.entries[index];
            // The only paths sent to Chromium are generated here beneath the pinned root.
            paths.push(format!(
                "{SANDBOX_SCRATCH_PATH}/uploads/{}/{}",
                entry.directory_name, entry.filename
            ));
        }
        Ok(paths)
    }

    fn validate_paths(
        &self,
        files: &[BrowserFileAttachment],
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        let directory = self
            .directory
            .as_ref()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        Self::validate_directory(
            self.root
                .as_ref()
                .ok_or(OwnerActorError::OutcomeUncertain)?,
            "uploads",
            directory,
        )?;
        for file in files {
            let entry = self
                .entries
                .iter()
                .find(|entry| &entry.key == file.key() && entry.generation == file.generation())
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            Self::validate_cached(directory, entry, deadline)?;
        }
        Ok(())
    }

    pub(super) fn forget_context(&mut self, context: &str) -> Result<(), OwnerActorError> {
        let Some(directory) = self.directory.as_ref() else {
            return Ok(());
        };
        Self::validate_directory(
            self.root
                .as_ref()
                .ok_or(OwnerActorError::OutcomeUncertain)?,
            "uploads",
            directory,
        )?;
        let mut index = 0;
        while index < self.entries.len() {
            let entry = &mut self.entries[index];
            if entry.context != context {
                index += 1;
                continue;
            }
            let pinned_directory = entry
                .directory
                .as_ref()
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            Self::validate_directory(directory, &entry.directory_name, pinned_directory)?;
            if !entry.file_removed {
                if entry.ready {
                    Self::validate_cached(directory, entry, None)?;
                } else if let Some(file) = entry.file.as_ref() {
                    let current = File::from(
                        openat(
                            pinned_directory,
                            entry.filename.as_str(),
                            OFlag::O_RDONLY
                                | OFlag::O_CLOEXEC
                                | OFlag::O_NOFOLLOW
                                | OFlag::O_NONBLOCK,
                            Mode::empty(),
                        )
                        .map_err(|_| OwnerActorError::OutcomeUncertain)?,
                    );
                    if Identity::read(&current)? != Identity::read(file)? {
                        return Err(OwnerActorError::OutcomeUncertain);
                    }
                } else {
                    // No file was successfully created; never guess which unowned entry
                    // might explain an O_EXCL or directory-open failure.
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                unlinkat(
                    pinned_directory,
                    entry.filename.as_str(),
                    UnlinkatFlags::NoRemoveDir,
                )
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
                entry.file_removed = true;
            }
            unlinkat(
                directory,
                entry.directory_name.as_str(),
                UnlinkatFlags::RemoveDir,
            )
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            self.retained_bytes -= entry.reserved_bytes;
            self.entries.remove(index);
        }
        Ok(())
    }
}

pub(super) struct PreparedFiles {
    top: String,
    flat: String,
    node: String,
    backend: u64,
    files: Vec<BrowserFileAttachment>,
    paths: Vec<String>,
    frame: super::frames::FrameGuard,
    guarded: Option<GuardedPageExecution>,
    allow_child: bool,
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    pub(super) async fn inspect_typed_file_input(
        &mut self,
        top: &str,
        node: &str,
        count: usize,
        deadline: Instant,
    ) -> Result<(), OwnerActorError> {
        if !(1..=MAX_FILES).contains(&count) || self.uploads.root.is_none() {
            return Err(OwnerActorError::Rejected);
        }
        let (frame, _) = self.node_frame_guard(top, node, false)?;
        let declaration = FILE_INPUT_PREFLIGHT.replace(
            "doc.defaultView === doc.defaultView.top",
            "doc.defaultView === globalThis",
        );
        let valid = self
            .call_function_on_node(
                top,
                frame.scope.cdp_session_id.as_str().to_owned(),
                None,
                node,
                NodeFunctionCall {
                    declaration: &declaration,
                    arguments: json!([{"value":count}]),
                },
                Some(deadline),
            )
            .await?;
        if valid != Value::Bool(true) {
            return Err(OwnerActorError::Rejected);
        }
        self.validate_frame_guard(&frame)
    }

    pub(super) async fn execute_set_files(
        &mut self,
        target_id: &str,
        _cdp_session_id: String,
        node_ref: &str,
        files: Vec<BrowserFileAttachment>,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let prepared = self
            .prepare_set_files(target_id, node_ref, files, deadline, false)
            .await?;
        self.commit_set_files(prepared, deadline).await
    }

    pub(super) async fn prepare_set_files(
        &mut self,
        target_id: &str,
        node_ref: &str,
        files: Vec<BrowserFileAttachment>,
        deadline: Option<Instant>,
        allow_child: bool,
    ) -> Result<PreparedFiles, OwnerActorError> {
        UploadState::validate_request(&files)?;
        let route = self
            .routes
            .get(target_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if files.iter().any(|file| {
            file.key().tenant_id() != route.route.tenant_id()
                || file.key().session_id() != route.route.owner_session_id()
                || file.fence() != route.route.ownership_fence()
        }) {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if self.uploads.root.is_none() {
            return Err(OwnerActorError::Rejected);
        }
        let context = route.route.browser_context_id().to_owned();
        let guarded = Some(GuardedPageExecution {
            viewer_transform: None,
            target_id: target_id.to_owned(),
            fence: PageExecutionFence {
                target_incarnation: route.target_incarnation,
                frame_document_epoch: route.frame_document_epoch,
                url_revision: route.url_revision,
            },
        });
        let (frame, backend) = self.node_frame_guard(target_id, node_ref, !allow_child)?;
        let flat = frame.scope.cdp_session_id.as_str().to_owned();
        let declaration = if allow_child {
            FILE_INPUT_PREFLIGHT.replace(
                "doc.defaultView === doc.defaultView.top",
                "doc.defaultView === globalThis",
            )
        } else {
            FILE_INPUT_PREFLIGHT.to_owned()
        };
        let valid = self
            .call_function_on_node(
                target_id,
                flat.clone(),
                guarded.clone(),
                node_ref,
                NodeFunctionCall {
                    declaration: &declaration,
                    arguments: json!([{"value":files.len()}]),
                },
                deadline,
            )
            .await?;
        if valid != Value::Bool(true) {
            return Err(OwnerActorError::Rejected);
        }
        let paths = self.uploads.prepare(&context, &files, deadline)?;
        let valid = self
            .call_function_on_node(
                target_id,
                flat.clone(),
                guarded.clone(),
                node_ref,
                NodeFunctionCall {
                    declaration: &declaration,
                    arguments: json!([{"value":files.len()}]),
                },
                deadline,
            )
            .await?;
        if valid != Value::Bool(true) {
            return Err(OwnerActorError::Rejected);
        }
        self.uploads.validate_paths(&files, deadline)?;
        self.validate_frame_guard(&frame)?;
        Ok(PreparedFiles {
            top: target_id.to_owned(),
            flat,
            node: node_ref.to_owned(),
            backend,
            files,
            paths,
            frame,
            guarded,
            allow_child,
        })
    }

    pub(super) async fn commit_set_files(
        &mut self,
        prepared: PreparedFiles,
        deadline: Option<Instant>,
    ) -> Result<Value, OwnerActorError> {
        let PreparedFiles {
            top,
            flat,
            node,
            backend,
            files,
            paths,
            frame,
            guarded,
            allow_child,
        } = prepared;
        self.validate_frame_guard(&frame)?;
        if self.node_frame_guard(&top, &node, !allow_child)?.1 != backend {
            return Err(OwnerActorError::Rejected);
        }
        self.uploads.validate_paths(&files, deadline)?;
        self.command_event_first(
            "DOM.setFileInputFiles",
            json!({"backendNodeId":backend,"files":paths}),
            Some(flat.clone()),
            None,
            guarded.clone(),
            deadline,
        )
        .await
        .map_err(|error| {
            if error == OwnerActorError::DeadlineBeforeDispatch {
                error
            } else {
                OwnerActorError::OutcomeUncertain
            }
        })?;
        let declaration = if allow_child {
            FILE_INPUT_SELECTION.replace(
                "doc.defaultView !== doc.defaultView.top",
                "doc.defaultView !== globalThis",
            )
        } else {
            FILE_INPUT_SELECTION.to_owned()
        };
        let observed = self
            .call_function_on_node(
                &top,
                flat,
                guarded,
                &node,
                NodeFunctionCall {
                    declaration: &declaration,
                    arguments: json!([]),
                },
                deadline,
            )
            .await
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let expected = json!(
            files
                .iter()
                .map(|file| json!({"name":file.display_filename(),"size":file.bytes().len()}))
                .collect::<Vec<_>>()
        );
        if observed != expected {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(json!({"ok":true}))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use browserd_core::{ArtifactId, SessionId, TenantId, WorkerId};
    use nix::fcntl::{FcntlArg, fcntl};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    fn attachment(name: &str, bytes: &[u8]) -> BrowserFileAttachment {
        BrowserFileAttachment::verified(
            ArtifactKey::new(TenantId::new(), SessionId::new(), ArtifactId::new()),
            OwnershipFence::new(WorkerId::new("upload-test").unwrap(), 1, 1, 1),
            ArtifactObjectGeneration::new([1; 32]),
            ArtifactChecksum::new(Sha256::digest(bytes).into()),
            name.to_owned(),
            Arc::from(bytes),
        )
    }

    fn fixture() -> (tempfile::TempDir, UploadState) {
        let temporary = tempfile::tempdir().unwrap();
        let state = UploadState {
            root: Some(File::open(temporary.path()).unwrap()),
            ..UploadState::default()
        };
        (temporary, state)
    }

    #[tokio::test]
    async fn file_selection_interrupted_after_dispatch_is_uncertain_and_retains_files() {
        use super::super::{
            ChromiumConnectionOwner, ChromiumTargetRoute, ContextEntry, ContextLifecycle,
            ContextOwnership, NetworkActivity, OwnerActorContext, TargetRouteEntry, downloads,
            node_store_now,
        };
        use browserd_chromium::{
            ChromiumArtifactIdentity, ChromiumConnection, ChromiumConnectionConfig, Sha256Digest,
        };
        use browserd_core::{
            LaunchGeneration, OwnerFence, PageId, ShardFence, ShardId, WorkerEpoch,
        };
        use browserd_sandbox::ChromiumCdpPipes;
        use browserd_targets::{
            BackendNodeId, DocumentEpoch, NodeBinding, SessionIncarnation, SnapshotId,
            TargetIncarnation, TargetKind, UrlRevision,
        };
        use std::collections::{BTreeMap, BTreeSet};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::unix::pipe::{Receiver, Sender};
        use tokio::sync::mpsc;
        use tokio_util::sync::CancellationToken;

        struct Drain(AtomicBool);
        impl TargetManagerDrain for Drain {
            fn begin_drain(&self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        async fn read(reader: &mut Receiver, method: &str) -> Value {
            let mut bytes = Vec::new();
            loop {
                let byte = reader.read_u8().await.unwrap();
                if byte == 0 {
                    break;
                }
                bytes.push(byte);
                assert!(bytes.len() <= 16 * 1024);
            }
            let command: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(command["method"], method);
            command
        }

        async fn write(writer: &mut Sender, message: Value) {
            writer
                .write_all(&serde_json::to_vec(&message).unwrap())
                .await
                .unwrap();
            writer.write_all(&[0]).await.unwrap();
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            let digest = Sha256Digest::from_hex(&"00".repeat(32)).unwrap();
            let identity = ChromiumArtifactIdentity {
                binary_digest: digest,
                product_version: "149.0.7827.55".to_owned(),
                chromium_revision: "r1234567".to_owned(),
                browser_protocol_schema_digest: digest,
                js_protocol_schema_digest: digest,
                launch_profile_digest: digest,
                extension_bundle_digest: digest,
                font_bundle_digest: digest,
                certificate_runtime_bundle_digest: digest,
            };
            let file = attachment("input.txt", b"retained bytes");
            let shard = ShardFence::new(
                OwnerFence::new(WorkerId::new("upload-test").unwrap(), WorkerEpoch::new(1).unwrap()),
                ShardId::new(),
                LaunchGeneration::new(1).unwrap(),
            );
            let config = ChromiumConnectionConfig::default();
            let drain = Arc::new(Drain(AtomicBool::new(false)));
            let (owner, manager) = ChromiumConnectionOwner::new_bounded(
                identity.clone(), config.clone(), shard.clone(), 8, drain.clone(),
            ).unwrap();
            let (command_reader, command_writer) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
            let (event_reader, event_writer) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
            let pipes = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader).unwrap();
            let mut reader = Receiver::from_owned_fd(command_reader).unwrap();
            let mut writer = Sender::from_owned_fd(event_writer).unwrap();
            let (connection, ()) = tokio::join!(
                ChromiumConnection::connect(pipes, &identity, config),
                async {
                    let command = read(&mut reader, "Browser.getVersion").await;
                    write(&mut writer, json!({"id":command["id"],"result":{
                        "protocolVersion":"1.3", "product":"HeadlessChrome/149.0.7827.55",
                        "revision":"r1234567", "userAgent":"browserd-test", "jsVersion":"14.9"
                    }})).await;
                }
            );
            let (client, events, driver) = connection.unwrap().into_verified_parts();
            let (_bootstrap_sender, bootstrap_receiver) = mpsc::channel(8);
            let (_control_sender, control_receiver) = mpsc::channel(16);
            let (temporary, uploads) = fixture();
            let mut actor = ChromiumOwnerActor::new(client, events, driver, OwnerActorContext {
                artifact_identity: identity,
                ingress: owner.ingress.clone(),
                mailbox: Arc::downgrade(&owner.mailbox),
                shard_fence: shard,
                process_profile: None,
                launch_spec: None,
                context_policy: None,
                egress_proxy_binding: None,
                downloads: downloads::DownloadState::new(None),
                uploads,
                bootstrap_receiver,
                control_receiver,
                shutdown: CancellationToken::new(),
            }, Duration::from_secs(1));
            let page_id = PageId::new();
            actor.contexts.insert("owned-context".to_owned(), ContextEntry {
                checkpoint_restore_available: false,
                ownership: ContextOwnership { tenant_id: file.key().tenant_id().clone(), session_id: file.key().session_id().clone(), fence: file.fence().clone() },
                options: None, emulation_owner_target_id: None, lifecycle: ContextLifecycle::Active,
                pages: BTreeMap::from([(page_id.clone(), "target".to_owned())]), closing_pages: BTreeSet::new(),
            });
            actor.routes.insert("target".to_owned(), TargetRouteEntry {
                route: ChromiumTargetRoute {
                    session_id: "flat".to_owned(),
                    browser_context_id: "owned-context".to_owned(),
                    tenant_id: file.key().tenant_id().clone(),
                    owner_session_id: file.key().session_id().clone(),
                    ownership_fence: file.fence().clone(),
                },
                kind: TargetKind::Page,
                page_id: Some(page_id),
                target_incarnation: 1,
                frame_document_epoch: 1,
                url_revision: 1,
                document: Default::default(),
                network: NetworkActivity::quiet_at(Instant::now()),
            });
            let frame_scope = actor.seed_test_main_frame("target");
            let frame_epoch = actor.main_frame_guard("target").unwrap().epoch;
            let node = actor.node_store.insert(NodeBinding {
                frame_scope: frame_scope.clone(),
                session_incarnation: SessionIncarnation::new(1),
                target_incarnation: TargetIncarnation::new(1),
                frame_document_epoch: DocumentEpoch::new(frame_epoch),
                backend_node_id: BackendNodeId::new(42),
                snapshot_id: SnapshotId::new(0),
                url_revision: UrlRevision::new(1),
            }, node_store_now());

            let mut child_scope = frame_scope;
            child_scope.frame_id = browserd_targets::FrameId::new("child-frame");
            let child = actor.node_store.insert(NodeBinding {
                frame_scope: child_scope, session_incarnation: SessionIncarnation::new(1),
                target_incarnation: TargetIncarnation::new(1), frame_document_epoch: DocumentEpoch::new(frame_epoch),
                backend_node_id: BackendNodeId::new(43), snapshot_id: SnapshotId::new(0), url_revision: UrlRevision::new(1),
            }, node_store_now());
            assert_eq!(actor.execute_set_files("target", "flat".to_owned(), child.as_token(), vec![file.clone()], None).await, Err(OwnerActorError::Rejected));
            assert!(tokio::time::timeout(Duration::from_millis(20), reader.read_u8()).await.is_err());
            assert!(actor.uploads.entries.is_empty());

            // A deadline before any dispatch remains a known failure with no filesystem effect.
            assert!(matches!(actor.execute_set_files("target", "flat".to_owned(), node.as_token(),
                vec![file.clone()], Some(Instant::now())).await,
                Err(OwnerActorError::DeadlineBeforeDispatch)));
            assert!(actor.uploads.entries.is_empty());

            let (result, ()) = tokio::join!(
                actor.execute_set_files("target", "flat".to_owned(), node.as_token(), vec![file.clone()], None),
                async {
                    for _ in 0..2 {
                        for (method, result) in [
                            ("DOM.resolveNode", json!({"object":{"objectId":"input"}})),
                            ("Runtime.callFunctionOn", json!({"result":{"type":"boolean","value":true}})),
                            ("Runtime.releaseObject", json!({})),
                        ] {
                            let command = read(&mut reader, method).await;
                            write(&mut writer, json!({"id":command["id"],"result":result})).await;
                        }
                    }
                    let command = read(&mut reader, "DOM.setFileInputFiles").await;
                    assert_eq!(command["params"]["backendNodeId"], 42);
                    let paths = command["params"]["files"].as_array().unwrap();
                    assert_eq!(paths.len(), 1);
                    assert!(paths[0].as_str().unwrap().starts_with("/profile/browserd-files/uploads/"));
                    // The command reached Chromium. An event now interrupts it before ACK;
                    // no protocol response can prove whether the file selection took effect.
                    write(&mut writer, json!({"method":"Target.attachedToTarget","params":{
                        "sessionId":"foreign-flat", "waitingForDebugger":true,
                        "targetInfo":{"targetId":"foreign-target","browserContextId":"foreign-context","type":"iframe"}
                    }})).await;
                }
            );
            assert_eq!(result, Err(OwnerActorError::OutcomeUncertain));
            assert!(actor.event_failed_closed);
            assert!(manager.is_tainted());
            assert!(drain.0.load(Ordering::SeqCst));
            assert_eq!(actor.uploads.entries.len(), 1);
            assert_eq!(actor.uploads.retained_bytes, file.bytes().len());
            let retained = temporary.path().join("uploads")
                .join(&actor.uploads.entries[0].directory_name).join("input.txt");
            assert_eq!(std::fs::read(retained).unwrap(), file.bytes());
            // A possibly selected file remains pinned until verified context/shard teardown.
            actor.driver.shutdown().await;
        }).await.expect("bounded file-selection interruption proof");
    }

    #[test]
    fn immutable_cache_reuses_exact_generation_and_retains_empty_and_korean_files() {
        let (temporary, mut state) = fixture();
        let file = attachment("한글.txt", "본문".as_bytes());
        let empty = attachment("empty.bin", b"");
        let paths = state
            .prepare("context", &[file.clone(), empty.clone()], None)
            .unwrap();
        assert_eq!(
            paths,
            state
                .prepare("context", &[file.clone(), empty], None)
                .unwrap()
        );
        assert_eq!(state.entries.len(), 2);
        let entry = &state.entries[0];
        let path = temporary
            .path()
            .join("uploads")
            .join(&entry.directory_name)
            .join("한글.txt");
        assert_eq!(std::fs::read(&path).unwrap(), "본문".as_bytes());
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o400);
        let fd = entry.file.as_ref().unwrap();
        assert_eq!(
            fcntl(fd, FcntlArg::F_GETFL).unwrap() & nix::libc::O_ACCMODE,
            nix::libc::O_RDONLY
        );
        assert_ne!(
            fcntl(fd, FcntlArg::F_GETFD).unwrap() & nix::libc::FD_CLOEXEC,
            0
        );
        let newer = BrowserFileAttachment::verified(
            file.key().clone(),
            file.fence().clone(),
            ArtifactObjectGeneration::new([2; 32]),
            *file.checksum(),
            file.display_filename().to_owned(),
            Arc::from(file.bytes()),
        );
        assert_ne!(
            state.prepare("context", &[newer], None).unwrap()[0],
            paths[0]
        );
        state.forget_context("unrelated").unwrap();
        assert!(path.exists());
        state.forget_context("context").unwrap();
        assert!(!path.exists());
        assert_eq!(state.entries.len(), 0);
        assert_eq!(state.retained_bytes, 0);
    }

    #[test]
    fn invalid_names_duplicate_keys_and_changed_checksum_never_materialize() {
        let (temporary, mut state) = fixture();
        for filename in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "nul\0file",
            "line\nfile",
        ] {
            assert!(matches!(
                state.prepare("c", &[attachment(filename, b"x")], None),
                Err(OwnerActorError::Rejected)
            ));
        }
        let file = attachment("ok", b"x");
        assert!(
            state
                .prepare("c", &[file.clone(), file.clone()], None)
                .is_err()
        );
        let corrupt = BrowserFileAttachment::verified(
            file.key().clone(),
            file.fence().clone(),
            file.generation(),
            ArtifactChecksum::new([0; 32]),
            "ok".to_owned(),
            Arc::from(b"x".as_slice()),
        );
        assert!(state.prepare("c", &[corrupt], None).is_err());
        assert!(
            std::fs::read_dir(temporary.path())
                .unwrap()
                .next()
                .is_none()
        );
        assert_eq!(state.retained_bytes, 0);
    }

    #[test]
    fn cache_and_action_byte_limits_reject_before_allocating_more_files() {
        let (_temporary, mut state) = fixture();
        let bytes = vec![42; MAX_ACTION_BYTES];
        let first = attachment("first", &bytes);
        let second = attachment("second", &bytes);
        assert!(
            state
                .prepare("c", &[first.clone(), second.clone()], None)
                .is_err()
        );
        assert!(state.entries.is_empty());
        state.prepare("c", &[first], None).unwrap();
        state.prepare("c", &[second], None).unwrap();
        assert_eq!(state.retained_bytes, MAX_CACHE_BYTES);
        assert!(
            state
                .prepare("c", &[attachment("overflow", b"x")], None)
                .is_err()
        );
        assert_eq!(state.entries.len(), 2);
    }

    #[test]
    fn retained_zero_byte_file_count_is_bounded_and_released_only_on_context_cleanup() {
        let (_temporary, mut state) = fixture();
        let files: Vec<_> = (0..MAX_FILES)
            .map(|n| attachment(&format!("{n}.bin"), b""))
            .collect();
        state.prepare("c", &files, None).unwrap();
        assert_eq!(state.entries.len(), MAX_FILES);
        assert!(
            state
                .prepare("c", &[attachment("extra", b"")], None)
                .is_err()
        );
        state.forget_context("c").unwrap();
        state
            .prepare("c", &[attachment("next", b"")], None)
            .unwrap();
    }

    #[test]
    fn replaced_ancestor_or_symlink_never_selects_a_different_browser_path() {
        for replace_root in [false, true] {
            let (temporary, mut state) = fixture();
            let file = attachment("same.bin", b"original");
            state
                .prepare("c", std::slice::from_ref(&file), None)
                .unwrap();
            let replaced = if replace_root {
                temporary.path().join("uploads")
            } else {
                temporary
                    .path()
                    .join("uploads")
                    .join(&state.entries[0].directory_name)
            };
            std::fs::rename(&replaced, replaced.with_extension("old")).unwrap();
            std::fs::create_dir(&replaced).unwrap();
            std::fs::set_permissions(&replaced, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(matches!(
                state.validate_paths(std::slice::from_ref(&file), None),
                Err(OwnerActorError::OutcomeUncertain)
            ));
            assert!(state.prepare("c", &[file], None).is_err());
            assert!(state.forget_context("c").is_err());
            assert_eq!(state.entries.len(), 1);
        }
        let (temporary, mut state) = fixture();
        let file = attachment("same.bin", b"original");
        state
            .prepare("c", std::slice::from_ref(&file), None)
            .unwrap();
        let path = temporary
            .path()
            .join("uploads")
            .join(&state.entries[0].directory_name)
            .join("same.bin");
        std::fs::remove_file(&path).unwrap();
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, b"not an input").unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(state.validate_paths(&[file], None).is_err());
        assert!(state.forget_context("c").is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"not an input");
    }

    #[test]
    fn stale_content_and_context_binding_do_not_reuse_cache() {
        let (temporary, mut state) = fixture();
        let file = attachment("same.bin", b"original");
        state
            .prepare("c", std::slice::from_ref(&file), None)
            .unwrap();
        assert!(matches!(
            state.prepare("other", std::slice::from_ref(&file), None),
            Err(OwnerActorError::Rejected)
        ));
        let path = temporary
            .path()
            .join("uploads")
            .join(&state.entries[0].directory_name)
            .join("same.bin");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, b"modified").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(state.prepare("c", &[file], None).is_err());
        assert!(state.forget_context("c").is_err());
        assert_eq!(state.retained_bytes, 8);
    }

    #[test]
    fn exact_cleanup_retries_after_directory_failure_and_handles_pinned_partial_write() {
        let (temporary, mut state) = fixture();
        state
            .prepare("c", &[attachment("input", b"bytes")], None)
            .unwrap();
        let path = temporary
            .path()
            .join("uploads")
            .join(&state.entries[0].directory_name);
        std::fs::write(path.join("unexpected"), b"owned by nobody").unwrap();
        assert!(state.forget_context("c").is_err());
        assert!(state.entries[0].file_removed);
        assert_eq!(state.retained_bytes, 5);
        std::fs::remove_file(path.join("unexpected")).unwrap();
        state.forget_context("c").unwrap();
        state
            .prepare("c", &[attachment("partial", b"bytes")], None)
            .unwrap();
        state.entries[0].ready = false;
        state.entries[0].identity = None;
        state.forget_context("c").unwrap();
        assert_eq!(state.retained_bytes, 0);
    }

    #[test]
    fn missing_capability_and_expired_deadline_cannot_materialize_files() {
        let file = attachment("file", b"bytes");
        assert!(
            UploadState::default()
                .prepare("c", std::slice::from_ref(&file), None)
                .is_err()
        );
        let (temporary, mut state) = fixture();
        assert!(matches!(
            state.prepare("c", &[file], Some(Instant::now())),
            Err(OwnerActorError::DeadlineBeforeDispatch)
        ));
        assert!(
            std::fs::read_dir(temporary.path())
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod live_tests {
    use super::*;
    use crate::{ActionExecutionResult, ChromiumDriver};
    use browserd_core::ArtifactId;
    use std::sync::Arc;
    use std::time::Duration;

    fn attachment(
        browser: &live_chromium::LiveChromium,
        filename: &str,
        bytes: &[u8],
    ) -> BrowserFileAttachment {
        BrowserFileAttachment::verified(
            ArtifactKey::new(
                browser.tenant.clone(),
                browser.session.clone(),
                ArtifactId::new(),
            ),
            browser.fence.clone(),
            ArtifactObjectGeneration::new([1; 32]),
            ArtifactChecksum::new(Sha256::digest(bytes).into()),
            filename.to_owned(),
            Arc::from(bytes),
        )
    }

    async fn set_files(
        browser: &live_chromium::LiveChromium,
        node: &str,
        files: Vec<BrowserFileAttachment>,
    ) -> ActionExecutionResult {
        let driver = browser.driver.clone();
        let session = browser.session.clone();
        let page = browser.page.clone();
        let fence = browser.fence.clone();
        let node = node.to_owned();
        tokio::task::spawn_blocking(move || {
            driver.execute_file_attachment_until(
                &session,
                &page,
                &fence,
                &node,
                files,
                Instant::now() + Duration::from_secs(5),
            )
        })
        .await
        .unwrap()
    }

    #[test]
    #[ignore = "requires explicit sandbox-enabled Chromium and private user/mount/pid namespaces; functional proof only"]
    fn actual_owner_file_inputs_preserve_names_bytes_and_scope() {
        const NAME: &str = "chromium_owner::uploads::live_tests::actual_owner_file_inputs_preserve_names_bytes_and_scope";
        if !bounded_scratch::enter_or_spawn(NAME) {
            return;
        }
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(async {
            // The strict owner has an exact fixed proxy binding, while this controlled document
            // needs no external origin. Downloads remain denied; only the scratch capability is enabled.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let browser = live_chromium::LiveChromium::start_with_files(listener.local_addr().unwrap()).await;
            eprintln!("file-input proof: initialize controlled document");
            browser.evaluate("document.body.innerHTML = `<input id='single' type='file'><input id='multiple' type='file' multiple><input id='disabled' type='file' disabled><fieldset disabled><input id='fieldset' type='file'></fieldset><input id='text' type='text'><input id='removed' type='file'>`; true").await;
            browser.evaluate("window.fileEvents = []; for (const type of ['input','change']) document.addEventListener(type, e => window.fileEvents.push(type + ':' + e.target.id)); true").await;
            let file = attachment(&browser, "same.txt", "첫 파일 내용".as_bytes());
            let empty = attachment(&browser, "empty.bin", b"");
            eprintln!("file-input proof: reject unsupported inputs and foreign ownership");
            for selector in ["#disabled", "#fieldset", "#text"] {
                let node = browser.node(selector).await;
                assert!(matches!(set_files(&browser, &node, vec![file.clone()]).await, ActionExecutionResult::FailedKnown(_)), "invalid input {selector}");
            }
            let single = browser.node("#single").await;
            assert!(matches!(set_files(&browser, &single, vec![file.clone(), empty.clone()]).await, ActionExecutionResult::FailedKnown(_)), "multiple files on single input");
            let removed = browser.node("#removed").await;
            browser.evaluate("document.querySelector('#removed').remove(); true").await;
            assert!(matches!(set_files(&browser, &removed, vec![file.clone()]).await, ActionExecutionResult::FailedKnown(_)), "detached node");
            let foreign = BrowserFileAttachment::verified(
                ArtifactKey::new(browserd_core::TenantId::new(), browser.session.clone(), ArtifactId::new()),
                browser.fence.clone(), file.generation(), *file.checksum(), "foreign.txt".to_owned(), Arc::from(file.bytes()),
            );
            assert!(matches!(set_files(&browser, &single, vec![foreign]).await, ActionExecutionResult::FailedKnown(_)), "foreign tenant");
            let foreign = BrowserFileAttachment::verified(file.key().clone(),
                OwnershipFence::new(browser.fence.worker_id().clone(), 2, 1, 1), file.generation(),
                *file.checksum(), file.display_filename().to_owned(), Arc::from(file.bytes()));
            assert!(matches!(set_files(&browser, &single, vec![foreign]).await, ActionExecutionResult::FailedKnown(_)), "foreign full fence");
            assert_eq!(browser.evaluate("document.querySelector('#single').files.length").await, json!(0));
            assert!(!std::path::Path::new(SANDBOX_SCRATCH_PATH).join("uploads").exists(), "preflight rejections cannot materialize files");

            eprintln!("file-input proof: select first and replacement generations");
            assert!(matches!(set_files(&browser, &single, vec![file.clone()]).await, ActionExecutionResult::Succeeded(_)));
            browser.evaluate("window.savedFile = document.querySelector('#single').files[0]; true").await;
            let first_events = browser.evaluate("window.fileEvents.slice()").await;
            let first_metadata = browser.evaluate("({count:document.querySelector('#single').files.length,name:window.savedFile?.name,size:window.savedFile?.size})").await;
            let first_read = browser.evaluate("Promise.resolve().then(() => window.savedFile.text()).then(text => ({text}), e => ({error:e.name,code:e.code}))").await;
            let changed_bytes = "새 세대".as_bytes();
            let changed = BrowserFileAttachment::verified(file.key().clone(), file.fence().clone(),
                ArtifactObjectGeneration::new([2;32]), ArtifactChecksum::new(Sha256::digest(changed_bytes).into()),
                "same.txt".to_owned(), Arc::from(changed_bytes));
            assert!(matches!(set_files(&browser, &single, vec![changed]).await, ActionExecutionResult::Succeeded(_)));
            // Both current and earlier File objects read lazily after the action has returned.
            tokio::time::sleep(Duration::from_millis(100)).await;
            eprintln!("file-input proof: lazy reads of retained File objects");
            let retained_reads = browser.evaluate("Promise.all([window.savedFile, document.querySelector('#single').files[0]].map(f => Promise.resolve().then(() => f.text()).then(text => ({text}), e => ({error:e.name,code:e.code}))))").await;
            // Compare browser failures with the exact cache bytes without using the cache as a
            // substitute for successful renderer File.text() reads.
            let directory = std::path::Path::new(SANDBOX_SCRATCH_PATH).join("uploads");
            let mut cache_lengths = Vec::new();
            for entry in std::fs::read_dir(&directory).unwrap() {
                let input = entry.unwrap().path().join("same.txt");
                let data = std::fs::read(&input).unwrap();
                assert!(data == "첫 파일 내용".as_bytes() || data == "새 세대".as_bytes());
                let metadata = input.metadata().unwrap();
                cache_lengths.push((data.len(), metadata.mode() & 0o7777, metadata.uid()));
            }
            eprintln!("file-input proof: first_metadata={first_metadata}, first_events={first_events}, first_read={first_read}, retained_reads={retained_reads}, cache_length_mode_uid={cache_lengths:?}");
            assert_eq!(first_read, json!({"text":"첫 파일 내용"}), "initial renderer read must succeed");
            assert_eq!(retained_reads, json!([{"text":"첫 파일 내용"}, {"text":"새 세대"}]), "retained and current renderer reads must succeed");
            assert_eq!(first_events, json!(["input:single", "change:single"]), "native input/change events must fire once per selection");
            let multiple = browser.node("#multiple").await;
            eprintln!("file-input proof: multiple selection with ASCII, Korean basename, and empty file");
            let korean = attachment(&browser, "한글.txt", "첫 파일 내용".as_bytes());
            let selected = set_files(&browser, &multiple, vec![file, korean, empty]).await;
            assert!(matches!(selected, ActionExecutionResult::Succeeded(_)), "native Korean basename selection: {selected:?}");
            assert_eq!(browser.evaluate("Promise.all(Array.from(document.querySelector('#multiple').files, async f => ({name:f.name,size:f.size,text:await f.text()})))").await,
                json!([{"name":"same.txt","size":"첫 파일 내용".len(),"text":"첫 파일 내용"}, {"name":"한글.txt","size":"첫 파일 내용".len(),"text":"첫 파일 내용"}, {"name":"empty.bin","size":0,"text":""}]));
            assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 4, "same generation reused, old generation retained");

            // A document change invalidates earlier opaque handles before another selection.
            eprintln!("file-input proof: reload and reject stale document handle");
            let reloaded = browser.action(json!({"type":"reload"})).await;
            assert!(matches!(reloaded, ActionExecutionResult::Succeeded(_)), "reload for stale handle: {reloaded:?}");
            assert!(matches!(set_files(&browser, &single, vec![attachment(&browser,"stale.txt",b"stale")]).await, ActionExecutionResult::FailedKnown(_)));
            let driver = browser.driver.clone();
            let backend = browser.owner.target_manager_backend();
            let tenant = browser.tenant.clone();
            let session = browser.session.clone();
            let fence = browser.fence.clone();
            eprintln!("file-input proof: proved context disposal clears retained cache");
            tokio::task::spawn_blocking(move || {
                driver.close_context_fenced(&session, &fence).unwrap();
                backend.verify_context_disposed_until(&tenant, &session, &fence, Instant::now()+Duration::from_secs(5)).unwrap();
            }).await.unwrap();
            assert_eq!(std::fs::read_dir(directory).unwrap().count(), 0, "proved context disposal removes retained inputs");
            browser.owner.shutdown_and_join(Duration::from_secs(5)).await.unwrap();
        });
    }
}
