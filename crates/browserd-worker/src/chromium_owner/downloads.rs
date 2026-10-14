//! Download ownership and filesystem capabilities. Browser event paths are never opened.
use futures::StreamExt;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use browserd_core::{ArtifactId, PageId, SessionId, TenantId};
use browserd_sandbox::{SANDBOX_SCRATCH_PATH, SandboxScratch};
use browserd_session::OwnershipFence;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde_json::{Value, json};

use super::{
    ChromiumOwnerActor, ContextLifecycle, OwnerActorError, TargetRouteEntry, valid_identifier,
};
use crate::TargetManagerDrain;

pub(super) const MAX_DOWNLOADS: usize = 4;
pub(super) const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;
pub(super) const DOWNLOAD_TICK: Duration = Duration::from_millis(100);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FRAMES: usize = 4096;
const MAX_DOWNLOAD_TOMBSTONES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserDownloadCompletion {
    pub guid: String,
    pub artifact_id: ArtifactId,
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub fence: OwnershipFence,
    pub page_id: PageId,
    pub expected_size_bytes: u64,
}

/// A read-only pinned object. The importing worker checks metadata before and after its bounded read.
#[derive(Debug)]
pub struct BrowserDownloadFile {
    completion: BrowserDownloadCompletion,
    file: File,
    identity: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn read(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_DOWNLOAD_BYTES {
            return Err(io::Error::other("invalid browser download object"));
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

impl BrowserDownloadFile {
    #[cfg(test)]
    pub(crate) fn from_test_file(
        completion: BrowserDownloadCompletion,
        file: File,
    ) -> io::Result<Self> {
        let identity = FileIdentity::read(&file)?;
        if identity.bytes != completion.expected_size_bytes {
            return Err(io::Error::other("invalid browser download fixture"));
        }
        Ok(Self {
            completion,
            file,
            identity,
        })
    }
    pub fn completion(&self) -> &BrowserDownloadCompletion {
        &self.completion
    }
    pub fn size_bytes(&self) -> u64 {
        self.identity.bytes
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn into_file(self) -> File {
        self.file
    }
    pub fn validate_unchanged(&self) -> io::Result<()> {
        if FileIdentity::read(&self.file)? != self.identity {
            return Err(io::Error::other("browser download changed during import"));
        }
        Ok(())
    }
}

pub(super) struct DownloadDirectory {
    directory: File,
    _scratch: Option<SandboxScratch>,
}

impl DownloadDirectory {
    pub(super) fn new(scratch: SandboxScratch) -> Result<Self, OwnerActorError> {
        mkdirat(
            scratch.directory(),
            "downloads",
            Mode::from_bits_truncate(0o700),
        )
        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let fd = openat(
            scratch.directory(),
            "downloads",
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let directory = File::from(fd);
        let metadata = directory
            .metadata()
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(Self {
            directory,
            _scratch: Some(scratch),
        })
    }

    fn open(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<BrowserDownloadFile, OwnerActorError> {
        if !valid_guid(&completion.guid) {
            return Err(OwnerActorError::Rejected);
        }
        let fd: OwnedFd = openat(
            &self.directory,
            completion.guid.as_str(),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let file = File::from(fd);
        let identity = FileIdentity::read(&file).map_err(|_| OwnerActorError::OutcomeUncertain)?;
        if identity.bytes != completion.expected_size_bytes {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        Ok(BrowserDownloadFile {
            completion: completion.clone(),
            file,
            identity,
        })
    }

    fn cleanup(&self, guid: &str, expected: Option<&FileIdentity>) -> Result<(), OwnerActorError> {
        if !valid_guid(guid) {
            return Err(OwnerActorError::Rejected);
        }
        for name in [guid.to_owned(), format!("{guid}.crdownload")] {
            let fd = match openat(
                &self.directory,
                name.as_str(),
                OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(nix::errno::Errno::ENOENT) => continue,
                Err(_) => return Err(OwnerActorError::OutcomeUncertain),
            };
            let file = File::from(fd);
            let metadata = file
                .metadata()
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            if let Some(expected) = expected
                && (name != guid
                    || FileIdentity::read(&file).map_err(|_| OwnerActorError::OutcomeUncertain)?
                        != *expected)
            {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            // Unlink only this one checked basename under the pinned private directory.
            unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir)
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        }
        Ok(())
    }

    fn inspect(&self, registry: &DownloadRegistry) -> Result<bool, OwnerActorError> {
        // The mounted tmpfs is the hard physical ceiling. This bounded inspection catches
        // unexplained files and size growth even when Chromium emits no progress event.
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
            .map_err(|_| OwnerActorError::OutcomeUncertain)?;
        let mut unattributed = false;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_DOWNLOADS * 2 {
                return Err(OwnerActorError::StateOverflow);
            }
            let entry = entry.map_err(|_| OwnerActorError::OutcomeUncertain)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| OwnerActorError::OutcomeUncertain)?;
            let guid = name.strip_suffix(".crdownload").unwrap_or(&name);
            unattributed |= !valid_guid(guid) || !registry.entries.contains_key(guid);
            let metadata = match std::fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(OwnerActorError::OutcomeUncertain),
            };
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(OwnerActorError::OutcomeUncertain);
            }
        }
        Ok(unattributed)
    }
}

pub(super) fn valid_guid(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == value)
}

#[derive(Clone)]
struct FrameBinding {
    tenant_id: TenantId,
    session_id: SessionId,
    fence: OwnershipFence,
    page_id: PageId,
    context_id: String,
    target_id: String,
    target_incarnation: u64,
    parent_id: Option<String>,
    swapping: bool,
}

impl FrameBinding {
    fn same_owner(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.session_id == other.session_id
            && self.fence == other.fence
            && self.page_id == other.page_id
            && self.context_id == other.context_id
    }
}

struct DownloadEntry {
    artifact_id: ArtifactId,
    binding: FrameBinding,
    received: u64,
    completed: bool,
    canceled: bool,
    cancel_requested: bool,
    cancel_sent: bool,
    deadline: Instant,
    opened_identity: Option<FileIdentity>,
}

impl DownloadEntry {
    fn completion(&self, guid: &str) -> BrowserDownloadCompletion {
        BrowserDownloadCompletion {
            guid: guid.to_owned(),
            artifact_id: self.artifact_id.clone(),
            tenant_id: self.binding.tenant_id.clone(),
            session_id: self.binding.session_id.clone(),
            fence: self.binding.fence.clone(),
            page_id: self.binding.page_id.clone(),
            expected_size_bytes: self.received,
        }
    }
}

#[derive(Default)]
struct DownloadRegistry {
    frames: BTreeMap<String, FrameBinding>,
    entries: BTreeMap<String, DownloadEntry>,
    tombstones: BTreeMap<String, BrowserDownloadCompletion>,
}

impl DownloadRegistry {
    fn register_frame(
        &mut self,
        id: &str,
        mut binding: FrameBinding,
        direct_root: bool,
    ) -> Result<(), OwnerActorError> {
        if !valid_identifier(id) || binding.parent_id.as_deref() == Some(id) {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        if let Some(previous) = self.frames.get(id) {
            if !previous.same_owner(&binding) {
                return Err(OwnerActorError::UnknownOwnership);
            }
            if let (Some(old), Some(new)) = (&previous.parent_id, &binding.parent_id)
                && old != new
            {
                return Err(OwnerActorError::UnknownOwnership);
            }
            if binding.parent_id.is_none() {
                binding.parent_id.clone_from(&previous.parent_id);
            }
            if previous.target_id != binding.target_id && !direct_root {
                return Ok(());
            }
        } else if self.frames.len() >= MAX_FRAMES {
            return Err(OwnerActorError::StateOverflow);
        }
        self.frames.insert(id.to_owned(), binding);
        Ok(())
    }

    fn detach_frame(
        &mut self,
        id: &str,
        target: &str,
        swapping: bool,
    ) -> Result<(), OwnerActorError> {
        let Some(frame) = self.frames.get_mut(id) else {
            return Ok(());
        };
        if swapping {
            // A late swap from the parent must not retire a newly bound OOPIF target.
            if frame.target_id == target {
                frame.swapping = true;
            }
            return Ok(());
        }
        let mut removed = vec![id.to_owned()];
        let mut index = 0;
        while index < removed.len() {
            let parent = &removed[index];
            let children: Vec<_> = self
                .frames
                .iter()
                .filter(|(_, frame)| frame.parent_id.as_deref() == Some(parent.as_str()))
                .map(|(id, _)| id.clone())
                .collect();
            for child in children {
                if removed.contains(&child) {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                removed.push(child);
            }
            index += 1;
        }
        for id in removed {
            self.frames.remove(&id);
        }
        Ok(())
    }

    fn begin(
        &mut self,
        frame_id: &str,
        guid: &str,
        now: Instant,
    ) -> Result<ArtifactId, OwnerActorError> {
        if !valid_guid(guid)
            || self.entries.contains_key(guid)
            || self.tombstones.contains_key(guid)
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let binding = self
            .frames
            .get(frame_id)
            .filter(|frame| !frame.swapping)
            .cloned()
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if self.entries.len() >= MAX_DOWNLOADS || self.tombstones.len() >= MAX_DOWNLOAD_TOMBSTONES {
            return Err(OwnerActorError::StateOverflow);
        }
        let artifact_id = ArtifactId::new();
        self.entries.insert(
            guid.to_owned(),
            DownloadEntry {
                artifact_id: artifact_id.clone(),
                binding,
                received: 0,
                completed: false,
                canceled: false,
                cancel_requested: false,
                cancel_sent: false,
                deadline: now + DOWNLOAD_TIMEOUT,
                opened_identity: None,
            },
        );
        Ok(artifact_id)
    }

    fn begin_with_admission(
        &mut self,
        frame_id: &str,
        guid: &str,
        now: Instant,
        allowed: bool,
    ) -> Result<ArtifactId, OwnerActorError> {
        let artifact = self.begin(frame_id, guid, now)?;
        self.entries
            .get_mut(guid)
            .ok_or(OwnerActorError::OutcomeUncertain)?
            .cancel_requested = !allowed;
        Ok(artifact)
    }

    fn progress(
        &mut self,
        guid: &str,
        total: f64,
        received: f64,
        state: &str,
    ) -> Result<(), OwnerActorError> {
        if !valid_guid(guid)
            || !total.is_finite()
            || !received.is_finite()
            || total < 0.0
            || received < 0.0
            || total.fract() != 0.0
            || received.fract() != 0.0
            || total > 9_007_199_254_740_991.0
            || received > 9_007_199_254_740_991.0
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let total = total as u64;
        let received = received as u64;
        let entry = self
            .entries
            .get_mut(guid)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if received < entry.received || entry.completed || entry.canceled {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        entry.received = received;
        if total > MAX_DOWNLOAD_BYTES || received > MAX_DOWNLOAD_BYTES {
            entry.cancel_requested = true;
        }
        match state {
            "inProgress" => {}
            "completed" => {
                if total != 0 && total != received {
                    entry.cancel_requested = true;
                }
                if entry.cancel_requested {
                    entry.canceled = true;
                } else {
                    entry.completed = true;
                }
            }
            "canceled" => {
                entry.canceled = true;
            }
            _ => return Err(OwnerActorError::OutcomeUncertain),
        }
        Ok(())
    }

    fn expire(&mut self, now: Instant) -> Result<(), OwnerActorError> {
        for entry in self.entries.values_mut() {
            if entry.completed || entry.canceled {
                continue;
            }
            if now >= entry.deadline {
                if entry.cancel_sent {
                    return Err(OwnerActorError::OutcomeUncertain);
                }
                entry.cancel_requested = true;
            }
        }
        Ok(())
    }

    fn pending(
        &self,
        session: &SessionId,
        fence: &OwnershipFence,
        limit: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, OwnerActorError> {
        if !(1..=MAX_DOWNLOADS).contains(&limit) {
            return Err(OwnerActorError::Rejected);
        }
        Ok(self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.completed
                    && !e.cancel_requested
                    && &e.binding.session_id == session
                    && &e.binding.fence == fence
            })
            .take(limit)
            .map(|(guid, e)| e.completion(guid))
            .collect())
    }

    fn validate_completion(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<(), OwnerActorError> {
        if self.tombstones.get(&completion.guid) == Some(completion) {
            return Ok(());
        }
        let entry = self
            .entries
            .get(&completion.guid)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if !(entry.completed || entry.canceled) || entry.completion(&completion.guid) != *completion
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        Ok(())
    }

    fn finish_cleanup(
        &mut self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<(), OwnerActorError> {
        self.validate_completion(completion)?;
        if self.tombstones.get(&completion.guid) == Some(completion) {
            return Ok(());
        }
        if self.tombstones.len() >= MAX_DOWNLOAD_TOMBSTONES {
            return Err(OwnerActorError::StateOverflow);
        }
        self.tombstones
            .insert(completion.guid.clone(), completion.clone());
        self.entries.remove(&completion.guid);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct DownloadState {
    directory: Option<DownloadDirectory>,
    registry: DownloadRegistry,
    pub(super) runtime_modes: BTreeMap<String, bool>,
    unattributed_since: Option<Instant>,
    _inactive_scratch: Option<SandboxScratch>,
}

impl DownloadState {
    pub(super) fn new(directory: Option<DownloadDirectory>) -> Self {
        Self {
            directory,
            registry: DownloadRegistry::default(),
            runtime_modes: BTreeMap::new(),
            unattributed_since: None,
            _inactive_scratch: None,
        }
    }
    pub(super) fn disabled(scratch: Option<SandboxScratch>) -> Self {
        Self {
            _inactive_scratch: scratch,
            ..Self::default()
        }
    }
    pub(super) fn enabled(&self) -> bool {
        self.directory.is_some()
    }
    pub(super) fn sandbox_path(&self) -> String {
        format!("{SANDBOX_SCRATCH_PATH}/downloads")
    }
    pub(super) fn pending(
        &self,
        session: &SessionId,
        fence: &OwnershipFence,
        limit: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, OwnerActorError> {
        self.registry.pending(session, fence, limit)
    }
    pub(super) fn open(
        &mut self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<BrowserDownloadFile, OwnerActorError> {
        self.registry.validate_completion(completion)?;
        if !self
            .registry
            .entries
            .get(&completion.guid)
            .is_some_and(|entry| entry.completed && !entry.cancel_requested)
        {
            return Err(OwnerActorError::Rejected);
        }
        let opened = self
            .directory
            .as_ref()
            .ok_or(OwnerActorError::Rejected)?
            .open(completion)?;
        let entry = self
            .registry
            .entries
            .get_mut(&completion.guid)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if entry
            .opened_identity
            .as_ref()
            .is_some_and(|identity| identity != &opened.identity)
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        entry.opened_identity = Some(opened.identity.clone());
        Ok(opened)
    }
    pub(super) fn acknowledge(
        &mut self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<(), OwnerActorError> {
        self.registry.validate_completion(completion)?;
        if self.registry.tombstones.get(&completion.guid) == Some(completion) {
            return Ok(());
        }
        self.directory
            .as_ref()
            .ok_or(OwnerActorError::Rejected)?
            .cleanup(
                &completion.guid,
                self.registry
                    .entries
                    .get(&completion.guid)
                    .and_then(|entry| entry.opened_identity.as_ref()),
            )?;
        self.registry.finish_cleanup(completion)
    }
    pub(super) fn retire_target(&mut self, target: &str) {
        for frame in self
            .registry
            .frames
            .values_mut()
            .filter(|frame| frame.target_id == target)
        {
            frame.swapping = true;
        }
    }
    pub(super) fn retire_page(&mut self, page: &PageId) {
        for entry in self
            .registry
            .entries
            .values_mut()
            .filter(|entry| &entry.binding.page_id == page)
        {
            entry.cancel_requested = true;
            if entry.completed {
                entry.canceled = true;
            }
        }
    }
    pub(super) fn forget_context(&mut self, context: &str) -> Result<(), OwnerActorError> {
        if self
            .registry
            .entries
            .values()
            .any(|entry| entry.binding.context_id == context)
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        self.registry
            .frames
            .retain(|_, frame| frame.context_id != context);
        Ok(())
    }
}

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    fn download_frame_binding(
        &self,
        target_id: &str,
        route: &TargetRouteEntry,
        frame_id: &str,
        parent_id: Option<&str>,
    ) -> Result<FrameBinding, OwnerActorError> {
        let inherited = self
            .downloads
            .registry
            .frames
            .get(frame_id)
            .or_else(|| parent_id.and_then(|id| self.downloads.registry.frames.get(id)));
        let page_id = route
            .page_id
            .clone()
            .or_else(|| inherited.map(|frame| frame.page_id.clone()))
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let binding = FrameBinding {
            tenant_id: route.route.tenant_id.clone(),
            session_id: route.route.owner_session_id.clone(),
            fence: route.route.ownership_fence.clone(),
            page_id,
            context_id: route.route.browser_context_id.clone(),
            target_id: target_id.to_owned(),
            target_incarnation: route.target_incarnation,
            parent_id: parent_id.map(str::to_owned),
            swapping: false,
        };
        if inherited.is_some_and(|previous| !previous.same_owner(&binding)) {
            return Err(OwnerActorError::UnknownOwnership);
        }
        Ok(binding)
    }

    pub(super) async fn seed_download_frames(
        &mut self,
        target_id: &str,
        deadline: Option<Instant>,
    ) -> Result<(), OwnerActorError> {
        if !self.downloads.enabled() {
            return Ok(());
        }
        let route = self
            .routes
            .get(target_id)
            .cloned()
            .ok_or(OwnerActorError::UnknownOwnership)?;
        let response = self
            .command_event_first(
                "Page.getFrameTree",
                json!({}),
                Some(route.route.session_id.clone()),
                None,
                None,
                deadline,
            )
            .await?;
        let mut stack = vec![(
            response
                .get("frameTree")
                .ok_or(OwnerActorError::OutcomeUncertain)?,
            true,
        )];
        let mut count = 0;
        while let Some((tree, root)) = stack.pop() {
            count += 1;
            if count > MAX_FRAMES {
                return Err(OwnerActorError::StateOverflow);
            }
            let frame = tree.get("frame").ok_or(OwnerActorError::OutcomeUncertain)?;
            let id = frame
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| valid_identifier(id))
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            let parent = frame.get("parentId").and_then(Value::as_str);
            let binding = self.download_frame_binding(target_id, &route, id, parent)?;
            self.downloads.registry.register_frame(id, binding, root)?;
            if let Some(children) = tree.get("childFrames") {
                let children = children
                    .as_array()
                    .ok_or(OwnerActorError::OutcomeUncertain)?;
                if stack.len() + children.len() > MAX_FRAMES {
                    return Err(OwnerActorError::StateOverflow);
                }
                for child in children.iter().rev() {
                    stack.push((child, false));
                }
            }
        }
        Ok(())
    }

    pub(super) fn download_frame_event(
        &mut self,
        method: &str,
        cdp_session: Option<&str>,
        params: &Value,
    ) -> Result<(), OwnerActorError> {
        if !self.downloads.enabled() {
            return Ok(());
        }
        let observed = self
            .routes
            .iter()
            .find(|(_, route)| Some(route.route.session_id.as_str()) == cdp_session)
            .map(|(id, route)| (id.clone(), route.clone()));
        let (target_id, route) = match observed {
            Some(route) => route,
            None if self
                .retired_targets
                .values()
                .any(|retired| Some(retired.as_str()) == cdp_session) =>
            {
                return Ok(());
            }
            None => return Err(OwnerActorError::UnknownOwnership),
        };
        if method == "Page.frameDetached" {
            let id = params
                .get("frameId")
                .and_then(Value::as_str)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            let swap = match params.get("reason").and_then(Value::as_str) {
                Some("swap") => true,
                Some("remove") => false,
                _ => return Err(OwnerActorError::OutcomeUncertain),
            };
            return self.downloads.registry.detach_frame(id, &target_id, swap);
        }
        let frame = if method == "Page.frameNavigated" {
            params
                .get("frame")
                .ok_or(OwnerActorError::OutcomeUncertain)?
        } else {
            params
        };
        let id = frame
            .get(if method == "Page.frameNavigated" {
                "id"
            } else {
                "frameId"
            })
            .and_then(Value::as_str)
            .filter(|id| valid_identifier(id))
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let parent = frame
            .get(if method == "Page.frameNavigated" {
                "parentId"
            } else {
                "parentFrameId"
            })
            .and_then(Value::as_str);
        let binding = self.download_frame_binding(&target_id, &route, id, parent)?;
        self.downloads.registry.register_frame(
            id,
            binding,
            method == "Page.frameNavigated" && parent.is_none(),
        )
    }

    pub(super) fn download_event(
        &mut self,
        method: &str,
        params: &Value,
    ) -> Result<(), OwnerActorError> {
        if !self.downloads.enabled() {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let guid = params
            .get("guid")
            .and_then(Value::as_str)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if method == "Browser.downloadWillBegin" {
            let frame_id = params
                .get("frameId")
                .and_then(Value::as_str)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            let binding = self
                .downloads
                .registry
                .frames
                .get(frame_id)
                .ok_or(OwnerActorError::UnknownOwnership)?;
            let route = self
                .routes
                .get(&binding.target_id)
                .ok_or(OwnerActorError::UnknownOwnership)?;
            let context = self
                .contexts
                .get(&binding.context_id)
                .ok_or(OwnerActorError::UnknownOwnership)?;
            if context.lifecycle != ContextLifecycle::Active
                || context.closing_pages.contains(&binding.page_id)
                || context.ownership.fence != binding.fence
                || route.target_incarnation != binding.target_incarnation
                || route.route.ownership_fence != binding.fence
            {
                return Err(OwnerActorError::UnknownOwnership);
            }
            let cache = self.runtime_safety.clone();
            let digest = self.artifact_identity.binary_digest.to_string();
            let admit = |allowed| {
                self.downloads.registry.begin_with_admission(
                    frame_id,
                    guid,
                    Instant::now(),
                    allowed,
                )
            };
            match cache {
                Some(cache) => {
                    let mut admit = admit;
                    if let Ok(result) = cache.with_fresh_snapshot(|snapshot| {
                        admit(
                            !snapshot.downloads_disabled()
                                && !snapshot.chromium_build_disabled(&digest),
                        )
                    }) {
                        result?;
                    } else {
                        admit(false)?;
                    }
                }
                None => {
                    let mut admit = admit;
                    admit(true)?;
                }
            }
            return Ok(());
        }
        let total = params
            .get("totalBytes")
            .and_then(Value::as_f64)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let received = params
            .get("receivedBytes")
            .and_then(Value::as_f64)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        let state = params
            .get("state")
            .and_then(Value::as_str)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        self.downloads
            .registry
            .progress(guid, total, received, state)
    }

    pub(super) async fn service_downloads(&mut self) -> Result<(), OwnerActorError> {
        if !self.downloads.enabled() {
            return Ok(());
        }
        let allow = self.runtime_download_admission();
        let contexts = self
            .contexts
            .iter()
            .filter(|(_, entry)| entry.lifecycle == ContextLifecycle::Active)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        self.downloads
            .runtime_modes
            .retain(|id, _| self.contexts.contains_key(id));
        for context_id in contexts {
            if self.downloads.runtime_modes.get(&context_id) == Some(&allow) {
                continue;
            }
            let client = self.client.clone();
            let expires = self.context_command_deadline(Instant::now() + self.command_timeout);
            let command = client.command(
                "Browser.setDownloadBehavior",
                if allow {
                    json!({"behavior":"allowAndName", "browserContextId":context_id, "downloadPath":self.downloads.sandbox_path(), "eventsEnabled":true})
                } else {
                    json!({"behavior":"deny", "browserContextId":context_id, "eventsEnabled":true})
                }, None, Some(self.command_timeout),
            );
            let response = self.control_ack(command, expires).await?;
            if !response.is_object() {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            self.downloads.runtime_modes.insert(context_id, allow);
        }
        if !allow {
            for entry in self.downloads.registry.entries.values_mut() {
                entry.cancel_requested = true;
                if entry.completed {
                    entry.canceled = true;
                }
            }
        }
        self.downloads.registry.expire(Instant::now())?;
        let directory = self
            .downloads
            .directory
            .as_ref()
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if directory.inspect(&self.downloads.registry)? {
            // File writes and queued CDP WillBegin events race. Give the bounded event
            // lane a chance to establish ownership; no unidentified file is imported.
            let since = self
                .downloads
                .unattributed_since
                .get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(1) {
                return Err(OwnerActorError::OutcomeUncertain);
            }
        } else {
            self.downloads.unattributed_since = None;
        }
        for (guid, entry) in &mut self.downloads.registry.entries {
            for name in [guid.clone(), format!("{guid}.crdownload")] {
                let path = format!("/proc/self/fd/{}/{}", directory.directory.as_raw_fd(), name);
                match std::fs::symlink_metadata(path) {
                    Ok(metadata) if metadata.len() > MAX_DOWNLOAD_BYTES => {
                        entry.cancel_requested = true;
                        if entry.completed {
                            entry.canceled = true;
                        }
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return Err(OwnerActorError::OutcomeUncertain),
                }
            }
        }
        let cancel: Vec<_> = self
            .downloads
            .registry
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.cancel_requested && !entry.cancel_sent && !entry.canceled && !entry.completed
            })
            .map(|(guid, entry)| (guid.clone(), entry.binding.context_id.clone()))
            .collect();
        for (guid, context_id) in cancel {
            let client = self.client.clone();
            let expires = self.context_command_deadline(Instant::now() + self.command_timeout);
            let command = client.command(
                "Browser.cancelDownload",
                json!({"guid":guid,"browserContextId":context_id}),
                None,
                Some(self.command_timeout),
            );
            let response = self.control_ack(command, expires).await?;
            if !response.is_object() {
                return Err(OwnerActorError::OutcomeUncertain);
            }
            let entry = self
                .downloads
                .registry
                .entries
                .get_mut(&guid)
                .ok_or(OwnerActorError::OutcomeUncertain)?;
            entry.cancel_sent = true;
            entry.deadline = Instant::now() + CANCEL_TIMEOUT;
        }
        let canceled: Vec<_> = self
            .downloads
            .registry
            .entries
            .iter()
            .filter(|(_, entry)| entry.canceled)
            .map(|(guid, entry)| entry.completion(guid))
            .collect();
        for completion in canceled {
            self.downloads.acknowledge(&completion)?;
        }
        Ok(())
    }

    pub(super) fn runtime_download_admission(&self) -> bool {
        self.downloads.enabled()
            && self.runtime_safety.as_ref().is_none_or(|cache| {
                cache
                    .with_fresh_snapshot(|snapshot| {
                        !snapshot.downloads_disabled()
                            && !snapshot.chromium_build_disabled(
                                &self.artifact_identity.binary_digest.to_string(),
                            )
                    })
                    .unwrap_or(false)
            })
    }

    pub(super) async fn close_downloads(
        &mut self,
        context_id: &str,
        page_id: Option<&PageId>,
    ) -> Result<(), OwnerActorError> {
        if !self.downloads.enabled() {
            return Ok(());
        }
        for entry in self
            .downloads
            .registry
            .entries
            .values_mut()
            .filter(|entry| {
                entry.binding.context_id == context_id
                    && page_id.is_none_or(|page| &entry.binding.page_id == page)
            })
        {
            entry.cancel_requested = true;
            if entry.completed {
                entry.canceled = true;
            }
        }
        let expires = Instant::now() + CANCEL_TIMEOUT;
        loop {
            self.service_downloads().await?;
            if !self.downloads.registry.entries.values().any(|entry| {
                entry.binding.context_id == context_id
                    && page_id.is_none_or(|page| &entry.binding.page_id == page)
            }) {
                return Ok(());
            }
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => return Err(OwnerActorError::OutcomeUncertain),
                control = self.control_requests.recv() => {
                    self.start_control(control.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                completed = self.control_tasks.next(), if !self.control_tasks.is_empty() => {
                    self.finish_control(completed.ok_or(OwnerActorError::OutcomeUncertain)?)?;
                }
                () = tokio::time::sleep_until(expires.into()) => return Err(OwnerActorError::OutcomeUncertain),
                incoming = self.events.recv() => self.handle_incoming(incoming.ok_or(OwnerActorError::OutcomeUncertain)?, None)?,
                () = tokio::time::sleep(DOWNLOAD_TICK) => {}
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use browserd_core::WorkerId;

    fn frame() -> FrameBinding {
        FrameBinding {
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            fence: OwnershipFence::new(WorkerId::new("download-owner").unwrap(), 1, 2, 3),
            page_id: PageId::new(),
            context_id: "owned-context".to_owned(),
            target_id: "owned-target".to_owned(),
            target_incarnation: 1,
            parent_id: None,
            swapping: false,
        }
    }

    #[test]
    fn autonomous_download_rejected_at_admission_never_becomes_importable_on_completion() {
        let mut registry = DownloadRegistry::default();
        let binding = frame();
        registry
            .register_frame("frame", binding.clone(), true)
            .unwrap();
        let guid = uuid::Uuid::new_v4().to_string();
        registry
            .begin_with_admission("frame", &guid, Instant::now(), false)
            .unwrap();
        assert!(registry.entries[&guid].cancel_requested);
        registry.progress(&guid, 10.0, 10.0, "completed").unwrap();
        assert!(
            registry.entries[&guid].canceled,
            "racing completion cannot restore publication authority"
        );
        assert!(
            registry
                .pending(&binding.session_id, &binding.fence, MAX_DOWNLOADS)
                .unwrap()
                .is_empty()
        );
        assert!(!registry.entries[&guid].completed);
    }

    fn file_fixture() -> (tempfile::TempDir, DownloadState, BrowserDownloadCompletion) {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let mut state = DownloadState::new(Some(DownloadDirectory {
            directory,
            _scratch: None,
        }));
        let binding = frame();
        state
            .registry
            .register_frame("frame", binding.clone(), true)
            .unwrap();
        let guid = uuid::Uuid::new_v4().to_string();
        state
            .registry
            .begin("frame", &guid, Instant::now())
            .unwrap();
        state
            .registry
            .progress(&guid, 12.0, 12.0, "completed")
            .unwrap();
        let completion = state
            .pending(&binding.session_id, &binding.fence, 4)
            .unwrap()
            .remove(0);
        (temporary, state, completion)
    }

    #[test]
    fn download_import_rejects_symlinks_and_hardlinks_without_removing_them() {
        let (temporary, mut state, completion) = file_fixture();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"twelve-bytes").unwrap();
        let path = temporary.path().join(&completion.guid);
        std::os::unix::fs::symlink(outside.path(), &path).unwrap();
        assert!(state.open(&completion).is_err());
        assert!(state.acknowledge(&completion).is_err());
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"twelve-bytes");
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(outside.path(), &path).unwrap();
        assert!(state.open(&completion).is_err());
        assert!(state.acknowledge(&completion).is_err());
        assert!(state.registry.entries.contains_key(&completion.guid));
    }

    #[test]
    fn download_ack_rejects_same_guid_replacement_and_retains_ownership() {
        let (temporary, mut state, completion) = file_fixture();
        let path = temporary.path().join(&completion.guid);
        std::fs::write(&path, b"twelve-bytes").unwrap();
        let opened = state.open(&completion).unwrap();
        opened.validate_unchanged().unwrap();
        std::fs::rename(&path, temporary.path().join("original")).unwrap();
        std::fs::write(&path, b"other--bytes").unwrap();
        assert!(state.open(&completion).is_err());
        assert!(state.acknowledge(&completion).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"other--bytes");
        assert!(state.registry.entries.contains_key(&completion.guid));
    }

    #[test]
    fn download_read_capability_detects_mutation_and_ack_is_exact_and_idempotent() {
        let (temporary, mut state, completion) = file_fixture();
        let path = temporary.path().join(&completion.guid);
        std::fs::write(&path, b"twelve-bytes").unwrap();
        let opened = state.open(&completion).unwrap();
        opened.validate_unchanged().unwrap();
        std::fs::write(&path, b"changed").unwrap();
        assert!(opened.validate_unchanged().is_err());
        assert!(state.acknowledge(&completion).is_err());
        drop(opened);

        let (temporary, mut state, completion) = file_fixture();
        let path = temporary.path().join(&completion.guid);
        std::fs::write(&path, b"twelve-bytes").unwrap();
        let opened = state.open(&completion).unwrap();
        assert_eq!(opened.size_bytes(), 12);
        drop(opened);
        state.acknowledge(&completion).unwrap();
        state.acknowledge(&completion).unwrap();
        assert!(!path.exists());
        assert!(state.registry.entries.is_empty());
    }

    #[test]
    fn download_guid_is_a_canonical_uuid_not_a_path() {
        assert!(valid_guid("3c880225-d605-4117-bebe-e3f69186206c"));
        for value in [
            "../outside",
            "guid",
            "3c880225d6054117bebee3f69186206c",
            "3C880225-D605-4117-BEBE-E3F69186206C",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(!valid_guid(value), "{value}");
        }
    }

    #[test]
    fn download_empty_file_completes_and_can_be_read_and_acknowledged() {
        let (temporary, mut state, original) = file_fixture();
        let guid = uuid::Uuid::new_v4().to_string();
        state
            .registry
            .begin("frame", &guid, Instant::now())
            .unwrap();
        state
            .registry
            .progress(&guid, 0.0, 0.0, "completed")
            .unwrap();
        let completion = state
            .pending(&original.session_id, &original.fence, 4)
            .unwrap()
            .into_iter()
            .find(|completion| completion.guid == guid)
            .unwrap();
        std::fs::write(temporary.path().join(&guid), []).unwrap();
        let opened = state.open(&completion).unwrap();
        assert_eq!(opened.size_bytes(), 0);
        opened.validate_unchanged().unwrap();
        drop(opened);
        state.acknowledge(&completion).unwrap();
    }

    #[test]
    fn download_unknown_frame_and_duplicate_guid_never_gain_ownership() {
        let mut registry = DownloadRegistry::default();
        let guid = uuid::Uuid::new_v4().to_string();
        assert!(registry.begin("unknown", &guid, Instant::now()).is_err());
        registry.register_frame("frame", frame(), true).unwrap();
        let artifact = registry.begin("frame", &guid, Instant::now()).unwrap();
        assert!(registry.begin("frame", &guid, Instant::now()).is_err());
        assert_eq!(registry.entries[&guid].artifact_id, artifact);
    }

    #[test]
    fn download_oopif_swap_preserves_page_but_rejects_foreign_rebinding() {
        let mut registry = DownloadRegistry::default();
        let original = frame();
        registry
            .register_frame("frame", original.clone(), true)
            .unwrap();
        registry
            .detach_frame("frame", &original.target_id, true)
            .unwrap();
        assert!(
            registry
                .begin("frame", &uuid::Uuid::new_v4().to_string(), Instant::now())
                .is_err()
        );
        let mut replacement = original.clone();
        replacement.target_id = "oopif-target".to_owned();
        replacement.target_incarnation = 2;
        registry
            .register_frame("frame", replacement.clone(), true)
            .unwrap();
        let guid = uuid::Uuid::new_v4().to_string();
        registry.begin("frame", &guid, Instant::now()).unwrap();
        assert_eq!(registry.entries[&guid].binding.page_id, original.page_id);
        assert_eq!(
            registry.entries[&guid].binding.target_id,
            replacement.target_id
        );
        let mut foreign = replacement;
        foreign.session_id = SessionId::new();
        assert!(registry.register_frame("frame", foreign, true).is_err());
    }

    #[test]
    fn download_slots_are_retained_until_exact_ack() {
        let mut registry = DownloadRegistry::default();
        let binding = frame();
        registry
            .register_frame("frame", binding.clone(), true)
            .unwrap();
        let guids: Vec<_> = (0..4).map(|_| uuid::Uuid::new_v4().to_string()).collect();
        for guid in &guids {
            registry.begin("frame", guid, Instant::now()).unwrap();
        }
        assert!(
            registry
                .begin("frame", &uuid::Uuid::new_v4().to_string(), Instant::now())
                .is_err()
        );
        registry
            .progress(&guids[0], 12.0, 12.0, "completed")
            .unwrap();
        let pending = registry
            .pending(&binding.session_id, &binding.fence, 4)
            .unwrap();
        assert_eq!(pending.len(), 1);
        let mut wrong = pending[0].clone();
        wrong.artifact_id = ArtifactId::new();
        assert!(registry.validate_completion(&wrong).is_err());
        assert_eq!(
            registry
                .pending(&binding.session_id, &binding.fence, 4)
                .unwrap(),
            pending
        );
        registry.finish_cleanup(&pending[0]).unwrap();
        registry.finish_cleanup(&pending[0]).unwrap();
        assert!(registry.begin("frame", &guids[0], Instant::now()).is_err());
        registry
            .begin("frame", &uuid::Uuid::new_v4().to_string(), Instant::now())
            .unwrap();
    }

    #[test]
    fn download_limit_and_timeout_cancel_without_publishing() {
        let mut registry = DownloadRegistry::default();
        let binding = frame();
        registry
            .register_frame("frame", binding.clone(), true)
            .unwrap();
        let started = Instant::now();
        let large = uuid::Uuid::new_v4().to_string();
        registry.begin("frame", &large, started).unwrap();
        registry
            .progress(&large, (MAX_DOWNLOAD_BYTES + 1) as f64, 0.0, "inProgress")
            .unwrap();
        assert!(registry.entries[&large].cancel_requested);
        let stalled = uuid::Uuid::new_v4().to_string();
        registry.begin("frame", &stalled, started).unwrap();
        registry.expire(started + DOWNLOAD_TIMEOUT).unwrap();
        assert!(registry.entries[&stalled].cancel_requested);
        assert!(
            registry
                .pending(&binding.session_id, &binding.fence, 4)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn download_progress_requires_finite_monotonic_bytes_and_known_guid() {
        let mut registry = DownloadRegistry::default();
        registry.register_frame("frame", frame(), true).unwrap();
        let guid = uuid::Uuid::new_v4().to_string();
        assert!(registry.progress(&guid, 0.0, 0.0, "inProgress").is_err());
        registry.begin("frame", &guid, Instant::now()).unwrap();
        assert!(
            registry
                .progress(&guid, f64::NAN, 0.0, "inProgress")
                .is_err()
        );
        assert!(registry.progress(&guid, 0.0, -1.0, "inProgress").is_err());
        registry.progress(&guid, 0.0, 10.0, "inProgress").unwrap();
        assert!(registry.progress(&guid, 0.0, 9.0, "inProgress").is_err());
    }
}
