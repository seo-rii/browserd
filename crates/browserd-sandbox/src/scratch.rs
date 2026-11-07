//! A bounded tmpfs directory handed over by the still-gated, authenticated launch helper.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::stat::fstat;
use nix::sys::statfs::fstatfs;
use nix::sys::statvfs::fstatvfs;
use serde::{Deserialize, Serialize};

use crate::{DedicatedEgressProxyBinding, LaunchSpec, SandboxError};

pub use browserd_launch_gate::{SANDBOX_SCRATCH_MAX_BYTES, SANDBOX_SCRATCH_PATH};

const SCRATCH_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScratchMetadata {
    version: u32,
    sandbox_path: String,
    max_bytes: u64,
    owner_uid: u32,
    device: u64,
    inode: u64,
    binding: DedicatedEgressProxyBinding,
}

impl ScratchMetadata {
    #[must_use]
    pub fn sandbox_path(&self) -> &str {
        &self.sandbox_path
    }
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }
    #[must_use]
    pub const fn binding(&self) -> &DedicatedEgressProxyBinding {
        &self.binding
    }
    #[must_use]
    pub fn matches_launch(&self, spec: &LaunchSpec) -> bool {
        self.valid() && self.binding.matches_launch(spec)
    }
    pub(crate) fn valid(&self) -> bool {
        self.version == SCRATCH_VERSION
            && self.sandbox_path == SANDBOX_SCRATCH_PATH
            && self.max_bytes == SANDBOX_SCRATCH_MAX_BYTES
            && self.device != 0
            && self.inode != 0
    }
}

#[derive(Debug)]
pub struct SandboxScratch {
    directory: OwnedFd,
    metadata: ScratchMetadata,
}

fn invalid() -> SandboxError {
    SandboxError::Backend("invalid bounded scratch capability".into())
}

fn directory_identity(directory: &impl AsFd, owner_uid: u32) -> Result<(u64, u64), SandboxError> {
    let metadata = fstat(directory).map_err(|_| invalid())?;
    let flags = fcntl(directory, FcntlArg::F_GETFD).map_err(|_| invalid())?;
    let status = fcntl(directory, FcntlArg::F_GETFL).map_err(|_| invalid())?;
    let filesystem = fstatfs(directory).map_err(|_| invalid())?;
    let limits = fstatvfs(directory).map_err(|_| invalid())?;
    let capacity = limits
        .blocks()
        .checked_mul(limits.fragment_size())
        .ok_or_else(invalid)?;
    if metadata.st_mode & nix::libc::S_IFMT != nix::libc::S_IFDIR
        || metadata.st_mode & 0o7777 != 0o700
        || metadata.st_uid != owner_uid
        || !FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC)
        || status & nix::libc::O_PATH != 0
        || status & nix::libc::O_ACCMODE != nix::libc::O_RDONLY
        || filesystem.filesystem_type().0 != nix::libc::TMPFS_MAGIC
        || capacity == 0
        || capacity > SANDBOX_SCRATCH_MAX_BYTES
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(invalid());
    }
    Ok((metadata.st_dev, metadata.st_ino))
}

/// Validates a launch-helper offer before Chromium may execute. This does not grant session
/// authority; only a subsequent exact ingress binding can construct an exportable capability.
pub fn validate_scratch_directory(directory: &OwnedFd) -> Result<(), SandboxError> {
    directory_identity(directory, nix::unistd::geteuid().as_raw()).map(|_| ())
}

impl SandboxScratch {
    pub(crate) fn from_launch_fd(
        directory: OwnedFd,
        binding: DedicatedEgressProxyBinding,
    ) -> Result<Self, SandboxError> {
        let owner_uid = nix::unistd::geteuid().as_raw();
        let (device, inode) = directory_identity(&directory, owner_uid)?;
        let metadata = ScratchMetadata {
            version: SCRATCH_VERSION,
            sandbox_path: SANDBOX_SCRATCH_PATH.to_owned(),
            max_bytes: SANDBOX_SCRATCH_MAX_BYTES,
            owner_uid,
            device,
            inode,
            binding,
        };
        Ok(Self {
            directory,
            metadata,
        })
    }

    /// Revalidates received OS metadata against the authenticated handoff's immutable facts.
    /// The RPC receiver also checks owner_uid and the full binding before acknowledging transfer.
    pub fn from_owned_fd(
        directory: OwnedFd,
        metadata: ScratchMetadata,
    ) -> Result<Self, SandboxError> {
        if !metadata.valid()
            || directory_identity(&directory, metadata.owner_uid)?
                != (metadata.device, metadata.inode)
        {
            return Err(invalid());
        }
        Ok(Self {
            directory,
            metadata,
        })
    }
    #[must_use]
    pub const fn metadata(&self) -> &ScratchMetadata {
        &self.metadata
    }
    #[must_use]
    pub fn directory(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }
    #[must_use]
    pub fn into_owned_fd(self) -> OwnedFd {
        self.directory
    }
}
