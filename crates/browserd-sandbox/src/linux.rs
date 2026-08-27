use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{EgressFence, LeaseId, ShardFence, ShardId, TenantId};
use browserd_launch_gate::APPROVAL_FRAME;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl, open, openat};
use nix::sys::signal::Signal;
use nix::sys::stat::{Mode, fstat};
use nix::sys::statfs::fstatfs;
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
use nix::unistd::{pipe2, write as write_fd};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;

use crate::journal::{
    FilePreparedShardJournal, PreparedShardCleanupFailure, PreparedShardCleanupPermit,
    PreparedShardCleanupStage, PreparedShardCleanupStageStatus, PreparedShardEffect,
    PreparedShardEffectPermit, PreparedShardJournalRecord, PreparedShardRecoveryDisposition,
    PreparedShardRecoveryLocators,
};
use crate::{
    CleanupReason, DedicatedEgressSpec, InspectResources, LaunchSpec, SandboxBackend,
    SandboxCapabilities, SandboxError, SandboxHandle,
};

/// Chromium's fixed command-input descriptor for `--remote-debugging-pipe`.
pub const CHROMIUM_CDP_READ_FD: i32 = 3;
/// Chromium's fixed event/output descriptor for `--remote-debugging-pipe`.
pub const CHROMIUM_CDP_WRITE_FD: i32 = 4;

const BWRAP_INFO_TIMEOUT: Duration = Duration::from_secs(1);
const PREPARED_CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(2);
const PREPARED_CHILD_EXIT_POLL: Duration = Duration::from_millis(5);
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const NSFS_MAGIC: u64 = 0x6e73_6673;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupLimits {
    memory_max: u64,
    memory_high: u64,
    pids_max: u32,
    cpu_quota: u64,
    cpu_period: u64,
}

impl CgroupLimits {
    pub fn new(
        memory_max: u64,
        memory_high: u64,
        pids_max: u32,
        cpu_quota: u64,
        cpu_period: u64,
    ) -> Result<Self, SandboxError> {
        if memory_max == 0
            || memory_high == 0
            || memory_high > memory_max
            || pids_max == 0
            || cpu_quota == 0
            || cpu_period == 0
        {
            return Err(SandboxError::Backend("invalid cgroup limits".into()));
        }
        Ok(Self {
            memory_max,
            memory_high,
            pids_max,
            cpu_quota,
            cpu_period,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChromiumRuntime {
    host_executable: PathBuf,
    sandbox_executable: PathBuf,
}

impl ChromiumRuntime {
    #[must_use]
    pub fn new(
        host_executable: impl Into<PathBuf>,
        sandbox_executable: impl Into<PathBuf>,
    ) -> Self {
        Self {
            host_executable: host_executable.into(),
            sandbox_executable: sandbox_executable.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchGateRuntime {
    host_executable: PathBuf,
    sandbox_executable: PathBuf,
}

impl LaunchGateRuntime {
    #[must_use]
    pub fn new(
        host_executable: impl Into<PathBuf>,
        sandbox_executable: impl Into<PathBuf>,
    ) -> Self {
        Self {
            host_executable: host_executable.into(),
            sandbox_executable: sandbox_executable.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyMount {
    source: PathBuf,
    destination: PathBuf,
}

impl ReadOnlyMount {
    #[must_use]
    pub fn new(source: impl Into<PathBuf>, destination: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LinuxSandboxConfig {
    cgroup_root: PathBuf,
    sandbox_root: PathBuf,
    bwrap_executable: PathBuf,
    chromium: ChromiumRuntime,
    launch_gate: LaunchGateRuntime,
    read_only_mounts: Vec<ReadOnlyMount>,
    limits: CgroupLimits,
    seccomp_fd: i32,
    termination_grace: Duration,
    poll_interval: Duration,
}

impl LinuxSandboxConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I>(
        cgroup_root: impl Into<PathBuf>,
        sandbox_root: impl Into<PathBuf>,
        bwrap_executable: impl Into<PathBuf>,
        chromium: ChromiumRuntime,
        launch_gate: LaunchGateRuntime,
        read_only_mounts: I,
        limits: CgroupLimits,
        seccomp_fd: i32,
        termination_grace: Duration,
        poll_interval: Duration,
    ) -> Result<Self, SandboxError>
    where
        I: IntoIterator<Item = ReadOnlyMount>,
    {
        let cgroup_root = cgroup_root.into();
        let sandbox_root = sandbox_root.into();
        let bwrap_executable = bwrap_executable.into();
        validate_absolute_path(&cgroup_root)?;
        validate_absolute_path(&sandbox_root)?;
        validate_absolute_path(&bwrap_executable)?;
        validate_absolute_path(&chromium.host_executable)?;
        validate_absolute_path(&chromium.sandbox_executable)?;
        validate_absolute_path(&launch_gate.host_executable)?;
        validate_absolute_path(&launch_gate.sandbox_executable)?;
        if cgroup_root == Path::new("/sys/fs/cgroup")
            || cgroup_root == Path::new("/")
            || sandbox_root == Path::new("/")
            || cgroup_root.components().count() < 5
            || sandbox_root.components().count() < 4
            || seccomp_fd < 3
            || [CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD].contains(&seccomp_fd)
            || termination_grace.is_zero()
            || poll_interval.is_zero()
            || poll_interval > termination_grace
            || [
                "/home",
                "/root",
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/run/user",
                "/proc",
                "/sys",
            ]
            .into_iter()
            .any(|mutable| launch_gate.host_executable.starts_with(mutable))
            || launch_gate.host_executable.starts_with(&cgroup_root)
            || launch_gate.host_executable.starts_with(&sandbox_root)
            || launch_gate.host_executable == bwrap_executable
            || launch_gate.host_executable == chromium.host_executable
            || ["/proc", "/dev", "/sys", "/tmp", "/profile"]
                .into_iter()
                .any(|protected| launch_gate.sandbox_executable.starts_with(protected))
            || launch_gate
                .sandbox_executable
                .starts_with(&chromium.sandbox_executable)
            || chromium
                .sandbox_executable
                .starts_with(&launch_gate.sandbox_executable)
        {
            return Err(SandboxError::Backend(
                "unsafe Linux sandbox configuration".into(),
            ));
        }
        let read_only_mounts: Vec<_> = read_only_mounts.into_iter().collect();
        for mount in &read_only_mounts {
            validate_absolute_path(&mount.source)?;
            validate_absolute_path(&mount.destination)?;
            if mount.destination == Path::new("/")
                || mount.source.starts_with("/home")
                || mount.source.starts_with("/root")
                || ["/proc", "/dev", "/tmp", "/profile"]
                    .into_iter()
                    .any(|protected| mount.destination.starts_with(protected))
            {
                return Err(SandboxError::Backend(
                    "unsafe read-only runtime mount".into(),
                ));
            }
            if mount
                .destination
                .starts_with(&launch_gate.sandbox_executable)
                || launch_gate
                    .sandbox_executable
                    .starts_with(&mount.destination)
            {
                return Err(SandboxError::Backend(
                    "runtime mount overlaps launch gate".into(),
                ));
            }
        }
        Ok(Self {
            cgroup_root,
            sandbox_root,
            bwrap_executable,
            chromium,
            launch_gate,
            read_only_mounts,
            limits,
            seccomp_fd,
            termination_grace,
            poll_interval,
        })
    }
}

fn validate_absolute_path(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(SandboxError::Backend(format!(
            "unsafe sandbox path: {}",
            path.display()
        )));
    }
    Ok(())
}

pub trait SandboxFilesystem: Send + Sync + 'static {
    fn is_directory(&self, path: &Path) -> Result<bool, SandboxError>;
    fn is_file(&self, path: &Path) -> Result<bool, SandboxError>;
    fn is_writable(&self, path: &Path) -> Result<bool, SandboxError>;
    fn contains_symlink(&self, path: &Path) -> Result<bool, SandboxError>;
    fn create_directory(&self, path: &Path) -> Result<(), SandboxError>;
    fn write_file(&self, path: &Path, value: &str) -> Result<(), SandboxError>;
    fn read_file(&self, path: &Path) -> Result<String, SandboxError>;
    fn remove_directory(&self, path: &Path) -> Result<(), SandboxError>;
}

#[derive(Clone, Debug)]
pub struct StdSandboxFilesystem {
    mutation_roots: [PathBuf; 2],
}

impl StdSandboxFilesystem {
    pub fn new(
        cgroup_root: impl Into<PathBuf>,
        sandbox_root: impl Into<PathBuf>,
    ) -> Result<Self, SandboxError> {
        let cgroup_root = cgroup_root.into();
        let sandbox_root = sandbox_root.into();
        validate_absolute_path(&cgroup_root)?;
        validate_absolute_path(&sandbox_root)?;
        if cgroup_root == Path::new("/sys/fs/cgroup")
            || cgroup_root == Path::new("/")
            || sandbox_root == Path::new("/")
        {
            return Err(SandboxError::Backend("mutation root is too broad".into()));
        }
        let filesystem = Self {
            mutation_roots: [cgroup_root, sandbox_root],
        };
        for root in &filesystem.mutation_roots {
            if filesystem.contains_symlink(root)? {
                return Err(SandboxError::Backend(
                    "mutation root contains a symlink".into(),
                ));
            }
        }
        Ok(filesystem)
    }

    fn validate_mutation_path(&self, path: &Path) -> Result<(), SandboxError> {
        validate_absolute_path(path)?;
        if !self
            .mutation_roots
            .iter()
            .any(|root| path.starts_with(root) && path != root)
        {
            return Err(SandboxError::Backend(
                "mutation escaped configured root".into(),
            ));
        }
        if self.contains_symlink(path)? {
            return Err(SandboxError::Backend(
                "mutation path contains a symlink".into(),
            ));
        }
        Ok(())
    }
}

impl SandboxFilesystem for StdSandboxFilesystem {
    fn is_directory(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(fs::metadata(path).is_ok_and(|metadata| metadata.is_dir()))
    }

    fn is_file(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(fs::metadata(path).is_ok_and(|metadata| metadata.is_file()))
    }

    fn is_writable(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(fs::metadata(path)
            .map(|metadata| !metadata.permissions().readonly())
            .unwrap_or(false))
    }

    fn contains_symlink(&self, path: &Path) -> Result<bool, SandboxError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(SandboxError::Backend(error.to_string())),
            }
        }
        Ok(false)
    }

    fn create_directory(&self, path: &Path) -> Result<(), SandboxError> {
        self.validate_mutation_path(path)?;
        fs::create_dir(path).map_err(|error| SandboxError::Backend(error.to_string()))
    }

    fn write_file(&self, path: &Path, value: &str) -> Result<(), SandboxError> {
        self.validate_mutation_path(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        file.write_all(value.as_bytes())
            .map_err(|error| SandboxError::Backend(error.to_string()))
    }

    fn read_file(&self, path: &Path) -> Result<String, SandboxError> {
        fs::read_to_string(path).map_err(|error| SandboxError::Backend(error.to_string()))
    }

    fn remove_directory(&self, path: &Path) -> Result<(), SandboxError> {
        self.validate_mutation_path(path)?;
        if path.starts_with(&self.mutation_roots[0]) {
            fs::remove_dir(path).map_err(|error| SandboxError::Backend(error.to_string()))
        } else {
            fs::remove_dir_all(path).map_err(|error| SandboxError::Backend(error.to_string()))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildIdentity {
    pid: u32,
    start_time_ticks: u64,
}

impl ChildIdentity {
    #[must_use]
    pub const fn new(pid: u32, start_time_ticks: u64) -> Self {
        Self {
            pid,
            start_time_ticks,
        }
    }

    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NetworkNamespaceIdentity {
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// An exact, close-on-exec capability that pins one Linux network namespace.
#[derive(Debug)]
pub struct PinnedNetworkNamespace {
    descriptor: Arc<OwnedFd>,
    identity: NetworkNamespaceIdentity,
}

impl PinnedNetworkNamespace {
    pub fn from_owned_fd(descriptor: OwnedFd) -> Result<Self, SandboxError> {
        let filesystem = fstatfs(&descriptor).map_err(|error| {
            SandboxError::Backend(format!("network namespace filesystem type: {error}"))
        })?;
        if filesystem.filesystem_type().0 as u64 != NSFS_MAGIC {
            return Err(SandboxError::Backend(
                "network namespace capability is not an nsfs descriptor".into(),
            ));
        }
        let descriptor_flags = fcntl(&descriptor, FcntlArg::F_GETFD).map_err(|error| {
            SandboxError::Backend(format!("network namespace descriptor flags: {error}"))
        })?;
        if !FdFlag::from_bits_truncate(descriptor_flags).contains(FdFlag::FD_CLOEXEC) {
            return Err(SandboxError::Backend(
                "network namespace capability is not close-on-exec".into(),
            ));
        }
        // SAFETY: NS_GET_NSTYPE takes no third argument and only queries the namespace referred to
        // by the still-owned descriptor.
        let namespace_type =
            unsafe { nix::libc::ioctl(descriptor.as_raw_fd(), nix::libc::NS_GET_NSTYPE) };
        if namespace_type != nix::libc::CLONE_NEWNET {
            if namespace_type < 0 {
                return Err(SandboxError::Backend(format!(
                    "network namespace type: {}",
                    std::io::Error::last_os_error()
                )));
            }
            return Err(SandboxError::Backend(
                "namespace capability is not a network namespace".into(),
            ));
        }
        let metadata = fstat(&descriptor).map_err(|error| {
            SandboxError::Backend(format!("network namespace metadata: {error}"))
        })?;
        Ok(Self {
            descriptor: Arc::new(descriptor),
            identity: NetworkNamespaceIdentity {
                device: metadata.st_dev,
                inode: metadata.st_ino,
            },
        })
    }

    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    #[must_use]
    pub const fn identity(&self) -> NetworkNamespaceIdentity {
        self.identity
    }

    fn clone_for_owner(&self) -> Self {
        Self {
            descriptor: Arc::clone(&self.descriptor),
            identity: self.identity,
        }
    }
}

#[derive(Debug)]
pub struct PreparedLinuxChild {
    identity: ChildIdentity,
    network_namespace: PinnedNetworkNamespace,
}

impl PreparedLinuxChild {
    #[must_use]
    pub const fn new(identity: ChildIdentity, network_namespace: PinnedNetworkNamespace) -> Self {
        Self {
            identity,
            network_namespace,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> ChildIdentity {
        self.identity
    }

    #[must_use]
    pub const fn network_namespace(&self) -> &PinnedNetworkNamespace {
        &self.network_namespace
    }

    #[must_use]
    pub fn into_parts(self) -> (ChildIdentity, PinnedNetworkNamespace) {
        (self.identity, self.network_namespace)
    }
}

fn open_pidfd(pid: u32) -> Result<OwnedFd, SandboxError> {
    let pid =
        i32::try_from(pid).map_err(|_| SandboxError::Backend("child PID exceeds i32".into()))?;
    // SAFETY: pidfd_open takes a numeric PID and flags=0 and returns a new owned descriptor.
    let descriptor = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(SandboxError::Backend(format!(
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        )));
    }
    let descriptor = i32::try_from(descriptor)
        .map_err(|_| SandboxError::Backend("pidfd descriptor exceeds i32".into()))?;
    // SAFETY: the successful pidfd_open call returned a new descriptor owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn signal_pidfd(descriptor: &OwnedFd, signal: Signal) -> Result<(), SandboxError> {
    // SAFETY: the descriptor remains owned for the call, siginfo=NULL is supported, and flags=0.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pidfd_send_signal,
            descriptor.as_raw_fd(),
            signal as i32,
            std::ptr::null::<nix::libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(nix::libc::ESRCH) {
            return Err(SandboxError::Backend(format!("pidfd_send_signal: {error}")));
        }
    }
    Ok(())
}

fn pidfd_has_exited(descriptor: &OwnedFd) -> Result<bool, SandboxError> {
    let mut descriptor = nix::libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: nix::libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one valid pollfd for a nonblocking readiness query.
    let result = unsafe { nix::libc::poll(&raw mut descriptor, 1, 0) };
    if result < 0 {
        return Err(SandboxError::Backend(format!(
            "pidfd poll: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(result == 1
        && descriptor.revents & (nix::libc::POLLIN | nix::libc::POLLHUP | nix::libc::POLLERR) != 0)
}

async fn wait_for_pidfd_exit(descriptor: &OwnedFd, description: &str) -> Result<(), SandboxError> {
    tokio::time::timeout(PREPARED_CHILD_EXIT_TIMEOUT, async {
        while !pidfd_has_exited(descriptor)? {
            tokio::time::sleep(PREPARED_CHILD_EXIT_POLL).await;
        }
        Ok::<(), SandboxError>(())
    })
    .await
    .map_err(|_| SandboxError::Backend(format!("{description} exit timed out")))??;
    Ok(())
}

fn reap_pidfd(descriptor: &OwnedFd, description: &str) -> Result<(), SandboxError> {
    match waitid(
        Id::PIDFd(descriptor.as_fd()),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG,
    ) {
        Ok(WaitStatus::StillAlive) => Err(SandboxError::Backend(format!(
            "{description} was not reapable after its exact pidfd reported exit"
        ))),
        Ok(_) | Err(nix::errno::Errno::ECHILD) => Ok(()),
        Err(error) => Err(SandboxError::Backend(format!(
            "{description} pidfd reap: {error}"
        ))),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSignal {
    Terminate,
    Kill,
}

/// Parent-side capabilities for Chromium's fixed remote-debugging pipes.
#[derive(Debug)]
pub struct ChromiumCdpPipes {
    command_writer: OwnedFd,
    event_reader: OwnedFd,
}

impl ChromiumCdpPipes {
    /// Reconstructs a received capability pair after validating descriptor type, direction,
    /// close-on-exec state, and that the two ends belong to distinct anonymous pipes.
    pub fn from_owned_fds(
        command_writer: OwnedFd,
        event_reader: OwnedFd,
    ) -> Result<Self, SandboxError> {
        let mut command_pipe_identity = None;
        for (descriptor, required_access, description) in [
            (&command_writer, nix::libc::O_WRONLY, "CDP command writer"),
            (&event_reader, nix::libc::O_RDONLY, "CDP event reader"),
        ] {
            let metadata = fstat(descriptor).map_err(|error| {
                SandboxError::Backend(format!("{description} metadata: {error}"))
            })?;
            if metadata.st_mode & nix::libc::S_IFMT != nix::libc::S_IFIFO {
                return Err(SandboxError::Backend(format!(
                    "{description} is not a pipe"
                )));
            }
            let status = fcntl(descriptor, FcntlArg::F_GETFL).map_err(|error| {
                SandboxError::Backend(format!("{description} status flags: {error}"))
            })?;
            if status & nix::libc::O_PATH != 0 {
                return Err(SandboxError::Backend(format!("{description} is path-only")));
            }
            if status & nix::libc::O_ACCMODE != required_access {
                return Err(SandboxError::Backend(format!(
                    "{description} has the wrong access direction"
                )));
            }
            let filesystem = fstatfs(descriptor).map_err(|error| {
                SandboxError::Backend(format!("{description} filesystem type: {error}"))
            })?;
            if filesystem.filesystem_type().0 as u64 != PIPEFS_MAGIC {
                return Err(SandboxError::Backend(format!(
                    "{description} is not an anonymous pipe"
                )));
            }
            let descriptor_flags = fcntl(descriptor, FcntlArg::F_GETFD).map_err(|error| {
                SandboxError::Backend(format!("{description} descriptor flags: {error}"))
            })?;
            if !FdFlag::from_bits_truncate(descriptor_flags).contains(FdFlag::FD_CLOEXEC) {
                return Err(SandboxError::Backend(format!(
                    "{description} is not close-on-exec"
                )));
            }
            let identity = (metadata.st_dev, metadata.st_ino);
            if command_pipe_identity == Some(identity) {
                return Err(SandboxError::Backend(
                    "CDP command and event capabilities alias one pipe".into(),
                ));
            }
            command_pipe_identity = Some(identity);
        }
        Ok(Self {
            command_writer,
            event_reader,
        })
    }

    #[must_use]
    pub fn command_writer(&self) -> BorrowedFd<'_> {
        self.command_writer.as_fd()
    }

    #[must_use]
    pub fn event_reader(&self) -> BorrowedFd<'_> {
        self.event_reader.as_fd()
    }

    #[must_use]
    pub fn into_owned_fds(self) -> (OwnedFd, OwnedFd) {
        (self.command_writer, self.event_reader)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpawnRequest {
    program: PathBuf,
    arguments: Vec<OsString>,
    inherited_fds: Vec<i32>,
    cgroup_procs_path: PathBuf,
}

impl SpawnRequest {
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    #[must_use]
    pub fn inherited_fds(&self) -> &[i32] {
        // The process backend creates and maps per-launch CDP pipe ends to child FDs 3/4.
        // Only caller-supplied descriptors, such as the seccomp program, are listed here.
        &self.inherited_fds
    }

    #[must_use]
    pub fn cgroup_procs_path(&self) -> &Path {
        &self.cgroup_procs_path
    }
}

#[async_trait]
pub trait LinuxProcessBackend: Send + Sync + 'static {
    /// Prepares the child behind an execution gate and captures its stable PID/start-time identity
    /// together with a pinned, distinct network-namespace capability.
    /// The requested browser runtime must remain unable to execute until `release_prepared`
    /// succeeds for that exact identity. Before returning `Err`, implementations must either prove
    /// that every child they started exited or retain the gate so execution remains impossible.
    ///
    /// `StdLinuxProcessBackend` retains that tombstone for cancellation and ordinary error recovery.
    /// Its control pipe terminates at the fail-closed launch helper, which rejects supervisor EOF;
    /// bubblewrap itself must never interpret the pipe as an execution gate.
    /// Implementations must also place the bootstrap process in `request.cgroup_procs_path()`
    /// before exec so every descendant inherits containment; callers must never attach a returned
    /// numeric PID after userspace identity checks.
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<PreparedLinuxChild, SandboxError>;
    /// Claims the parent command-write and event-read capabilities exactly once for the owned
    /// child identified by `backend_token` and `identity`. The capabilities remain registry-owned
    /// before the claim, including after a successful gate release.
    async fn claim_cdp_pipes(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        Err(SandboxError::Backend(
            "CDP pipe claim is unsupported by this process backend".into(),
        ))
    }
    /// Revalidates that the exact gated child still occupies the pinned network namespace.
    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError>;
    /// Releases the execution gate for exactly this prepared PID/start-time identity.
    /// The caller must durably record its fenced release intent before entering this one-shot
    /// boundary. `StdLinuxProcessBackend` writes the complete approval frame and closes its writer
    /// without suspension. Returning `Err` must leave Chromium unable to execute so
    /// `abort_spawned` can fail closed.
    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError>;
    /// Terminates a child still owned by this backend. `None` means identity capture was interrupted;
    /// the stable backend token must still resolve the retained reader, gate, and bootstrap handle.
    /// Implementations must make successful cleanup idempotent for cancellation retries.
    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError>;
    /// Releases the retained process handle after cgroup emptiness has proven process exit.
    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError>;
    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError>;
    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError>;
    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError>;
    async fn wait(&self, duration: Duration);
}

#[derive(Debug)]
struct OwnedLinuxChild {
    _monitor: std::process::Child,
    bootstrap_pid: Option<u32>,
    bootstrap_pidfd: Option<OwnedFd>,
    cgroup_events: fs::File,
    cgroup_kill: fs::File,
    cgroup_kill_requested: bool,
    cgroup_empty: bool,
    unclaimed_cdp_pipes: Option<ChromiumCdpPipes>,
    cdp_pipes_claimed: bool,
    identity: Option<ChildIdentity>,
    sandbox_pidfd: Option<OwnedFd>,
    execution_gate: Option<OwnedFd>,
    info_reader: Option<tokio::fs::File>,
    info_bytes: Vec<u8>,
    info_eof: bool,
    bootstrap_process_signalled: bool,
    bootstrap_monitor_reaped: bool,
}

static EMERGENCY_GATE_QUARANTINE: OnceLock<StdMutex<HashMap<String, Vec<OwnedLinuxChild>>>> =
    OnceLock::new();

type OwnedLinuxChildSlot = Arc<StdMutex<Option<OwnedLinuxChild>>>;

struct CheckedOutLinuxChild {
    backend_token: String,
    slot: OwnedLinuxChildSlot,
    child: Option<OwnedLinuxChild>,
}

impl CheckedOutLinuxChild {
    fn new(backend_token: &str, slot: OwnedLinuxChildSlot) -> Result<Self, SandboxError> {
        let mut state = slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))?;
        let child = state
            .take()
            .ok_or_else(|| SandboxError::Backend("child operation already in progress".into()))?;
        drop(state);
        Ok(Self {
            backend_token: backend_token.to_owned(),
            slot,
            child: Some(child),
        })
    }

    fn child_mut(&mut self) -> Result<&mut OwnedLinuxChild, SandboxError> {
        self.child
            .as_mut()
            .ok_or_else(|| SandboxError::Backend("checked-out child ownership missing".into()))
    }

    fn finish(mut self) {
        self.child.take();
    }
}

impl Drop for CheckedOutLinuxChild {
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        let mut state = match self.slot.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.is_none() {
            *state = Some(child);
            return;
        }
        drop(state);
        let quarantine = EMERGENCY_GATE_QUARANTINE.get_or_init(|| StdMutex::new(HashMap::new()));
        let mut quarantine = match quarantine.lock() {
            Ok(quarantine) => quarantine,
            Err(poisoned) => poisoned.into_inner(),
        };
        quarantine
            .entry(self.backend_token.clone())
            .or_default()
            .push(child);
    }
}

#[derive(Debug, Default)]
struct StdLinuxProcessRegistry {
    children: StdMutex<HashMap<String, OwnedLinuxChildSlot>>,
}

// Process-global ownership is intentional: dropping a backend value or cancelling a future must
// not close a quarantined writer during ordinary in-process recovery. Any fresh backend handle can
// retry cleanup by the stable launch token. If the supervisor process dies, writer EOF reaches the
// fail-closed launch helper and can never release Chromium.
static STD_LINUX_PROCESS_REGISTRY: OnceLock<StdLinuxProcessRegistry> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub struct StdLinuxProcessBackend {
    registry: &'static StdLinuxProcessRegistry,
}

impl Default for StdLinuxProcessBackend {
    fn default() -> Self {
        Self {
            registry: STD_LINUX_PROCESS_REGISTRY.get_or_init(StdLinuxProcessRegistry::default),
        }
    }
}

fn read_proc_identity(pid: u32) -> Result<Option<(u32, u64)>, SandboxError> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(SandboxError::Backend(error.to_string())),
    };
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| SandboxError::Backend("invalid child proc stat".into()))?;
    let mut fields = fields.split_whitespace();
    let parent_pid = fields
        .nth(1)
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|parent_pid| *parent_pid != 0)
        .ok_or_else(|| SandboxError::Backend("invalid child parent PID".into()))?;
    let start_time_ticks = fields
        .nth(17)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|start_time_ticks| *start_time_ticks != 0)
        .ok_or_else(|| SandboxError::Backend("invalid child start time".into()))?;
    Ok(Some((parent_pid, start_time_ticks)))
}

fn pin_sandbox_network_namespace(
    child: &OwnedLinuxChild,
    identity: ChildIdentity,
) -> Result<PinnedNetworkNamespace, SandboxError> {
    if child.identity != Some(identity) {
        return Err(SandboxError::Backend(
            "prepared child PID identity changed before network namespace capture".into(),
        ));
    }
    let pidfd = child
        .sandbox_pidfd
        .as_ref()
        .ok_or_else(|| SandboxError::Backend("sandbox child pidfd missing".into()))?;
    let bootstrap_pid = child
        .bootstrap_pid
        .ok_or_else(|| SandboxError::Backend("bootstrap process PID missing".into()))?;
    let bootstrap_pidfd = child
        .bootstrap_pidfd
        .as_ref()
        .ok_or_else(|| SandboxError::Backend("bootstrap process pidfd missing".into()))?;
    let before = read_proc_identity(identity.pid())?.ok_or_else(|| {
        SandboxError::Backend("sandbox child exited before network namespace capture".into())
    })?;
    if before.0 != bootstrap_pid
        || before.1 != identity.start_time_ticks
        || pidfd_has_exited(pidfd)?
        || pidfd_has_exited(bootstrap_pidfd)?
    {
        return Err(SandboxError::Backend(
            "sandbox child identity changed before network namespace capture".into(),
        ));
    }
    let descriptor = open(
        format!("/proc/{}/ns/net", identity.pid()).as_str(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| SandboxError::Backend(format!("sandbox network namespace: {error}")))?;
    let namespace = PinnedNetworkNamespace::from_owned_fd(descriptor)?;
    let host_descriptor = open(
        "/proc/self/ns/net",
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| SandboxError::Backend(format!("host network namespace: {error}")))?;
    let host_namespace = PinnedNetworkNamespace::from_owned_fd(host_descriptor)?;
    if namespace.identity() == host_namespace.identity() {
        return Err(SandboxError::Backend(
            "sandbox did not create a distinct network namespace".into(),
        ));
    }
    let after = read_proc_identity(identity.pid())?.ok_or_else(|| {
        SandboxError::Backend("sandbox child exited during network namespace capture".into())
    })?;
    if after != before
        || after.0 != bootstrap_pid
        || after.1 != identity.start_time_ticks
        || pidfd_has_exited(pidfd)?
        || pidfd_has_exited(bootstrap_pidfd)?
    {
        return Err(SandboxError::Backend(
            "sandbox child identity changed around network namespace capture".into(),
        ));
    }
    Ok(namespace)
}

async fn capture_sandbox_identity(
    child: &mut OwnedLinuxChild,
) -> Result<ChildIdentity, SandboxError> {
    if let Some(identity) = child.identity {
        return Ok(identity);
    }
    if child.info_bytes.len() > 16_384 {
        return Err(SandboxError::Backend(
            "sandbox PID response exceeded its bound".into(),
        ));
    }
    if !child.info_eof {
        let deadline = tokio::time::Instant::now() + BWRAP_INFO_TIMEOUT;
        tokio::time::timeout_at(deadline, async {
            let mut chunk = [0_u8; 1024];
            loop {
                let reader = child
                    .info_reader
                    .as_mut()
                    .ok_or_else(|| SandboxError::Backend("sandbox PID reader missing".into()))?;
                let read = reader.read(&mut chunk).await.map_err(|error| {
                    SandboxError::Backend(format!("failed to read sandbox PID: {error}"))
                })?;
                if read == 0 {
                    child.info_eof = true;
                    break;
                }
                child.info_bytes.extend_from_slice(&chunk[..read]);
                if child.info_bytes.len() > 16_384 {
                    return Err(SandboxError::Backend(
                        "sandbox PID response exceeded its bound".into(),
                    ));
                }
            }
            Ok::<(), SandboxError>(())
        })
        .await
        .map_err(|_| SandboxError::Backend("sandbox PID response timed out".into()))??;
    }
    let info: serde_json::Value = serde_json::from_slice(&child.info_bytes)
        .map_err(|error| SandboxError::Backend(format!("invalid sandbox PID response: {error}")))?;
    let pid = info
        .get("child-pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(|| SandboxError::Backend("invalid sandbox child PID".into()))?;
    let bootstrap_pid = child
        .bootstrap_pid
        .ok_or_else(|| SandboxError::Backend("bootstrap process PID missing".into()))?;
    let bootstrap_pidfd = child
        .bootstrap_pidfd
        .as_ref()
        .ok_or_else(|| SandboxError::Backend("bootstrap process pidfd missing".into()))?;
    if pidfd_has_exited(bootstrap_pidfd)? {
        return Err(SandboxError::Backend(
            "sandbox bootstrap exited before identity capture".into(),
        ));
    }
    let identity_before_pidfd = read_proc_identity(pid)?.ok_or_else(|| {
        SandboxError::Backend("sandbox child exited before identity capture".into())
    })?;
    if identity_before_pidfd.0 != bootstrap_pid {
        return Err(SandboxError::Backend(
            "sandbox child does not have the exact bootstrap parent".into(),
        ));
    }
    let pidfd = open_pidfd(pid)?;
    let identity_after_pidfd = read_proc_identity(pid)?.ok_or_else(|| {
        SandboxError::Backend("sandbox child exited during identity capture".into())
    })?;
    if identity_after_pidfd != identity_before_pidfd {
        return Err(SandboxError::Backend(
            "sandbox child identity changed around pidfd capture".into(),
        ));
    }
    if identity_after_pidfd.0 != bootstrap_pid
        || pidfd_has_exited(&pidfd)?
        || pidfd_has_exited(bootstrap_pidfd)?
    {
        return Err(SandboxError::Backend(
            "sandbox child exited during identity capture".into(),
        ));
    }
    let identity = ChildIdentity::new(pid, identity_after_pidfd.1);
    child.identity = Some(identity);
    child.sandbox_pidfd = Some(pidfd);
    Ok(identity)
}

#[async_trait]
impl LinuxProcessBackend for StdLinuxProcessBackend {
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<PreparedLinuxChild, SandboxError> {
        for descriptor in request.inherited_fds() {
            // SAFETY: this only borrows the caller-owned descriptor for the duration of fcntl.
            let descriptor = unsafe { BorrowedFd::borrow_raw(*descriptor) };
            let flags = fcntl(descriptor, FcntlArg::F_GETFD).map_err(|error| {
                SandboxError::Backend(format!(
                    "required inherited descriptor is not open: {error}"
                ))
            })?;
            if FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC) {
                return Err(SandboxError::Backend(
                    "required inherited descriptor is not inheritable across exec".into(),
                ));
            }
        }
        let (cdp_command_reader, cdp_command_writer) = pipe2(OFlag::O_CLOEXEC)
            .map_err(|error| SandboxError::Backend(format!("CDP command pipe: {error}")))?;
        let (cdp_event_reader, cdp_event_writer) = pipe2(OFlag::O_CLOEXEC)
            .map_err(|error| SandboxError::Backend(format!("CDP event pipe: {error}")))?;
        let relocate_child_end = |descriptor: OwnedFd,
                                  description: &str|
         -> Result<OwnedFd, SandboxError> {
            if ![CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD].contains(&descriptor.as_raw_fd()) {
                return Ok(descriptor);
            }
            let duplicated = fcntl(&descriptor, FcntlArg::F_DUPFD_CLOEXEC(5)).map_err(|error| {
                SandboxError::Backend(format!("{description} relocation: {error}"))
            })?;
            // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor on success.
            Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
        };
        let cdp_command_reader =
            relocate_child_end(cdp_command_reader, "CDP child command descriptor")?;
        let cdp_event_writer = relocate_child_end(cdp_event_writer, "CDP child event descriptor")?;
        let cgroup_path = request
            .cgroup_procs_path()
            .parent()
            .ok_or_else(|| SandboxError::Backend("sandbox cgroup path has no parent".into()))?;
        let cgroup_directory = open(
            cgroup_path,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| SandboxError::Backend(format!("sandbox cgroup directory: {error}")))?;
        let cgroup_procs = fs::File::from(
            openat(
                &cgroup_directory,
                "cgroup.procs",
                OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| {
                SandboxError::Backend(format!("sandbox cgroup attachment: {error}"))
            })?,
        );
        let cgroup_kill = fs::File::from(
            openat(
                &cgroup_directory,
                "cgroup.kill",
                OFlag::O_WRONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| SandboxError::Backend(format!("sandbox cgroup kill: {error}")))?,
        );
        let cgroup_events = fs::File::from(
            openat(
                &cgroup_directory,
                "cgroup.events",
                OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| SandboxError::Backend(format!("sandbox cgroup events: {error}")))?,
        );
        let (gate_read, gate_write) = pipe2(OFlag::O_CLOEXEC)
            .map_err(|error| SandboxError::Backend(format!("execution gate: {error}")))?;
        let (info_read, info_write) = pipe2(OFlag::O_CLOEXEC)
            .map_err(|error| SandboxError::Backend(format!("sandbox PID pipe: {error}")))?;
        fcntl(&info_write, FcntlArg::F_SETFD(FdFlag::empty())).map_err(|error| {
            SandboxError::Backend(format!("sandbox bootstrap descriptor: {error}"))
        })?;
        let mut command = Command::new(request.program());
        let cgroup_procs_fd = cgroup_procs.as_raw_fd();
        let cdp_command_reader_fd = cdp_command_reader.as_raw_fd();
        let cdp_event_writer_fd = cdp_event_writer.as_raw_fd();
        // SAFETY: this callback runs after fork and before exec. It performs only one libc write
        // through a descriptor opened by the parent, followed by async-signal-safe dup2 calls.
        // Writing 0 attaches the calling bootstrap itself, so the supervisor never resolves a
        // reusable numeric PID. The CDP sources were relocated away from targets 3/4 in the parent,
        // preventing either dup2 from clobbering the other source.
        unsafe {
            command.pre_exec(move || {
                let membership = b"0\n";
                let written = nix::libc::write(
                    cgroup_procs_fd,
                    membership.as_ptr().cast(),
                    membership.len(),
                );
                if written < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if written != membership.len() as isize {
                    return Err(std::io::Error::other(
                        "sandbox cgroup attachment was incomplete",
                    ));
                }
                if nix::libc::dup2(cdp_command_reader_fd, CHROMIUM_CDP_READ_FD)
                    != CHROMIUM_CDP_READ_FD
                {
                    return Err(std::io::Error::last_os_error());
                }
                if nix::libc::dup2(cdp_event_writer_fd, CHROMIUM_CDP_WRITE_FD)
                    != CHROMIUM_CDP_WRITE_FD
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
            .arg("--info-fd")
            .arg(info_write.as_raw_fd().to_string())
            .args(request.arguments())
            .env_clear()
            .stdin(Stdio::from(fs::File::from(gate_read)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let slot = Arc::new(StdMutex::new(None));
        {
            let mut children = self
                .registry
                .children
                .lock()
                .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?;
            if children.contains_key(backend_token) {
                return Err(SandboxError::Backend(
                    "prepared child token is already owned".into(),
                ));
            }
            children.insert(backend_token.to_owned(), slot.clone());
        }
        let monitor = command
            .into_std()
            .spawn()
            .map_err(|error| SandboxError::Backend(error.to_string()));
        drop(cdp_command_reader);
        drop(cdp_event_writer);
        let monitor = match monitor {
            Ok(monitor) => monitor,
            Err(error) => {
                self.registry
                    .children
                    .lock()
                    .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
                    .remove(backend_token);
                return Err(error);
            }
        };
        let bootstrap_pid = monitor.id();
        let (bootstrap_pidfd, bootstrap_pidfd_error) = match open_pidfd(bootstrap_pid) {
            Ok(pidfd) => (Some(pidfd), None),
            Err(error) => (None, Some(error)),
        };
        drop(info_write);
        let owned = OwnedLinuxChild {
            _monitor: monitor,
            bootstrap_pid: Some(bootstrap_pid),
            bootstrap_pidfd,
            cgroup_events,
            cgroup_kill,
            cgroup_kill_requested: false,
            cgroup_empty: false,
            unclaimed_cdp_pipes: Some(ChromiumCdpPipes {
                command_writer: cdp_command_writer,
                event_reader: cdp_event_reader,
            }),
            cdp_pipes_claimed: false,
            identity: None,
            sandbox_pidfd: None,
            execution_gate: Some(gate_write),
            info_reader: Some(tokio::fs::File::from_std(fs::File::from(info_read))),
            info_bytes: Vec::new(),
            info_eof: false,
            bootstrap_process_signalled: false,
            bootstrap_monitor_reaped: false,
        };
        *slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))? = Some(owned);
        if let Some(error) = bootstrap_pidfd_error {
            return Err(SandboxError::Backend(format!(
                "bootstrap process pidfd unavailable; child quarantined: {error}"
            )));
        }
        let mut checked_out = CheckedOutLinuxChild::new(backend_token, slot)?;
        let identity = capture_sandbox_identity(checked_out.child_mut()?).await?;
        let network_namespace = pin_sandbox_network_namespace(checked_out.child_mut()?, identity)?;
        Ok(PreparedLinuxChild::new(identity, network_namespace))
    }

    async fn claim_cdp_pipes(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned()
            .ok_or_else(|| SandboxError::Backend("prepared child ownership missing".into()))?;
        let mut state = slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))?;
        let child = state
            .as_mut()
            .ok_or_else(|| SandboxError::Backend("child operation already in progress".into()))?;
        if child.identity != Some(identity) {
            return Err(SandboxError::Backend(
                "prepared child PID identity changed".into(),
            ));
        }
        let pidfd = child
            .sandbox_pidfd
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("sandbox child pidfd missing".into()))?;
        if pidfd_has_exited(pidfd)? {
            return Err(SandboxError::Backend(
                "prepared child exited before CDP claim".into(),
            ));
        }
        if child.cdp_pipes_claimed {
            return Err(SandboxError::Backend(
                "prepared child CDP pipes already claimed".into(),
            ));
        }
        let pipes = child
            .unclaimed_cdp_pipes
            .take()
            .ok_or_else(|| SandboxError::Backend("prepared child CDP pipes missing".into()))?;
        child.cdp_pipes_claimed = true;
        Ok(pipes)
    }

    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned()
            .ok_or_else(|| SandboxError::Backend("prepared child ownership missing".into()))?;
        let state = slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))?;
        let child = state
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("child operation already in progress".into()))?;
        Ok(pin_sandbox_network_namespace(child, identity)?.identity()
            == network_namespace.identity())
    }

    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned()
            .ok_or_else(|| SandboxError::Backend("prepared child ownership missing".into()))?;
        let mut state = slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))?;
        let child = state
            .as_mut()
            .ok_or_else(|| SandboxError::Backend("child operation already in progress".into()))?;
        if child.identity != Some(identity) {
            return Err(SandboxError::Backend(
                "prepared child PID identity changed".into(),
            ));
        }
        let pidfd = child
            .sandbox_pidfd
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("sandbox child pidfd missing".into()))?;
        if pidfd_has_exited(pidfd)? {
            return Err(SandboxError::Backend(
                "prepared child exited before gate release".into(),
            ));
        }
        let Some(gate) = child.execution_gate.as_ref() else {
            return Ok(());
        };
        let written = write_fd(gate, APPROVAL_FRAME)
            .map_err(|error| SandboxError::Backend(format!("execution gate release: {error}")))?;
        if written != APPROVAL_FRAME.len() {
            return Err(SandboxError::Backend(
                "execution gate release was incomplete".into(),
            ));
        }
        child.execution_gate = None;
        Ok(())
    }

    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned();
        let Some(slot) = slot else {
            return Ok(());
        };
        let mut checked_out = CheckedOutLinuxChild::new(backend_token, slot.clone())?;
        if let Some(expected) = identity
            && checked_out.child_mut()?.identity != Some(expected)
        {
            return Err(SandboxError::Backend(
                "spawned child PID identity changed".into(),
            ));
        }
        if checked_out.child_mut()?.identity.is_none() && !checked_out.child_mut()?.info_eof {
            let _ = capture_sandbox_identity(checked_out.child_mut()?).await;
        }

        let mut cleanup_errors = Vec::new();
        let sandbox_dead = if let Some(pidfd) = checked_out.child_mut()?.sandbox_pidfd.as_ref() {
            if !pidfd_has_exited(pidfd)?
                && let Err(error) = signal_pidfd(pidfd, Signal::SIGKILL)
            {
                cleanup_errors.push(format!("sandbox signal: {error}"));
            }
            match wait_for_pidfd_exit(pidfd, "sandbox child").await {
                Ok(()) => true,
                Err(error) => {
                    cleanup_errors.push(error.to_string());
                    false
                }
            }
        } else {
            let cgroup_cleanup = async {
                if !checked_out.child_mut()?.cgroup_kill_requested {
                    checked_out
                        .child_mut()?
                        .cgroup_kill
                        .write_all(b"1")
                        .map_err(|error| {
                            SandboxError::Backend(format!("exact cgroup kill: {error}"))
                        })?;
                    checked_out.child_mut()?.cgroup_kill_requested = true;
                }
                if checked_out.child_mut()?.cgroup_empty {
                    return Ok(());
                }
                tokio::time::timeout(PREPARED_CHILD_EXIT_TIMEOUT, async {
                    loop {
                        let empty = {
                            let child = checked_out.child_mut()?;
                            child
                                .cgroup_events
                                .seek(SeekFrom::Start(0))
                                .map_err(|error| {
                                    SandboxError::Backend(format!(
                                        "exact cgroup events seek: {error}"
                                    ))
                                })?;
                            let mut events = String::new();
                            child
                                .cgroup_events
                                .read_to_string(&mut events)
                                .map_err(|error| {
                                    SandboxError::Backend(format!(
                                        "exact cgroup events read: {error}"
                                    ))
                                })?;
                            events.lines().any(|line| line.trim() == "populated 0")
                        };
                        if empty {
                            checked_out.child_mut()?.cgroup_empty = true;
                            return Ok::<(), SandboxError>(());
                        }
                        tokio::time::sleep(PREPARED_CHILD_EXIT_POLL).await;
                    }
                })
                .await
                .map_err(|_| {
                    SandboxError::Backend(
                        "exact cgroup remained populated after cgroup.kill".into(),
                    )
                })??;
                Ok::<(), SandboxError>(())
            }
            .await;
            match cgroup_cleanup {
                Ok(()) => true,
                Err(error) => {
                    cleanup_errors.push(error.to_string());
                    false
                }
            }
        };

        if !checked_out.child_mut()?.bootstrap_monitor_reaped
            && !checked_out.child_mut()?.bootstrap_process_signalled
        {
            let bootstrap_signal =
                if let Some(pidfd) = checked_out.child_mut()?.bootstrap_pidfd.as_ref() {
                    signal_pidfd(pidfd, Signal::SIGKILL)
                } else {
                    Err(SandboxError::Backend(
                        "bootstrap process pidfd unavailable".into(),
                    ))
                };
            match bootstrap_signal {
                Ok(()) => checked_out.child_mut()?.bootstrap_process_signalled = true,
                Err(error) => cleanup_errors.push(format!("bootstrap signal: {error}")),
            }
        }
        if !checked_out.child_mut()?.bootstrap_monitor_reaped {
            let pidfd_ready = if let Some(pidfd) = checked_out.child_mut()?.bootstrap_pidfd.as_ref()
            {
                match wait_for_pidfd_exit(pidfd, "bootstrap process").await {
                    Ok(()) => true,
                    Err(error) => {
                        cleanup_errors.push(error.to_string());
                        false
                    }
                }
            } else {
                cleanup_errors.push("bootstrap process pidfd unavailable".into());
                false
            };
            if pidfd_ready {
                let reap = checked_out
                    .child_mut()?
                    .bootstrap_pidfd
                    .as_ref()
                    .ok_or_else(|| {
                        SandboxError::Backend("bootstrap process pidfd unavailable".into())
                    })
                    .and_then(|pidfd| reap_pidfd(pidfd, "bootstrap process"));
                match reap {
                    Ok(()) => checked_out.child_mut()?.bootstrap_monitor_reaped = true,
                    Err(error) => cleanup_errors.push(error.to_string()),
                }
            }
        }

        if !sandbox_dead || !checked_out.child_mut()?.bootstrap_monitor_reaped {
            return Err(SandboxError::Backend(format!(
                "prepared child cleanup incomplete; execution gate quarantined: {}",
                cleanup_errors.join("; ")
            )));
        }
        checked_out.child_mut()?.execution_gate.take();
        let mut children = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?;
        if !children
            .get(backend_token)
            .is_some_and(|current| Arc::ptr_eq(current, &slot))
        {
            return Err(SandboxError::Backend(
                "spawned child ownership changed during abort".into(),
            ));
        }
        children.remove(backend_token);
        drop(children);
        checked_out.finish();
        Ok(())
    }

    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned();
        let Some(slot) = slot else {
            return Err(SandboxError::Backend(
                "spawned child ownership missing".into(),
            ));
        };
        let mut checked_out = CheckedOutLinuxChild::new(backend_token, slot.clone())?;
        if checked_out.child_mut()?.identity != Some(identity) {
            return Err(SandboxError::Backend(
                "spawned child PID identity changed".into(),
            ));
        }
        let pidfd = checked_out
            .child_mut()?
            .sandbox_pidfd
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("sandbox child pidfd missing".into()))?;
        if !pidfd_has_exited(pidfd)? {
            return Err(SandboxError::Backend(
                "cannot release a live spawned child".into(),
            ));
        }
        if checked_out.child_mut()?.execution_gate.is_some() {
            return Err(SandboxError::Backend(
                "cannot release a still-gated spawned child".into(),
            ));
        }
        let bootstrap_pidfd = checked_out
            .child_mut()?
            .bootstrap_pidfd
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("bootstrap process pidfd missing".into()))?;
        if !pidfd_has_exited(bootstrap_pidfd)? {
            return Err(SandboxError::Backend(
                "cannot release a live spawned child".into(),
            ));
        }
        reap_pidfd(bootstrap_pidfd, "bootstrap process")?;
        checked_out.child_mut()?.bootstrap_monitor_reaped = true;
        let mut children = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?;
        if !children
            .get(backend_token)
            .is_some_and(|current| Arc::ptr_eq(current, &slot))
        {
            return Err(SandboxError::Backend(
                "spawned child ownership changed during release".into(),
            ));
        }
        children.remove(backend_token);
        drop(children);
        checked_out.finish();
        Ok(())
    }

    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned();
        let Some(slot) = slot else {
            return Ok(false);
        };
        let state = slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))?;
        let Some(child) = state.as_ref() else {
            return Err(SandboxError::Backend(
                "child operation already in progress".into(),
            ));
        };
        if child.identity != Some(identity) {
            return Ok(false);
        }
        let pidfd = child
            .sandbox_pidfd
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("sandbox child pidfd missing".into()))?;
        Ok(!pidfd_has_exited(pidfd)?)
    }

    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        let slot = self
            .registry
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .get(backend_token)
            .cloned()
            .ok_or_else(|| SandboxError::Backend("spawned child ownership missing".into()))?;
        let state = slot
            .lock()
            .map_err(|_| SandboxError::Backend("child state lock poisoned".into()))?;
        let child = state
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("child operation already in progress".into()))?;
        if child.identity != Some(identity) {
            return Err(SandboxError::Backend("child PID identity changed".into()));
        }
        let pidfd = child
            .sandbox_pidfd
            .as_ref()
            .ok_or_else(|| SandboxError::Backend("sandbox child pidfd missing".into()))?;
        signal_pidfd(
            pidfd,
            match signal {
                ProcessSignal::Terminate => Signal::SIGTERM,
                ProcessSignal::Kill => Signal::SIGKILL,
            },
        )
    }

    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.identity_matches(backend_token, identity).await
    }

    async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[async_trait]
pub trait EgressRouteBackend: Send + Sync + 'static {
    /// Reserves one exact generation. `cancel_reservation` is a permanent tombstone: it must win
    /// over every concurrent or late `prepare` and `attach` completion for that generation.
    async fn prepare(&self, reservation: &ShardEgressReservation) -> Result<(), SandboxError>;
    /// Attaches ingress to the borrowed exact namespace. A concurrent or later
    /// `cancel_reservation` for the same generation must win permanently.
    async fn attach(
        &self,
        reservation: &ShardEgressReservation,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<ShardIngressReceipt, SandboxError>;
    /// Permanently cancels this exact generation. Once committed, every retry with the same
    /// reservation must return success even when the earlier caller was cancelled before it
    /// observed the result.
    async fn cancel_reservation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError>;
    /// Releases a cancelled reservation. The exact operation must be idempotent across an
    /// uncertain completion, while an active or differently generated reservation fails closed.
    async fn release_reservation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError>;
    /// Revokes this exact reservation, namespace, and attachment receipt. Once committed, retries
    /// with the same lease must succeed, including after its exact release; any different receipt
    /// or namespace must fail closed.
    async fn revoke(&self, lease: &ShardIngressLease) -> Result<(), SandboxError>;
    /// Releases this exact revoked lease. Once committed, retries with the same lease must return
    /// success so cancellation between the backend commit and local acknowledgement is recoverable.
    async fn release(&self, lease: &ShardIngressLease) -> Result<(), SandboxError>;
    async fn is_active(&self, lease: &ShardIngressLease) -> Result<bool, SandboxError>;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ShardEgressFence {
    shard_id: ShardId,
    worker_epoch: u64,
}

impl ShardEgressFence {
    #[must_use]
    pub const fn new(shard_id: ShardId, worker_epoch: u64) -> Self {
        Self {
            shard_id,
            worker_epoch,
        }
    }

    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardEgressReservation {
    fence: ShardEgressFence,
    generation: LeaseId,
    tenant_id: Option<TenantId>,
    dedicated_egress: Option<DedicatedEgressSpec>,
}

impl ShardEgressReservation {
    #[must_use]
    pub fn new(fence: ShardEgressFence) -> Self {
        Self {
            fence,
            generation: LeaseId::new(),
            tenant_id: None,
            dedicated_egress: None,
        }
    }

    #[must_use]
    pub fn from_launch_spec(spec: &LaunchSpec) -> Self {
        Self {
            fence: ShardEgressFence::new(spec.shard_id().clone(), spec.worker_epoch()),
            generation: LeaseId::new(),
            tenant_id: Some(spec.tenant_id().clone()),
            dedicated_egress: Some(spec.dedicated_egress().clone()),
        }
    }

    #[must_use]
    pub const fn fence(&self) -> &ShardEgressFence {
        &self.fence
    }

    #[must_use]
    pub const fn generation(&self) -> &LeaseId {
        &self.generation
    }

    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }

    #[must_use]
    pub const fn dedicated_egress(&self) -> Option<&DedicatedEgressSpec> {
        self.dedicated_egress.as_ref()
    }

    #[must_use]
    pub fn egress_fence(&self) -> Option<&EgressFence> {
        self.dedicated_egress
            .as_ref()
            .map(DedicatedEgressSpec::egress_fence)
    }
}

impl std::hash::Hash for ShardEgressReservation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.fence.hash(state);
        self.generation.hash(state);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardIngressReceipt {
    attachment_generation: LeaseId,
}

impl ShardIngressReceipt {
    #[must_use]
    pub fn new() -> Self {
        Self {
            attachment_generation: LeaseId::new(),
        }
    }

    #[must_use]
    pub const fn attachment_generation(&self) -> &LeaseId {
        &self.attachment_generation
    }
}

impl Default for ShardIngressReceipt {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardIngressLease {
    reservation: ShardEgressReservation,
    network_namespace: NetworkNamespaceIdentity,
    receipt: ShardIngressReceipt,
}

impl ShardIngressLease {
    const fn new(
        reservation: ShardEgressReservation,
        network_namespace: NetworkNamespaceIdentity,
        receipt: ShardIngressReceipt,
    ) -> Self {
        Self {
            reservation,
            network_namespace,
            receipt,
        }
    }

    #[must_use]
    pub const fn from_attachment(
        reservation: ShardEgressReservation,
        network_namespace: NetworkNamespaceIdentity,
        receipt: ShardIngressReceipt,
    ) -> Self {
        Self::new(reservation, network_namespace, receipt)
    }

    #[must_use]
    pub const fn reservation(&self) -> &ShardEgressReservation {
        &self.reservation
    }

    #[must_use]
    pub const fn namespace_identity(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn receipt(&self) -> &ShardIngressReceipt {
        &self.receipt
    }
}

struct LinuxRuntime {
    identity: ChildIdentity,
    backend_token: String,
    cgroup_path: PathBuf,
    runtime_path: PathBuf,
    _network_namespace: Option<PinnedNetworkNamespace>,
    ingress_lease: ShardIngressLease,
    gate_released: bool,
    egress_revoked: bool,
    egress_released: bool,
    process_released: bool,
    runtime_removed: bool,
    cgroup_removed: bool,
    namespaces_cleaned: bool,
    cleanup_operation: Arc<AsyncMutex<()>>,
    process_operation: Arc<AsyncMutex<()>>,
}

struct PreparedCleanupAttempt {
    journal: Option<Arc<FilePreparedShardJournal>>,
    permit: Option<PreparedShardCleanupPermit>,
}

impl PreparedCleanupAttempt {
    const fn unjournaled() -> Self {
        Self {
            journal: None,
            permit: None,
        }
    }

    fn journaled(
        journal: Arc<FilePreparedShardJournal>,
        permit: PreparedShardCleanupPermit,
    ) -> Self {
        Self {
            journal: Some(journal),
            permit: Some(permit),
        }
    }

    fn disarm(mut self) -> Option<(Arc<FilePreparedShardJournal>, PreparedShardCleanupPermit)> {
        self.journal.take().zip(self.permit.take())
    }
}

impl Drop for PreparedCleanupAttempt {
    fn drop(&mut self) {
        if let (Some(journal), Some(permit)) = (&self.journal, &self.permit) {
            let _ = journal.abandon_cleanup_stage(permit);
        }
    }
}

impl Clone for LinuxRuntime {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity,
            backend_token: self.backend_token.clone(),
            cgroup_path: self.cgroup_path.clone(),
            runtime_path: self.runtime_path.clone(),
            _network_namespace: self
                ._network_namespace
                .as_ref()
                .map(PinnedNetworkNamespace::clone_for_owner),
            ingress_lease: self.ingress_lease.clone(),
            gate_released: self.gate_released,
            egress_revoked: self.egress_revoked,
            egress_released: self.egress_released,
            process_released: self.process_released,
            runtime_removed: self.runtime_removed,
            cgroup_removed: self.cgroup_removed,
            namespaces_cleaned: self.namespaces_cleaned,
            cleanup_operation: Arc::clone(&self.cleanup_operation),
            process_operation: Arc::clone(&self.process_operation),
        }
    }
}

struct ProvisionCleanup {
    shard_fence: ShardFence,
    backend_token: String,
    cgroup_path: PathBuf,
    runtime_path: PathBuf,
    egress_reservation: ShardEgressReservation,
    _network_namespace: Option<PinnedNetworkNamespace>,
    ingress_lease: Option<ShardIngressLease>,
    owner_active: bool,
    cgroup_created: bool,
    runtime_created: bool,
    route_may_exist: bool,
    child_may_exist: bool,
    identity: Option<ChildIdentity>,
    route_revoked: bool,
    child_aborted: bool,
    runtime_removed: bool,
    cgroup_removed: bool,
    route_released: bool,
}

impl Clone for ProvisionCleanup {
    fn clone(&self) -> Self {
        Self {
            shard_fence: self.shard_fence.clone(),
            backend_token: self.backend_token.clone(),
            cgroup_path: self.cgroup_path.clone(),
            runtime_path: self.runtime_path.clone(),
            egress_reservation: self.egress_reservation.clone(),
            _network_namespace: self
                ._network_namespace
                .as_ref()
                .map(PinnedNetworkNamespace::clone_for_owner),
            ingress_lease: self.ingress_lease.clone(),
            owner_active: self.owner_active,
            cgroup_created: self.cgroup_created,
            runtime_created: self.runtime_created,
            route_may_exist: self.route_may_exist,
            child_may_exist: self.child_may_exist,
            identity: self.identity,
            route_revoked: self.route_revoked,
            child_aborted: self.child_aborted,
            runtime_removed: self.runtime_removed,
            cgroup_removed: self.cgroup_removed,
            route_released: self.route_released,
        }
    }
}

struct ProvisionAttempt<'a> {
    provisions: &'a StdMutex<HashMap<ShardId, ProvisionCleanup>>,
    shard_id: ShardId,
    backend_token: String,
}

impl Drop for ProvisionAttempt<'_> {
    fn drop(&mut self) {
        if let Ok(mut provisions) = self.provisions.lock()
            && let Some(provision) = provisions.get_mut(&self.shard_id)
            && provision.backend_token == self.backend_token
        {
            provision.owner_active = false;
        }
    }
}

fn exact_prepared_record(
    journal: &FilePreparedShardJournal,
    fence: &browserd_core::ShardFence,
) -> Result<PreparedShardJournalRecord, crate::journal::PreparedShardJournalError> {
    journal
        .records()?
        .into_iter()
        .find(|record| record.fence() == fence)
        .ok_or(crate::journal::PreparedShardJournalError::RecordNotFound)
}

pub struct LinuxSandboxBackend<F, P, E> {
    config: LinuxSandboxConfig,
    filesystem: F,
    process: P,
    egress: E,
    prepared_journal: Option<Arc<FilePreparedShardJournal>>,
    egress_daemon_epoch: Option<u64>,
    provisioning: StdMutex<HashMap<ShardId, ProvisionCleanup>>,
    runtimes: StdMutex<HashMap<ShardId, LinuxRuntime>>,
}

impl<F, P, E> LinuxSandboxBackend<F, P, E>
where
    F: SandboxFilesystem,
    P: LinuxProcessBackend,
    E: EgressRouteBackend,
{
    #[must_use]
    pub fn new(config: LinuxSandboxConfig, filesystem: F, process: P, egress: E) -> Self {
        Self {
            config,
            filesystem,
            process,
            egress,
            prepared_journal: None,
            egress_daemon_epoch: None,
            provisioning: StdMutex::new(HashMap::new()),
            runtimes: StdMutex::new(HashMap::new()),
        }
    }

    pub fn with_prepared_journal(
        mut self,
        journal: Arc<FilePreparedShardJournal>,
        egress_daemon_epoch: u64,
    ) -> Result<Self, SandboxError> {
        if egress_daemon_epoch == 0 {
            return Err(SandboxError::Backend(
                "egress daemon epoch must be nonzero".into(),
            ));
        }
        self.prepared_journal = Some(journal);
        self.egress_daemon_epoch = Some(egress_daemon_epoch);
        Ok(self)
    }

    async fn reserve_prepared_record(
        &self,
        spec: &LaunchSpec,
        backend_token: &str,
        cgroup_path: &Path,
        runtime_path: &Path,
    ) -> Result<(), SandboxError> {
        let Some(journal) = self.prepared_journal.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let daemon_epoch = self.egress_daemon_epoch.ok_or_else(|| {
            SandboxError::Backend("prepared journal is missing the egress daemon epoch".into())
        })?;
        let fence = spec.dedicated_egress().egress_fence().shard().clone();
        let egress_fence = spec.dedicated_egress().egress_fence().clone();
        let backend_token = backend_token.to_owned();
        let cgroup_path = cgroup_path.to_path_buf();
        let runtime_path = runtime_path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let locators =
                PreparedShardRecoveryLocators::new(backend_token, cgroup_path, runtime_path)?
                    .with_egress_binding(daemon_epoch, egress_fence)?;
            journal.reserve(fence, locators).map(|_| ())
        })
        .await
        .map_err(|error| SandboxError::Backend(format!("prepared journal task failed: {error}")))?
        .map_err(|error| SandboxError::Backend(format!("prepared journal reserve: {error}")))
    }

    async fn begin_prepared_effect(
        &self,
        fence: &browserd_core::ShardFence,
        effect: PreparedShardEffect,
    ) -> Result<Option<PreparedShardEffectPermit>, SandboxError> {
        let Some(journal) = self.prepared_journal.as_ref().map(Arc::clone) else {
            return Ok(None);
        };
        let fence = fence.clone();
        tokio::task::spawn_blocking(move || {
            let record = exact_prepared_record(&journal, &fence)?;
            journal
                .begin_effect(&fence, record.sequence(), effect)
                .map(Some)
        })
        .await
        .map_err(|error| SandboxError::Backend(format!("prepared journal task failed: {error}")))?
        .map_err(|error| SandboxError::Backend(format!("prepared journal effect intent: {error}")))
    }

    async fn complete_prepared_effect(
        &self,
        permit: Option<PreparedShardEffectPermit>,
    ) -> Result<(), SandboxError> {
        let (Some(journal), Some(permit)) =
            (self.prepared_journal.as_ref().map(Arc::clone), permit)
        else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || journal.complete_effect(&permit).map(|_| ()))
            .await
            .map_err(|error| {
                SandboxError::Backend(format!("prepared journal task failed: {error}"))
            })?
            .map_err(|error| {
                SandboxError::Backend(format!("prepared journal effect completion: {error}"))
            })
    }

    async fn next_release_sequence(
        &self,
        fence: &browserd_core::ShardFence,
    ) -> Result<u64, SandboxError> {
        let Some(journal) = self.prepared_journal.as_ref().map(Arc::clone) else {
            return Ok(1);
        };
        let fence = fence.clone();
        tokio::task::spawn_blocking(move || {
            exact_prepared_record(&journal, &fence)?
                .sequence()
                .get()
                .checked_add(1)
                .ok_or(crate::journal::PreparedShardJournalError::SequenceExhausted)
        })
        .await
        .map_err(|error| SandboxError::Backend(format!("prepared journal task failed: {error}")))?
        .map_err(|error| SandboxError::Backend(format!("prepared release sequence: {error}")))
    }

    async fn complete_prepared_cleanup(
        &self,
        fence: &browserd_core::ShardFence,
        stages: &'static [PreparedShardCleanupStage],
    ) -> Result<(), SandboxError> {
        let Some(journal) = self.prepared_journal.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let fence = fence.clone();
        tokio::task::spawn_blocking(move || {
            for stage in stages {
                let record = exact_prepared_record(&journal, &fence)?;
                if record.recovery_disposition()
                    == PreparedShardRecoveryDisposition::ReleasedTombstone
                    || record.cleanup_progress(*stage)?.status()
                        == PreparedShardCleanupStageStatus::Completed
                {
                    continue;
                }
                let permit = journal.begin_cleanup_stage(&fence, record.sequence(), *stage)?;
                journal.complete_cleanup_stage(&permit)?;
            }
            Ok::<(), crate::journal::PreparedShardJournalError>(())
        })
        .await
        .map_err(|error| SandboxError::Backend(format!("prepared journal task failed: {error}")))?
        .map_err(|error| SandboxError::Backend(format!("prepared cleanup journal: {error}")))
    }

    async fn begin_prepared_cleanup_stage(
        &self,
        fence: &browserd_core::ShardFence,
        stage: PreparedShardCleanupStage,
    ) -> Result<PreparedCleanupAttempt, SandboxError> {
        let Some(journal) = self.prepared_journal.as_ref().map(Arc::clone) else {
            return Ok(PreparedCleanupAttempt::unjournaled());
        };
        let fence = fence.clone();
        tokio::task::spawn_blocking(move || {
            for _ in 0..32 {
                let record = exact_prepared_record(&journal, &fence)?;
                if record.recovery_disposition()
                    == PreparedShardRecoveryDisposition::ReleasedTombstone
                    || record.cleanup_progress(stage)?.status()
                        == PreparedShardCleanupStageStatus::Completed
                {
                    return Ok(PreparedCleanupAttempt::unjournaled());
                }
                match journal.begin_cleanup_stage(&fence, record.sequence(), stage) {
                    Ok(permit) => {
                        return Ok(PreparedCleanupAttempt::journaled(
                            Arc::clone(&journal),
                            permit,
                        ));
                    }
                    Err(crate::journal::PreparedShardJournalError::StaleSequence { .. }) => {}
                    Err(crate::journal::PreparedShardJournalError::CleanupStageOutOfOrder)
                        if stage == PreparedShardCleanupStage::AbortGate
                            && record
                                .cleanup_progress(PreparedShardCleanupStage::RevokeEgress)?
                                .attempts()
                                == 0 =>
                    {
                        // Normal cleanup starts the egress and process branches together. The
                        // abort branch may read the record just before the revoke branch commits
                        // its intent, so retry that exact transient without allowing an abort to
                        // bypass the durable revoke intent.
                        std::thread::yield_now();
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(crate::journal::PreparedShardJournalError::CleanupStageInProgress)
        })
        .await
        .map_err(|error| SandboxError::Backend(format!("prepared journal task failed: {error}")))?
        .map_err(|error| SandboxError::Backend(format!("prepared cleanup intent: {error}")))
    }

    async fn finish_prepared_cleanup_stage(
        &self,
        attempt: PreparedCleanupAttempt,
        succeeded: bool,
    ) -> Result<(), SandboxError> {
        let Some((journal, permit)) = attempt.disarm() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || {
            if succeeded {
                journal.complete_cleanup_stage(&permit).map(|_| ())
            } else {
                journal
                    .record_cleanup_failure(&permit, PreparedShardCleanupFailure::Backend)
                    .map(|_| ())
            }
        })
        .await
        .map_err(|error| SandboxError::Backend(format!("prepared journal task failed: {error}")))?
        .map_err(|error| SandboxError::Backend(format!("prepared cleanup completion: {error}")))
    }

    fn validate_handle(runtime: &LinuxRuntime, handle: &SandboxHandle) -> Result<(), SandboxError> {
        if runtime.backend_token == handle.backend_token() {
            Ok(())
        } else {
            Err(SandboxError::ShardNotFound)
        }
    }

    fn runtime_shard_fence(
        runtime: &LinuxRuntime,
    ) -> Result<browserd_core::ShardFence, SandboxError> {
        runtime
            .ingress_lease
            .reservation()
            .egress_fence()
            .map(|fence| fence.shard().clone())
            .ok_or_else(|| {
                SandboxError::Backend("runtime is missing its exact egress fence".into())
            })
    }

    fn validate_host_paths(&self) -> Result<(), SandboxError> {
        for root in [&self.config.cgroup_root, &self.config.sandbox_root] {
            if !self.filesystem.is_directory(root)?
                || !self.filesystem.is_writable(root)?
                || self.filesystem.contains_symlink(root)?
            {
                return Err(SandboxError::Backend(format!(
                    "sandbox root unavailable: {}",
                    root.display()
                )));
            }
        }
        for executable in [
            &self.config.bwrap_executable,
            &self.config.chromium.host_executable,
            &self.config.launch_gate.host_executable,
        ] {
            if !self.filesystem.is_file(executable)?
                || self.filesystem.contains_symlink(executable)?
            {
                return Err(SandboxError::Backend(format!(
                    "runtime executable unavailable: {}",
                    executable.display()
                )));
            }
        }
        if self
            .filesystem
            .is_writable(&self.config.launch_gate.host_executable)?
        {
            return Err(SandboxError::Backend(
                "launch gate executable is writable".into(),
            ));
        }
        for mount in &self.config.read_only_mounts {
            if (!self.filesystem.is_directory(&mount.source)?
                && !self.filesystem.is_file(&mount.source)?)
                || self.filesystem.contains_symlink(&mount.source)?
            {
                return Err(SandboxError::Backend(format!(
                    "read-only runtime mount unavailable: {}",
                    mount.source.display()
                )));
            }
        }
        let controllers = self
            .filesystem
            .read_file(&self.config.cgroup_root.join("cgroup.controllers"))?;
        if !["cpu", "memory", "pids"].into_iter().all(|controller| {
            controllers
                .split_whitespace()
                .any(|item| item == controller)
        }) {
            return Err(SandboxError::Backend(
                "required cgroup v2 controllers unavailable".into(),
            ));
        }
        Ok(())
    }

    fn provision_snapshot(
        &self,
        shard_id: &ShardId,
        backend_token: &str,
    ) -> Result<ProvisionCleanup, SandboxError> {
        let provisions = self
            .provisioning
            .lock()
            .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
        let provision = provisions
            .get(shard_id)
            .ok_or_else(|| SandboxError::Backend("provision cleanup ownership missing".into()))?;
        if provision.backend_token != backend_token {
            return Err(SandboxError::Backend(
                "provision cleanup ownership changed".into(),
            ));
        }
        Ok(provision.clone())
    }

    fn update_provision(
        &self,
        shard_id: &ShardId,
        backend_token: &str,
        update: impl FnOnce(&mut ProvisionCleanup),
    ) -> Result<(), SandboxError> {
        let mut provisions = self
            .provisioning
            .lock()
            .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
        let provision = provisions
            .get_mut(shard_id)
            .ok_or_else(|| SandboxError::Backend("provision cleanup ownership missing".into()))?;
        if provision.backend_token != backend_token {
            return Err(SandboxError::Backend(
                "provision cleanup ownership changed".into(),
            ));
        }
        update(provision);
        Ok(())
    }

    fn runtime_cleanup_operation(
        &self,
        handle: &SandboxHandle,
    ) -> Result<Arc<AsyncMutex<()>>, SandboxError> {
        let runtimes = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
        let runtime = runtimes
            .get(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        Self::validate_handle(runtime, handle)?;
        Ok(runtime.cleanup_operation.clone())
    }

    fn runtime_process_operation(
        &self,
        handle: &SandboxHandle,
    ) -> Result<Arc<AsyncMutex<()>>, SandboxError> {
        let runtimes = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
        let runtime = runtimes
            .get(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        Self::validate_handle(runtime, handle)?;
        Ok(runtime.process_operation.clone())
    }

    async fn cleanup_provision(
        &self,
        shard_id: &ShardId,
        backend_token: &str,
    ) -> Result<(), SandboxError> {
        let state = self.provision_snapshot(shard_id, backend_token)?;
        let shard_fence = state
            .egress_reservation
            .egress_fence()
            .ok_or_else(|| SandboxError::Backend("missing exact egress cleanup fence".into()))?
            .shard()
            .clone();
        let revoke_needed = state.route_may_exist && !state.route_revoked;
        let abort_needed = state.child_may_exist && !state.child_aborted;
        let revoke_permit = self
            .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::RevokeEgress)
            .await?;
        let revoke = async {
            let revoke_result = if !revoke_needed {
                Ok(())
            } else if let Some(lease) = &state.ingress_lease {
                self.egress.revoke(lease).await
            } else {
                self.egress
                    .cancel_reservation(&state.egress_reservation)
                    .await
            };
            self.finish_prepared_cleanup_stage(revoke_permit, revoke_result.is_ok())
                .await?;
            revoke_result?;
            if revoke_needed {
                self.update_provision(shard_id, backend_token, |provision| {
                    provision.route_revoked = true;
                })?;
            }

            let drained_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::ConfirmEgressDrained,
                )
                .await?;
            let drained_result = if self.prepared_journal.is_none() || !state.route_may_exist {
                Ok(())
            } else if let Some(lease) = &state.ingress_lease {
                match self.egress.is_active(lease).await {
                    Ok(false) => Ok(()),
                    Ok(true) => Err(SandboxError::Backend(
                        "provisioning route remained active after revoke".into(),
                    )),
                    Err(error) => Err(error),
                }
            } else {
                // cancel_reservation is the terminal receipt for a generation that never
                // reached namespace attachment.
                Ok(())
            };
            self.finish_prepared_cleanup_stage(drained_permit, drained_result.is_ok())
                .await?;
            drained_result
        };
        let abort = async {
            let abort_permit = self
                .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::AbortGate)
                .await?;
            let abort_result = if abort_needed {
                self.process
                    .abort_spawned(backend_token, state.identity)
                    .await
            } else {
                Ok(())
            };
            self.finish_prepared_cleanup_stage(abort_permit, abort_result.is_ok())
                .await?;

            if self.prepared_journal.is_none() {
                abort_result?;
                if abort_needed {
                    self.update_provision(shard_id, backend_token, |provision| {
                        provision.child_aborted = true;
                    })?;
                }
                return Ok::<(), SandboxError>(());
            }

            let kill_permit = self
                .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::KillCgroup)
                .await?;
            let kill_result =
                if state.child_may_exist && state.cgroup_created && !state.cgroup_removed {
                    self.filesystem
                        .write_file(&state.cgroup_path.join("cgroup.kill"), "1")
                } else {
                    Ok(())
                };
            self.finish_prepared_cleanup_stage(kill_permit, kill_result.is_ok())
                .await?;
            kill_result?;

            let death_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::ConfirmProcessDeath,
                )
                .await?;
            let death_result = async {
                if state.child_may_exist && state.cgroup_created && !state.cgroup_removed {
                    let mut elapsed = Duration::ZERO;
                    loop {
                        let events = self
                            .filesystem
                            .read_file(&state.cgroup_path.join("cgroup.events"))?;
                        if events.lines().any(|line| line.trim() == "populated 0") {
                            break Ok(());
                        }
                        if elapsed >= self.config.termination_grace {
                            break Err(SandboxError::Backend(
                                "provisioning cgroup remained populated after kill".into(),
                            ));
                        }
                        self.process.wait(self.config.poll_interval).await;
                        elapsed = elapsed.saturating_add(self.config.poll_interval);
                    }
                } else {
                    Ok(())
                }
            }
            .await;
            self.finish_prepared_cleanup_stage(death_permit, death_result.is_ok())
                .await?;
            death_result?;
            self.update_provision(shard_id, backend_token, |provision| {
                provision.child_aborted = true;
            })?;
            Ok(())
        };
        let (revoke_result, abort_result) = tokio::join!(revoke, abort);
        let mut cleanup_errors = Vec::new();
        if let Err(error) = revoke_result {
            cleanup_errors.push(format!("route revoke: {error}"));
        }
        if let Err(error) = abort_result {
            cleanup_errors.push(format!("child abort: {error}"));
        }

        let mut state = self.provision_snapshot(shard_id, backend_token)?;
        let child_is_dead = !state.child_may_exist || state.child_aborted;
        let route_is_drained = !state.route_may_exist || state.route_revoked;
        if self.prepared_journal.is_some() && child_is_dead && route_is_drained {
            let close_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::CloseCapabilities,
                )
                .await?;
            self.finish_prepared_cleanup_stage(close_permit, true)
                .await?;

            let namespace_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::CleanupNetworkNamespace,
                )
                .await?;
            let namespace = {
                let mut provisions = self.provisioning.lock().map_err(|_| {
                    SandboxError::Backend("provision ownership lock poisoned".into())
                })?;
                let provision = provisions.get_mut(shard_id).ok_or_else(|| {
                    SandboxError::Backend("provision cleanup ownership missing".into())
                })?;
                if provision.backend_token != backend_token {
                    return Err(SandboxError::Backend(
                        "provision cleanup ownership changed".into(),
                    ));
                }
                provision._network_namespace.take()
            };
            drop(namespace);
            state._network_namespace = None;
            self.finish_prepared_cleanup_stage(namespace_permit, true)
                .await?;

            let runtime_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::CleanupRuntimeFilesystem,
                )
                .await?;
            let runtime_result = if state.runtime_created && !state.runtime_removed {
                self.filesystem.remove_directory(&state.runtime_path)
            } else {
                Ok(())
            };
            self.finish_prepared_cleanup_stage(runtime_permit, runtime_result.is_ok())
                .await?;
            match runtime_result {
                Ok(()) => {
                    if state.runtime_created {
                        self.update_provision(shard_id, backend_token, |provision| {
                            provision.runtime_removed = true;
                        })?;
                        state.runtime_removed = true;
                    }
                }
                Err(error) => cleanup_errors.push(format!("runtime removal: {error}")),
            }

            if cleanup_errors.is_empty() {
                let cgroup_permit = self
                    .begin_prepared_cleanup_stage(
                        &shard_fence,
                        PreparedShardCleanupStage::RemoveCgroup,
                    )
                    .await?;
                let cgroup_result = if state.cgroup_created && !state.cgroup_removed {
                    self.filesystem.remove_directory(&state.cgroup_path)
                } else {
                    Ok(())
                };
                self.finish_prepared_cleanup_stage(cgroup_permit, cgroup_result.is_ok())
                    .await?;
                match cgroup_result {
                    Ok(()) => {
                        if state.cgroup_created {
                            self.update_provision(shard_id, backend_token, |provision| {
                                provision.cgroup_removed = true;
                            })?;
                            state.cgroup_removed = true;
                        }
                    }
                    Err(error) => cleanup_errors.push(format!("cgroup removal: {error}")),
                }
            }
        } else if self.prepared_journal.is_none() {
            if child_is_dead && state.runtime_created && !state.runtime_removed {
                match self.filesystem.remove_directory(&state.runtime_path) {
                    Ok(()) => {
                        self.update_provision(shard_id, backend_token, |provision| {
                            provision.runtime_removed = true;
                        })?;
                        state.runtime_removed = true;
                    }
                    Err(error) => cleanup_errors.push(format!("runtime removal: {error}")),
                }
            }
            if child_is_dead && state.cgroup_created && !state.cgroup_removed {
                match self.filesystem.remove_directory(&state.cgroup_path) {
                    Ok(()) => {
                        self.update_provision(shard_id, backend_token, |provision| {
                            provision.cgroup_removed = true;
                        })?;
                        state.cgroup_removed = true;
                    }
                    Err(error) => cleanup_errors.push(format!("cgroup removal: {error}")),
                }
            }
        }
        let resources_removed = (!state.runtime_created || state.runtime_removed)
            && (!state.cgroup_created || state.cgroup_removed);
        if child_is_dead && route_is_drained && resources_removed {
            let release_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::ReleaseEgressGeneration,
                )
                .await?;
            let release = if !state.route_may_exist || state.route_released {
                Ok(())
            } else if let Some(lease) = &state.ingress_lease {
                self.egress.release(lease).await
            } else {
                self.egress
                    .release_reservation(&state.egress_reservation)
                    .await
            };
            self.finish_prepared_cleanup_stage(release_permit, release.is_ok())
                .await?;
            match release {
                Ok(()) => {
                    if state.route_may_exist {
                        self.update_provision(shard_id, backend_token, |provision| {
                            provision.route_released = true;
                        })?;
                        state.route_released = true;
                    }
                }
                Err(error) => cleanup_errors.push(format!("route release: {error}")),
            }
        }
        let complete = (!state.route_may_exist || (state.route_revoked && state.route_released))
            && (!state.child_may_exist || state.child_aborted)
            && (!state.runtime_created || state.runtime_removed)
            && (!state.cgroup_created || state.cgroup_removed);
        if !complete {
            if cleanup_errors.is_empty() {
                cleanup_errors.push("cleanup did not complete all stages".into());
            }
            return Err(SandboxError::Backend(format!(
                "provision cleanup incomplete: {}",
                cleanup_errors.join("; ")
            )));
        }
        let mut provisions = self
            .provisioning
            .lock()
            .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
        if provisions
            .get(shard_id)
            .is_none_or(|provision| provision.backend_token != backend_token)
        {
            return Err(SandboxError::Backend(
                "provision cleanup ownership changed before completion".into(),
            ));
        }
        provisions.remove(shard_id);
        Ok(())
    }

    fn instance_directory_name(spec: &LaunchSpec) -> String {
        format!(
            "{}-launch-{}",
            spec.shard_id(),
            spec.dedicated_egress()
                .egress_fence()
                .shard()
                .launch_generation()
                .get()
        )
    }

    #[must_use]
    pub fn planned_spawn_request(&self, spec: &LaunchSpec) -> SpawnRequest {
        let instance_directory = Self::instance_directory_name(spec);
        let runtime_path = self.config.sandbox_root.join(&instance_directory);
        let profile_path = runtime_path.join("profile");
        let mut arguments = [
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/dev/shm",
            "--rlimit",
            "core",
            "0",
            "--rlimit",
            "nofile",
            "65536",
            "--bind",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        arguments.push(profile_path.into_os_string());
        arguments.push(OsString::from("/profile"));
        arguments.extend([
            OsString::from("--ro-bind"),
            self.config
                .chromium
                .host_executable
                .clone()
                .into_os_string(),
            self.config
                .chromium
                .sandbox_executable
                .clone()
                .into_os_string(),
        ]);
        arguments.extend([
            OsString::from("--ro-bind"),
            self.config
                .launch_gate
                .host_executable
                .clone()
                .into_os_string(),
            self.config
                .launch_gate
                .sandbox_executable
                .clone()
                .into_os_string(),
        ]);
        for mount in &self.config.read_only_mounts {
            arguments.extend([
                OsString::from("--ro-bind"),
                mount.source.clone().into_os_string(),
                mount.destination.clone().into_os_string(),
            ]);
        }
        arguments.extend([
            OsString::from("--seccomp"),
            OsString::from(self.config.seccomp_fd.to_string()),
            OsString::from("--"),
            self.config
                .launch_gate
                .sandbox_executable
                .clone()
                .into_os_string(),
            OsString::from("--"),
            self.config
                .chromium
                .sandbox_executable
                .clone()
                .into_os_string(),
            OsString::from("--remote-debugging-pipe"),
            OsString::from("--headless"),
            OsString::from("--no-startup-window"),
            OsString::from("--user-data-dir=/profile"),
            OsString::from("--disable-features=BackForwardCache"),
        ]);
        SpawnRequest {
            program: self.config.bwrap_executable.clone(),
            arguments,
            inherited_fds: vec![self.config.seccomp_fd],
            cgroup_procs_path: self
                .config
                .cgroup_root
                .join(instance_directory)
                .join("cgroup.procs"),
        }
    }
}

#[async_trait]
impl<F, P, E> SandboxBackend for LinuxSandboxBackend<F, P, E>
where
    F: SandboxFilesystem,
    P: LinuxProcessBackend,
    E: EgressRouteBackend,
{
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        if self.prepared_journal.is_some() {
            return Err(SandboxError::Backend(
                "journaled Linux sandboxes require the gated supervisor workflow".into(),
            ));
        }
        let handle = self.provision_gated(spec).await?;
        let mut runtime = {
            let mut runtimes = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = runtimes
                .remove(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(&runtime, &handle)?;
            runtime
        };
        let backend_token = runtime.backend_token.clone();
        let identity = runtime.identity;
        let shard_fence = Self::runtime_shard_fence(&runtime)?;
        {
            let mut provisions = self
                .provisioning
                .lock()
                .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
            if provisions.contains_key(handle.shard_id()) {
                return Err(SandboxError::Backend(
                    "sandbox shard provisioning is already in progress".into(),
                ));
            }
            provisions.insert(
                handle.shard_id().clone(),
                ProvisionCleanup {
                    shard_fence,
                    backend_token: backend_token.clone(),
                    cgroup_path: runtime.cgroup_path.clone(),
                    runtime_path: runtime.runtime_path.clone(),
                    egress_reservation: runtime.ingress_lease.reservation().clone(),
                    _network_namespace: runtime._network_namespace.take(),
                    ingress_lease: Some(runtime.ingress_lease.clone()),
                    owner_active: true,
                    cgroup_created: true,
                    runtime_created: true,
                    route_may_exist: true,
                    child_may_exist: true,
                    identity: Some(identity),
                    route_revoked: false,
                    child_aborted: false,
                    runtime_removed: false,
                    cgroup_removed: false,
                    route_released: false,
                },
            );
        }
        let _attempt = ProvisionAttempt {
            provisions: &self.provisioning,
            shard_id: handle.shard_id().clone(),
            backend_token: backend_token.clone(),
        };
        let activation = self
            .process
            .release_prepared(&backend_token, identity)
            .await;
        if let Err(cause) = activation {
            let cleanup = self
                .cleanup_provision(handle.shard_id(), &backend_token)
                .await;
            return if cleanup.is_ok() {
                Err(cause)
            } else {
                Err(SandboxError::Backend(format!(
                    "{cause}; activation rollback incomplete"
                )))
            };
        }

        let provision = {
            let mut provisions = self
                .provisioning
                .lock()
                .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
            let provision = provisions
                .remove(handle.shard_id())
                .ok_or_else(|| SandboxError::Backend("provision ownership missing".into()))?;
            if provision.backend_token != backend_token {
                return Err(SandboxError::Backend(
                    "provision ownership changed before gate release commit".into(),
                ));
            }
            provision
        };
        runtime._network_namespace = provision._network_namespace;
        runtime.gate_released = true;
        let mut runtimes = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
        if runtimes
            .insert(handle.shard_id().clone(), runtime)
            .is_some()
        {
            return Err(SandboxError::Backend(
                "sandbox runtime changed before gate release commit".into(),
            ));
        }
        Ok(handle)
    }

    async fn provision_gated(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        let instance_directory = Self::instance_directory_name(spec);
        let cgroup_path = self.config.cgroup_root.join(&instance_directory);
        let runtime_path = self.config.sandbox_root.join(instance_directory);
        let egress_reservation = ShardEgressReservation::from_launch_spec(spec);
        let shard_fence = spec.dedicated_egress().egress_fence().shard().clone();
        let backend_token = LeaseId::new().to_string();
        let cleanup_retry = {
            let mut provisions = self
                .provisioning
                .lock()
                .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
            if let Some(existing) = provisions.get_mut(spec.shard_id()) {
                if existing.shard_fence != shard_fence {
                    return Err(SandboxError::LaunchGenerationMismatch);
                }
                if existing.owner_active {
                    return Err(SandboxError::Backend(
                        "sandbox shard provisioning is already in progress".into(),
                    ));
                }
                existing.owner_active = true;
                Some(existing.backend_token.clone())
            } else {
                if self
                    .runtimes
                    .lock()
                    .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?
                    .contains_key(spec.shard_id())
                {
                    return Err(SandboxError::Backend("sandbox shard already exists".into()));
                }
                provisions.insert(
                    spec.shard_id().clone(),
                    ProvisionCleanup {
                        shard_fence,
                        backend_token: backend_token.clone(),
                        cgroup_path: cgroup_path.clone(),
                        runtime_path: runtime_path.clone(),
                        egress_reservation: egress_reservation.clone(),
                        _network_namespace: None,
                        ingress_lease: None,
                        owner_active: true,
                        cgroup_created: false,
                        runtime_created: false,
                        route_may_exist: false,
                        child_may_exist: false,
                        identity: None,
                        route_revoked: false,
                        child_aborted: false,
                        runtime_removed: false,
                        cgroup_removed: false,
                        route_released: false,
                    },
                );
                None
            }
        };
        let owned_token = cleanup_retry
            .as_deref()
            .unwrap_or(backend_token.as_str())
            .to_owned();
        let _attempt = ProvisionAttempt {
            provisions: &self.provisioning,
            shard_id: spec.shard_id().clone(),
            backend_token: owned_token.clone(),
        };
        if cleanup_retry.is_some() {
            let cleanup = self.cleanup_provision(spec.shard_id(), &owned_token).await;
            return match cleanup {
                Ok(()) => {
                    self.complete_prepared_cleanup(
                        spec.dedicated_egress().egress_fence().shard(),
                        &PreparedShardCleanupStage::ALL,
                    )
                    .await?;
                    Err(SandboxError::Backend(
                        "abandoned sandbox provisioning was cleaned; retry provisioning".into(),
                    ))
                }
                Err(error) => Err(SandboxError::Backend(format!(
                    "abandoned sandbox provisioning cleanup incomplete: {error}"
                ))),
            };
        }
        let preflight = self
            .reserve_prepared_record(spec, &backend_token, &cgroup_path, &runtime_path)
            .await
            .and_then(|()| self.validate_host_paths());
        if let Err(cause) = preflight {
            let cleanup = self
                .cleanup_provision(spec.shard_id(), &backend_token)
                .await;
            return match cleanup {
                Ok(()) => {
                    self.complete_prepared_cleanup(
                        spec.dedicated_egress().egress_fence().shard(),
                        &PreparedShardCleanupStage::ALL,
                    )
                    .await?;
                    Err(cause)
                }
                Err(cleanup_error) => Err(SandboxError::Backend(format!(
                    "{cause}; empty provisioning rollback incomplete: {cleanup_error}"
                ))),
            };
        }
        let provisioned = async {
            let shard_fence = spec.dedicated_egress().egress_fence().shard();
            let filesystem_effect = self
                .begin_prepared_effect(shard_fence, PreparedShardEffect::CreateFilesystemCgroup)
                .await?;
            self.filesystem.create_directory(&cgroup_path)?;
            self.update_provision(spec.shard_id(), &backend_token, |provision| {
                provision.cgroup_created = true;
            })?;
            if self.filesystem.contains_symlink(&cgroup_path)? {
                return Err(SandboxError::Backend(
                    "created cgroup path resolved through a symlink".into(),
                ));
            }
            self.filesystem.write_file(
                &cgroup_path.join("memory.max"),
                &self.config.limits.memory_max.to_string(),
            )?;
            self.filesystem.write_file(
                &cgroup_path.join("memory.high"),
                &self.config.limits.memory_high.to_string(),
            )?;
            self.filesystem
                .write_file(&cgroup_path.join("memory.swap.max"), "0")?;
            self.filesystem
                .write_file(&cgroup_path.join("memory.oom.group"), "1")?;
            self.filesystem.write_file(
                &cgroup_path.join("pids.max"),
                &self.config.limits.pids_max.to_string(),
            )?;
            self.filesystem.write_file(
                &cgroup_path.join("cpu.max"),
                &format!(
                    "{} {}",
                    self.config.limits.cpu_quota, self.config.limits.cpu_period
                ),
            )?;
            self.filesystem
                .write_file(&cgroup_path.join("cpu.weight"), "100")?;
            self.filesystem.create_directory(&runtime_path)?;
            self.update_provision(spec.shard_id(), &backend_token, |provision| {
                provision.runtime_created = true;
            })?;
            if self.filesystem.contains_symlink(&runtime_path)? {
                return Err(SandboxError::Backend(
                    "created runtime path resolved through a symlink".into(),
                ));
            }
            self.filesystem
                .create_directory(&runtime_path.join("profile"))?;

            self.complete_prepared_effect(filesystem_effect).await?;

            // Reserving the exact egress generation is deliberately completed before
            // spawning. It does not install ingress in the sandbox namespace, while it
            // does preserve the fail-closed guarantee that a mandatory route failure
            // cannot leave a child behind.
            self.update_provision(spec.shard_id(), &backend_token, |provision| {
                provision.route_may_exist = true;
            })?;
            let prepare_egress_effect = self
                .begin_prepared_effect(
                    shard_fence,
                    PreparedShardEffect::PrepareEgress(
                        spec.dedicated_egress().egress_fence().clone(),
                    ),
                )
                .await?;
            self.egress.prepare(&egress_reservation).await?;
            self.complete_prepared_effect(prepare_egress_effect).await?;

            let spawn_effect = self
                .begin_prepared_effect(shard_fence, PreparedShardEffect::SpawnGatedChild)
                .await?;
            self.update_provision(spec.shard_id(), &backend_token, |provision| {
                provision.child_may_exist = true;
            })?;
            let prepared_child = self
                .process
                .spawn_prepared(&backend_token, &self.planned_spawn_request(spec))
                .await?;
            let (identity, network_namespace) = prepared_child.into_parts();
            self.complete_prepared_effect(spawn_effect).await?;
            self.update_provision(spec.shard_id(), &backend_token, |provision| {
                provision.identity = Some(identity);
                provision._network_namespace = Some(network_namespace.clone_for_owner());
            })?;
            let identity_effect = self
                .begin_prepared_effect(shard_fence, PreparedShardEffect::ProveProcessIdentity)
                .await?;
            if identity.pid == 0 || identity.start_time_ticks == 0 {
                return Err(SandboxError::Backend("invalid child PID identity".into()));
            }
            if !self
                .process
                .identity_matches(&backend_token, identity)
                .await?
            {
                return Err(SandboxError::Backend(
                    "spawned child PID identity mismatch".into(),
                ));
            }
            self.complete_prepared_effect(identity_effect).await?;

            let cgroup_effect = self
                .begin_prepared_effect(shard_fence, PreparedShardEffect::AttachCgroup)
                .await?;
            let cgroup_members = self
                .filesystem
                .read_file(&cgroup_path.join("cgroup.procs"))?
                .split_whitespace()
                .map(|member| {
                    member.parse::<u32>().map_err(|_| {
                        SandboxError::Backend("invalid cgroup.procs membership".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !cgroup_members.contains(&identity.pid()) {
                return Err(SandboxError::Backend(
                    "sandbox child was not attached to its cgroup".into(),
                ));
            }
            if !self
                .process
                .identity_matches(&backend_token, identity)
                .await?
            {
                return Err(SandboxError::Backend(
                    "sandbox child PID identity changed during cgroup attachment".into(),
                ));
            }
            self.complete_prepared_effect(cgroup_effect).await?;

            let namespace_effect = self
                .begin_prepared_effect(shard_fence, PreparedShardEffect::ProveNetworkNamespace)
                .await?;
            if self.prepared_journal.is_some()
                && !self
                    .process
                    .network_namespace_matches(&backend_token, identity, &network_namespace)
                    .await?
            {
                return Err(SandboxError::Backend(
                    "sandbox child network namespace did not match its pinned capability".into(),
                ));
            }
            self.complete_prepared_effect(namespace_effect).await?;

            let ingress_effect = self
                .begin_prepared_effect(
                    shard_fence,
                    PreparedShardEffect::RegisterIngress(
                        spec.dedicated_egress().egress_fence().clone(),
                    ),
                )
                .await?;
            let ingress_receipt = self
                .egress
                .attach(&egress_reservation, &network_namespace)
                .await?;
            let ingress_lease = ShardIngressLease::new(
                egress_reservation.clone(),
                network_namespace.identity(),
                ingress_receipt,
            );
            self.update_provision(spec.shard_id(), &backend_token, |provision| {
                provision.ingress_lease = Some(ingress_lease.clone());
            })?;
            if !self
                .process
                .network_namespace_matches(&backend_token, identity, &network_namespace)
                .await?
            {
                return Err(SandboxError::Backend(
                    "sandbox child network namespace changed during ingress attachment".into(),
                ));
            }
            if !self.egress.is_active(&ingress_lease).await? {
                return Err(SandboxError::Backend(
                    "sandbox ingress lease became inactive before launch".into(),
                ));
            }
            self.complete_prepared_effect(ingress_effect).await?;
            let mut provisions = self
                .provisioning
                .lock()
                .map_err(|_| SandboxError::Backend("provision ownership lock poisoned".into()))?;
            if provisions
                .get(spec.shard_id())
                .is_none_or(|provision| provision.backend_token != backend_token)
            {
                return Err(SandboxError::Backend(
                    "provision ownership changed before commit".into(),
                ));
            }
            let mut runtimes = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            if runtimes.contains_key(spec.shard_id()) {
                return Err(SandboxError::Backend("sandbox shard already exists".into()));
            }
            runtimes.insert(
                spec.shard_id().clone(),
                LinuxRuntime {
                    identity,
                    backend_token: backend_token.clone(),
                    cgroup_path: cgroup_path.clone(),
                    runtime_path: runtime_path.clone(),
                    _network_namespace: Some(network_namespace),
                    ingress_lease,
                    gate_released: false,
                    egress_revoked: false,
                    egress_released: false,
                    process_released: false,
                    runtime_removed: false,
                    cgroup_removed: false,
                    namespaces_cleaned: false,
                    cleanup_operation: Arc::new(AsyncMutex::new(())),
                    process_operation: Arc::new(AsyncMutex::new(())),
                },
            );
            provisions.remove(spec.shard_id());
            Ok(SandboxHandle::new(
                spec.shard_id().clone(),
                backend_token.clone(),
            ))
        }
        .await;
        match provisioned {
            Ok(handle) => Ok(handle),
            Err(cause) => {
                match self
                    .cleanup_provision(spec.shard_id(), &backend_token)
                    .await
                {
                    Ok(()) => {
                        self.complete_prepared_cleanup(
                            spec.dedicated_egress().egress_fence().shard(),
                            &PreparedShardCleanupStage::ALL,
                        )
                        .await?;
                        Err(cause)
                    }
                    Err(cleanup_error) => Err(SandboxError::Backend(format!(
                        "{cause}; provisioning rollback incomplete: {cleanup_error}"
                    ))),
                }
            }
        }
    }

    async fn commit_cdp_claim(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        let fence = {
            let runtimes = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = runtimes
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            runtime
                .ingress_lease
                .reservation()
                .egress_fence()
                .ok_or_else(|| {
                    SandboxError::Backend("runtime is missing its exact egress fence".into())
                })?
                .shard()
                .clone()
        };
        let permit = self
            .begin_prepared_effect(&fence, PreparedShardEffect::ClaimCdp)
            .await?;
        self.complete_prepared_effect(permit).await
    }

    async fn activate(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        let operation = self.runtime_process_operation(handle)?;
        let _operation_guard = operation.lock().await;
        let (
            backend_token,
            identity,
            already_released,
            cgroup_path,
            network_namespace,
            ingress_lease,
            shard_fence,
        ) = {
            let runtimes = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = runtimes
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            (
                runtime.backend_token.clone(),
                runtime.identity,
                runtime.gate_released,
                runtime.cgroup_path.clone(),
                runtime
                    ._network_namespace
                    .as_ref()
                    .ok_or_else(|| {
                        SandboxError::Backend("runtime network namespace is closed".into())
                    })?
                    .clone_for_owner(),
                runtime.ingress_lease.clone(),
                runtime
                    .ingress_lease
                    .reservation()
                    .egress_fence()
                    .ok_or_else(|| {
                        SandboxError::Backend("runtime is missing its exact egress fence".into())
                    })?
                    .shard()
                    .clone(),
            )
        };
        if already_released {
            return Ok(());
        }

        let containment = self
            .begin_prepared_effect(&shard_fence, PreparedShardEffect::ProveContainment)
            .await?;
        if !self
            .process
            .identity_matches(&backend_token, identity)
            .await?
            || !self
                .process
                .network_namespace_matches(&backend_token, identity, &network_namespace)
                .await?
            || !self.egress.is_active(&ingress_lease).await?
        {
            return Err(SandboxError::Backend(
                "sandbox containment changed before activation".into(),
            ));
        }
        let cgroup_members = self
            .filesystem
            .read_file(&cgroup_path.join("cgroup.procs"))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SandboxError::Backend("invalid cgroup.procs membership".into()))?;
        if !cgroup_members.contains(&identity.pid()) {
            return Err(SandboxError::Backend(
                "sandbox child left its cgroup before activation".into(),
            ));
        }
        self.complete_prepared_effect(containment).await?;

        let release_sequence = self.next_release_sequence(&shard_fence).await?;
        let release = self
            .begin_prepared_effect(
                &shard_fence,
                PreparedShardEffect::SendReleaseToken { release_sequence },
            )
            .await?;
        self.process
            .release_prepared(&backend_token, identity)
            .await?;
        self.complete_prepared_effect(release).await?;
        let mut runtimes = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
        let runtime = runtimes
            .get_mut(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        Self::validate_handle(runtime, handle)?;
        if runtime.backend_token != backend_token || runtime.identity != identity {
            return Err(SandboxError::ShardNotFound);
        }
        runtime.gate_released = true;
        Ok(())
    }

    async fn claim_cdp_pipes(
        &self,
        handle: &SandboxHandle,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        let operation = self.runtime_process_operation(handle)?;
        let _operation_guard = operation.lock().await;
        let (backend_token, identity) = {
            let runtimes = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = runtimes
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            (runtime.backend_token.clone(), runtime.identity)
        };
        self.process.claim_cdp_pipes(&backend_token, identity).await
    }

    async fn revoke_egress(
        &self,
        handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        let operation = self.runtime_cleanup_operation(handle)?;
        let _operation_guard = operation.lock().await;
        let (lease, already_revoked, shard_fence) = {
            let state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = state
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            (
                runtime.ingress_lease.clone(),
                runtime.egress_revoked,
                Self::runtime_shard_fence(runtime)?,
            )
        };
        let revoke_permit = self
            .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::RevokeEgress)
            .await?;
        let revoke_result = if already_revoked {
            Ok(())
        } else {
            self.egress.revoke(&lease).await
        };
        self.finish_prepared_cleanup_stage(revoke_permit, revoke_result.is_ok())
            .await?;
        revoke_result?;

        let drained_permit = self
            .begin_prepared_cleanup_stage(
                &shard_fence,
                PreparedShardCleanupStage::ConfirmEgressDrained,
            )
            .await?;
        let drained_result = if self.prepared_journal.is_some() {
            match self.egress.is_active(&lease).await {
                Ok(false) => Ok(()),
                Ok(true) => Err(SandboxError::Backend(
                    "egress route remained active after revoke".into(),
                )),
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        self.finish_prepared_cleanup_stage(drained_permit, drained_result.is_ok())
            .await?;
        drained_result?;

        let release_after_cleanup = {
            let mut state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = state
                .get_mut(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            if runtime.ingress_lease != lease {
                return Err(SandboxError::ShardNotFound);
            }
            runtime.egress_revoked = true;
            runtime.namespaces_cleaned && !runtime.egress_released
        };
        if release_after_cleanup {
            let release_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::ReleaseEgressGeneration,
                )
                .await?;
            let release_result = self.egress.release(&lease).await;
            self.finish_prepared_cleanup_stage(release_permit, release_result.is_ok())
                .await?;
            release_result?;
            let mut state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = state
                .get_mut(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            if runtime.ingress_lease != lease {
                return Err(SandboxError::ShardNotFound);
            }
            runtime.egress_released = true;
            let remove_runtime = runtime.namespaces_cleaned;
            if remove_runtime {
                state.remove(handle.shard_id());
            }
        }
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        let process_operation = self.runtime_process_operation(handle)?;
        let _process_operation_guard = process_operation.lock().await;
        let (identity, backend_token, cgroup_path, shard_fence) = {
            let state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = state
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            (
                runtime.identity,
                runtime.backend_token.clone(),
                runtime.cgroup_path.clone(),
                Self::runtime_shard_fence(runtime)?,
            )
        };

        let abort_permit = self
            .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::AbortGate)
            .await?;
        let abort_result = async {
            if self
                .process
                .identity_matches(&backend_token, identity)
                .await?
            {
                self.process
                    .signal(&backend_token, identity, ProcessSignal::Terminate)
                    .await?;
                let mut elapsed = Duration::ZERO;
                while elapsed < self.config.termination_grace
                    && self.process.is_alive(&backend_token, identity).await?
                {
                    self.process.wait(self.config.poll_interval).await;
                    elapsed = elapsed.saturating_add(self.config.poll_interval);
                }
                if self.process.is_alive(&backend_token, identity).await?
                    && self
                        .process
                        .identity_matches(&backend_token, identity)
                        .await?
                {
                    self.process
                        .signal(&backend_token, identity, ProcessSignal::Kill)
                        .await?;
                }
            }
            Ok::<(), SandboxError>(())
        }
        .await;
        self.finish_prepared_cleanup_stage(abort_permit, abort_result.is_ok())
            .await?;
        abort_result?;

        let kill_permit = self
            .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::KillCgroup)
            .await?;
        let kill_result = self
            .filesystem
            .write_file(&cgroup_path.join("cgroup.kill"), "1");
        self.finish_prepared_cleanup_stage(kill_permit, kill_result.is_ok())
            .await?;
        kill_result?;

        let death_permit = self
            .begin_prepared_cleanup_stage(
                &shard_fence,
                PreparedShardCleanupStage::ConfirmProcessDeath,
            )
            .await?;
        let death_result = async {
            let mut elapsed = Duration::ZERO;
            loop {
                let events = self
                    .filesystem
                    .read_file(&cgroup_path.join("cgroup.events"))?;
                if events.lines().any(|line| line.trim() == "populated 0") {
                    break Ok(());
                }
                if elapsed >= self.config.termination_grace {
                    break Err(SandboxError::Backend(
                        "cgroup remained populated after kill".into(),
                    ));
                }
                self.process.wait(self.config.poll_interval).await;
                elapsed = elapsed.saturating_add(self.config.poll_interval);
            }
        }
        .await;
        self.finish_prepared_cleanup_stage(death_permit, death_result.is_ok())
            .await?;
        death_result
    }

    async fn cleanup_namespaces(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        let operation = self.runtime_cleanup_operation(handle)?;
        let _operation_guard = operation.lock().await;
        let process_operation = self.runtime_process_operation(handle)?;
        let _process_operation_guard = process_operation.lock().await;
        let mut runtime = self
            .runtimes
            .lock()
            .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?
            .get(handle.shard_id())
            .cloned()
            .ok_or(SandboxError::ShardNotFound)?;
        Self::validate_handle(&runtime, handle)?;
        let shard_fence = Self::runtime_shard_fence(&runtime)?;
        let close_permit = self
            .begin_prepared_cleanup_stage(
                &shard_fence,
                PreparedShardCleanupStage::CloseCapabilities,
            )
            .await?;
        let close_result = async {
            if !runtime.process_released {
                let events = self
                    .filesystem
                    .read_file(&runtime.cgroup_path.join("cgroup.events"))?;
                if !events.lines().any(|line| line.trim() == "populated 0") {
                    return Err(SandboxError::Backend(
                        "refusing cleanup of populated cgroup".into(),
                    ));
                }
                self.process
                    .release_spawned(&runtime.backend_token, runtime.identity)
                    .await?;
                let mut state = self
                    .runtimes
                    .lock()
                    .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
                let stored = state
                    .get_mut(handle.shard_id())
                    .ok_or(SandboxError::ShardNotFound)?;
                Self::validate_handle(stored, handle)?;
                if stored.ingress_lease != runtime.ingress_lease {
                    return Err(SandboxError::Backend(
                        "sandbox runtime fence changed during cleanup".into(),
                    ));
                }
                stored.process_released = true;
                runtime.process_released = true;
            }
            Ok::<(), SandboxError>(())
        }
        .await;
        self.finish_prepared_cleanup_stage(close_permit, close_result.is_ok())
            .await?;
        close_result?;

        let namespace_permit = self
            .begin_prepared_cleanup_stage(
                &shard_fence,
                PreparedShardCleanupStage::CleanupNetworkNamespace,
            )
            .await?;
        let namespace_result = {
            let state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            if stored.ingress_lease != runtime.ingress_lease {
                Err(SandboxError::Backend(
                    "sandbox runtime fence changed during cleanup".into(),
                ))
            } else {
                // The namespace descriptor is the local proof of which namespace the
                // exact ingress generation targeted. Keep it pinned in the runtime
                // tombstone until that generation has been revoked and released.
                Ok(())
            }
        };
        self.finish_prepared_cleanup_stage(namespace_permit, namespace_result.is_ok())
            .await?;
        namespace_result?;

        let cleanup = {
            let state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            if stored.ingress_lease != runtime.ingress_lease {
                return Err(SandboxError::Backend(
                    "sandbox runtime fence changed during cleanup".into(),
                ));
            }
            stored.clone()
        };
        if !cleanup.runtime_removed {
            let runtime_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::CleanupRuntimeFilesystem,
                )
                .await?;
            let runtime_result = self.filesystem.remove_directory(&cleanup.runtime_path);
            self.finish_prepared_cleanup_stage(runtime_permit, runtime_result.is_ok())
                .await?;
            runtime_result?;
            let mut state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get_mut(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            if stored.ingress_lease != cleanup.ingress_lease {
                return Err(SandboxError::Backend(
                    "sandbox runtime fence changed during cleanup".into(),
                ));
            }
            stored.runtime_removed = true;
        }
        if !cleanup.cgroup_removed {
            let events = self
                .filesystem
                .read_file(&cleanup.cgroup_path.join("cgroup.events"))?;
            if !events.lines().any(|line| line.trim() == "populated 0") {
                return Err(SandboxError::Backend(
                    "refusing cleanup of populated cgroup".into(),
                ));
            }
            let cgroup_permit = self
                .begin_prepared_cleanup_stage(&shard_fence, PreparedShardCleanupStage::RemoveCgroup)
                .await?;
            let cgroup_result = self.filesystem.remove_directory(&cleanup.cgroup_path);
            self.finish_prepared_cleanup_stage(cgroup_permit, cgroup_result.is_ok())
                .await?;
            cgroup_result?;
            let mut state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get_mut(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            if stored.ingress_lease != cleanup.ingress_lease {
                return Err(SandboxError::Backend(
                    "sandbox runtime fence changed during cleanup".into(),
                ));
            }
            stored.cgroup_removed = true;
        }
        {
            let mut state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get_mut(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            stored.namespaces_cleaned =
                stored.process_released && stored.runtime_removed && stored.cgroup_removed;
        }

        let release_lease = {
            let state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            (stored.namespaces_cleaned && stored.egress_revoked && !stored.egress_released)
                .then(|| stored.ingress_lease.clone())
        };
        if let Some(lease) = release_lease {
            let release_permit = self
                .begin_prepared_cleanup_stage(
                    &shard_fence,
                    PreparedShardCleanupStage::ReleaseEgressGeneration,
                )
                .await?;
            let release_result = self.egress.release(&lease).await;
            self.finish_prepared_cleanup_stage(release_permit, release_result.is_ok())
                .await?;
            release_result?;
            let mut state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let stored = state
                .get_mut(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(stored, handle)?;
            if stored.ingress_lease != lease {
                return Err(SandboxError::ShardNotFound);
            }
            stored.egress_released = true;
            let remove_runtime = stored.namespaces_cleaned;
            if remove_runtime {
                state.remove(handle.shard_id());
            }
        }
        Ok(())
    }

    async fn inspect(&self, handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        self.validate_host_paths()?;
        let (cgroup_path, ingress_lease) = {
            let state = self
                .runtimes
                .lock()
                .map_err(|_| SandboxError::Backend("runtime state lock poisoned".into()))?;
            let runtime = state
                .get(handle.shard_id())
                .ok_or(SandboxError::ShardNotFound)?;
            Self::validate_handle(runtime, handle)?;
            if runtime.namespaces_cleaned {
                return Err(SandboxError::ShardNotFound);
            }
            (runtime.cgroup_path.clone(), runtime.ingress_lease.clone())
        };
        let memory_current_bytes = self
            .filesystem
            .read_file(&cgroup_path.join("memory.current"))?
            .trim()
            .parse()
            .map_err(|_| SandboxError::Backend("invalid memory.current".into()))?;
        let memory_peak_bytes = self
            .filesystem
            .read_file(&cgroup_path.join("memory.peak"))?
            .trim()
            .parse()
            .map_err(|_| SandboxError::Backend("invalid memory.peak".into()))?;
        let process_count = u32::try_from(
            self.filesystem
                .read_file(&cgroup_path.join("cgroup.procs"))?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
        )
        .map_err(|_| SandboxError::Backend("process count overflow".into()))?;
        Ok(InspectResources {
            memory_current_bytes,
            memory_peak_bytes,
            process_count,
            egress_route_active: self.egress.is_active(&ingress_lease).await?,
        })
    }
}
