use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::ShardId;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::{
    CleanupReason, InspectResources, LaunchSpec, SandboxBackend, SandboxCapabilities, SandboxError,
    SandboxHandle,
};

/// Chromium's fixed command-input descriptor for `--remote-debugging-pipe`.
pub const CHROMIUM_CDP_READ_FD: i32 = 3;
/// Chromium's fixed event/output descriptor for `--remote-debugging-pipe`.
pub const CHROMIUM_CDP_WRITE_FD: i32 = 4;

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
        }
        Ok(Self {
            cgroup_root,
            sandbox_root,
            bwrap_executable,
            chromium,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSignal {
    Terminate,
    Kill,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpawnRequest {
    program: PathBuf,
    arguments: Vec<OsString>,
    inherited_fds: Vec<i32>,
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
        // The process backend owns mapping the per-launch CDP pipe ends to child FDs 3/4.
        // The sandbox backend only requires bwrap to preserve those fixed child descriptors.
        &self.inherited_fds
    }
}

#[async_trait]
pub trait LinuxProcessBackend: Send + Sync + 'static {
    /// Spawns the child and returns only after it has captured a stable PID/start-time identity.
    /// Implementations must terminate and reap any child they started before returning `Err`.
    async fn spawn(&self, request: &SpawnRequest) -> Result<ChildIdentity, SandboxError>;
    /// Terminates a child still owned by this backend without trusting its reported identity.
    async fn abort_spawned(&self, identity: ChildIdentity) -> Result<(), SandboxError>;
    /// Releases the retained process handle after cgroup emptiness has proven process exit.
    async fn release_spawned(&self, identity: ChildIdentity) -> Result<(), SandboxError>;
    async fn identity_matches(&self, identity: ChildIdentity) -> Result<bool, SandboxError>;
    async fn signal(
        &self,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError>;
    async fn is_alive(&self, identity: ChildIdentity) -> Result<bool, SandboxError>;
    async fn wait(&self, duration: Duration);
}

#[derive(Clone, Debug, Default)]
pub struct StdLinuxProcessBackend {
    children: Arc<StdMutex<HashMap<u32, tokio::process::Child>>>,
}

#[async_trait]
impl LinuxProcessBackend for StdLinuxProcessBackend {
    async fn spawn(&self, request: &SpawnRequest) -> Result<ChildIdentity, SandboxError> {
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
        let mut command = Command::new(request.program());
        command
            .args(request.arguments())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| SandboxError::Backend("spawned child has no PID".into()))?;
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) => {
                child.kill().await.map_err(|cleanup_error| {
                    SandboxError::Backend(format!(
                        "failed to read child identity ({error}); child cleanup failed: {cleanup_error}"
                    ))
                })?;
                return Err(SandboxError::Backend(format!(
                    "failed to read child identity: {error}"
                )));
            }
        };
        let start_time_ticks = match stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(start_time_ticks) if start_time_ticks != 0 => start_time_ticks,
            _ => {
                child.kill().await.map_err(|cleanup_error| {
                    SandboxError::Backend(format!(
                        "invalid child proc stat; child cleanup failed: {cleanup_error}"
                    ))
                })?;
                return Err(SandboxError::Backend("invalid child proc stat".into()));
            }
        };
        self.children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .insert(pid, child);
        Ok(ChildIdentity::new(pid, start_time_ticks))
    }

    async fn abort_spawned(&self, identity: ChildIdentity) -> Result<(), SandboxError> {
        let mut child = self
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?
            .remove(&identity.pid)
            .ok_or_else(|| SandboxError::Backend("spawned child ownership missing".into()))?;
        if child
            .try_wait()
            .map_err(|error| SandboxError::Backend(error.to_string()))?
            .is_none()
        {
            child
                .kill()
                .await
                .map_err(|error| SandboxError::Backend(error.to_string()))?;
        }
        Ok(())
    }

    async fn release_spawned(&self, identity: ChildIdentity) -> Result<(), SandboxError> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| SandboxError::Backend("child ownership lock poisoned".into()))?;
        let mut child = children
            .remove(&identity.pid)
            .ok_or_else(|| SandboxError::Backend("spawned child ownership missing".into()))?;
        if child
            .try_wait()
            .map_err(|error| SandboxError::Backend(error.to_string()))?
            .is_none()
        {
            children.insert(identity.pid, child);
            return Err(SandboxError::Backend(
                "cannot release a live spawned child".into(),
            ));
        }
        Ok(())
    }

    async fn identity_matches(&self, identity: ChildIdentity) -> Result<bool, SandboxError> {
        let stat = match fs::read_to_string(format!("/proc/{}/stat", identity.pid)) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(SandboxError::Backend(error.to_string())),
        };
        Ok(stat
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|value| value.parse::<u64>().ok())
            == Some(identity.start_time_ticks))
    }

    async fn signal(
        &self,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        if !self.identity_matches(identity).await? {
            return Err(SandboxError::Backend("child PID identity changed".into()));
        }
        let pid = i32::try_from(identity.pid)
            .map_err(|_| SandboxError::Backend("child PID exceeds i32".into()))?;
        kill(
            Pid::from_raw(pid),
            match signal {
                ProcessSignal::Terminate => Signal::SIGTERM,
                ProcessSignal::Kill => Signal::SIGKILL,
            },
        )
        .map_err(|error| SandboxError::Backend(error.to_string()))
    }

    async fn is_alive(&self, identity: ChildIdentity) -> Result<bool, SandboxError> {
        self.identity_matches(identity).await
    }

    async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[async_trait]
pub trait EgressRouteBackend: Send + Sync + 'static {
    async fn prepare(&self, shard_id: &ShardId) -> Result<(), SandboxError>;
    async fn revoke(&self, shard_id: &ShardId) -> Result<(), SandboxError>;
    async fn is_active(&self, shard_id: &ShardId) -> Result<bool, SandboxError>;
}

#[derive(Clone)]
struct LinuxRuntime {
    identity: ChildIdentity,
    cgroup_path: PathBuf,
    runtime_path: PathBuf,
}

pub struct LinuxSandboxBackend<F, P, E> {
    config: LinuxSandboxConfig,
    filesystem: F,
    process: P,
    egress: E,
    runtimes: Mutex<HashMap<ShardId, LinuxRuntime>>,
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
            runtimes: Mutex::new(HashMap::new()),
        }
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

    #[must_use]
    pub fn planned_spawn_request(&self, shard_id: &ShardId) -> SpawnRequest {
        let runtime_path = self.config.sandbox_root.join(shard_id.to_string());
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
        for mount in &self.config.read_only_mounts {
            arguments.extend([
                OsString::from("--ro-bind"),
                mount.source.clone().into_os_string(),
                mount.destination.clone().into_os_string(),
            ]);
        }
        arguments.extend([
            OsString::from("--preserve-fds"),
            OsString::from("2"),
            OsString::from("--seccomp"),
            OsString::from(self.config.seccomp_fd.to_string()),
            OsString::from("--"),
            self.config
                .chromium
                .sandbox_executable
                .clone()
                .into_os_string(),
            OsString::from("--remote-debugging-pipe"),
            OsString::from("--user-data-dir=/profile"),
            OsString::from("--disable-features=BackForwardCache"),
        ]);
        SpawnRequest {
            program: self.config.bwrap_executable.clone(),
            arguments,
            inherited_fds: vec![
                CHROMIUM_CDP_READ_FD,
                CHROMIUM_CDP_WRITE_FD,
                self.config.seccomp_fd,
            ],
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
        self.validate_host_paths()?;
        let cgroup_path = self.config.cgroup_root.join(spec.shard_id().to_string());
        let runtime_path = self.config.sandbox_root.join(spec.shard_id().to_string());
        let mut cgroup_created = false;
        let mut runtime_created = false;
        let mut route_attempted = false;
        let mut spawned = None;
        let provisioned = async {
            self.filesystem.create_directory(&cgroup_path)?;
            cgroup_created = true;
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
            runtime_created = true;
            if self.filesystem.contains_symlink(&runtime_path)? {
                return Err(SandboxError::Backend(
                    "created runtime path resolved through a symlink".into(),
                ));
            }
            self.filesystem
                .create_directory(&runtime_path.join("profile"))?;

            route_attempted = true;
            self.egress.prepare(spec.shard_id()).await?;
            let identity = self
                .process
                .spawn(&self.planned_spawn_request(spec.shard_id()))
                .await?;
            spawned = Some(identity);
            if identity.pid == 0 || identity.start_time_ticks == 0 {
                return Err(SandboxError::Backend("invalid child PID identity".into()));
            }
            if !self.process.identity_matches(identity).await? {
                return Err(SandboxError::Backend(
                    "spawned child PID identity mismatch".into(),
                ));
            }
            self.filesystem.write_file(
                &cgroup_path.join("cgroup.procs"),
                &identity.pid().to_string(),
            )?;
            Ok(identity)
        }
        .await;
        let identity = match provisioned {
            Ok(identity) => identity,
            Err(cause) => {
                let mut cleanup_errors = Vec::new();
                if route_attempted && let Err(error) = self.egress.revoke(spec.shard_id()).await {
                    cleanup_errors.push(format!("route: {error}"));
                }
                if let Some(identity) = spawned
                    && let Err(error) = self.process.abort_spawned(identity).await
                {
                    cleanup_errors.push(format!("child: {error}"));
                }
                if runtime_created
                    && let Err(error) = self.filesystem.remove_directory(&runtime_path)
                {
                    cleanup_errors.push(format!("runtime: {error}"));
                }
                if cgroup_created && let Err(error) = self.filesystem.remove_directory(&cgroup_path)
                {
                    cleanup_errors.push(format!("cgroup: {error}"));
                }
                if cleanup_errors.is_empty() {
                    return Err(cause);
                }
                return Err(SandboxError::Backend(format!(
                    "{cause}; provisioning rollback incomplete: {}",
                    cleanup_errors.join("; ")
                )));
            }
        };
        self.runtimes.lock().await.insert(
            spec.shard_id().clone(),
            LinuxRuntime {
                identity,
                cgroup_path,
                runtime_path,
            },
        );
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            spec.shard_id().to_string(),
        ))
    }

    async fn revoke_egress(
        &self,
        handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.egress.revoke(handle.shard_id()).await
    }

    async fn kill_cgroup(
        &self,
        handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        let state = self.runtimes.lock().await;
        let runtime = state
            .get(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        let identity = runtime.identity;
        let cgroup_path = runtime.cgroup_path.clone();
        drop(state);

        if self.process.identity_matches(identity).await? {
            self.process
                .signal(identity, ProcessSignal::Terminate)
                .await?;
            let mut elapsed = Duration::ZERO;
            while elapsed < self.config.termination_grace && self.process.is_alive(identity).await?
            {
                self.process.wait(self.config.poll_interval).await;
                elapsed = elapsed.saturating_add(self.config.poll_interval);
            }
            if self.process.is_alive(identity).await?
                && self.process.identity_matches(identity).await?
            {
                self.process.signal(identity, ProcessSignal::Kill).await?;
            }
        }
        self.filesystem
            .write_file(&cgroup_path.join("cgroup.kill"), "1")?;
        let mut elapsed = Duration::ZERO;
        loop {
            let events = self
                .filesystem
                .read_file(&cgroup_path.join("cgroup.events"))?;
            if events.lines().any(|line| line.trim() == "populated 0") {
                return Ok(());
            }
            if elapsed >= self.config.termination_grace {
                return Err(SandboxError::Backend(
                    "cgroup remained populated after kill".into(),
                ));
            }
            self.process.wait(self.config.poll_interval).await;
            elapsed = elapsed.saturating_add(self.config.poll_interval);
        }
    }

    async fn cleanup_namespaces(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        let runtime = self
            .runtimes
            .lock()
            .await
            .get(handle.shard_id())
            .cloned()
            .ok_or(SandboxError::ShardNotFound)?;
        let events = self
            .filesystem
            .read_file(&runtime.cgroup_path.join("cgroup.events"))?;
        if !events.lines().any(|line| line.trim() == "populated 0") {
            return Err(SandboxError::Backend(
                "refusing cleanup of populated cgroup".into(),
            ));
        }
        self.process.release_spawned(runtime.identity).await?;
        self.filesystem.remove_directory(&runtime.runtime_path)?;
        self.filesystem.remove_directory(&runtime.cgroup_path)?;
        self.runtimes.lock().await.remove(handle.shard_id());
        Ok(())
    }

    async fn inspect(&self, handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        self.validate_host_paths()?;
        let state = self.runtimes.lock().await;
        let runtime = state
            .get(handle.shard_id())
            .ok_or(SandboxError::ShardNotFound)?;
        let cgroup_path = runtime.cgroup_path.clone();
        drop(state);
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
            egress_route_active: self.egress.is_active(handle.shard_id()).await?,
        })
    }
}
