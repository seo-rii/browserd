#![allow(clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browserd_core::{LeaseId, ShardId, WorkerId};
use browserd_sandbox::{
    CgroupLimits, ChildIdentity, ChromiumRuntime, CleanupReason, EgressRouteBackend,
    LaunchGateRuntime, LaunchSpec, LinuxProcessBackend, LinuxSandboxBackend, LinuxSandboxConfig,
    ProcessSignal, ReadOnlyMount, SandboxBackend, SandboxError, SandboxFilesystem,
    ShardEgressFence, SpawnRequest, StdLinuxProcessBackend, StdSandboxFilesystem,
};

#[derive(Clone)]
struct CgroupReadBarriers {
    entered: Arc<Barrier>,
    proceed: Arc<Barrier>,
}

#[derive(Clone)]
struct RemoveBarriers {
    suffix: PathBuf,
    entered: Arc<Barrier>,
    proceed: Arc<Barrier>,
}

#[derive(Clone, Default)]
struct FakeFilesystem {
    files: Arc<Mutex<HashMap<PathBuf, String>>>,
    directories: Arc<Mutex<HashSet<PathBuf>>>,
    symlinks: Arc<Mutex<HashSet<PathBuf>>>,
    unwritable: Arc<Mutex<HashSet<PathBuf>>>,
    failing_writes: Arc<Mutex<HashSet<String>>>,
    failing_directories: Arc<Mutex<HashSet<String>>>,
    failing_removes: Arc<Mutex<HashSet<String>>>,
    failing_removes_once: Arc<Mutex<HashSet<String>>>,
    cgroup_procs_override: Arc<Mutex<Option<String>>>,
    cgroup_procs_read_barriers: Arc<Mutex<Option<CgroupReadBarriers>>>,
    remove_barriers: Arc<Mutex<Option<RemoveBarriers>>>,
    events: Arc<Mutex<Vec<String>>>,
}

impl FakeFilesystem {
    fn production_tree() -> Self {
        let filesystem = Self::default();
        for directory in [
            "/sys/fs/cgroup/browserd",
            "/var/lib/browserd/shards",
            "/opt/chromium",
            "/opt/runtime",
            "/usr/share/fonts",
            "/usr/bin",
        ] {
            filesystem
                .directories
                .lock()
                .expect("directory lock should work")
                .insert(PathBuf::from(directory));
        }
        for file in [
            "/opt/chromium/chrome",
            "/usr/bin/bwrap",
            "/usr/libexec/browserd-launch-gate",
        ] {
            filesystem
                .files
                .lock()
                .expect("file lock should work")
                .insert(PathBuf::from(file), String::new());
        }
        filesystem
            .unwritable
            .lock()
            .expect("unwritable lock should work")
            .insert(PathBuf::from("/usr/libexec/browserd-launch-gate"));
        filesystem
            .files
            .lock()
            .expect("file lock should work")
            .insert(
                PathBuf::from("/sys/fs/cgroup/browserd/cgroup.controllers"),
                "cpu memory pids".into(),
            );
        filesystem
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().expect("event lock should work").clone()
    }

    fn has_shard_residue(&self, shard_id: &ShardId) -> bool {
        let shard = shard_id.to_string();
        self.directories
            .lock()
            .expect("directory lock should work")
            .iter()
            .any(|path| path.ends_with(&shard))
    }
}

impl SandboxFilesystem for FakeFilesystem {
    fn is_directory(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(self
            .directories
            .lock()
            .expect("directory lock should work")
            .contains(path))
    }

    fn is_file(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(self
            .files
            .lock()
            .expect("file lock should work")
            .contains_key(path))
    }

    fn is_writable(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(!self
            .unwritable
            .lock()
            .expect("unwritable lock should work")
            .contains(path))
    }

    fn contains_symlink(&self, path: &Path) -> Result<bool, SandboxError> {
        Ok(self
            .symlinks
            .lock()
            .expect("symlink lock should work")
            .iter()
            .any(|symlink| path.starts_with(symlink)))
    }

    fn create_directory(&self, path: &Path) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push(format!("mkdir:{}", path.display()));
        if self
            .failing_directories
            .lock()
            .expect("failing directory lock should work")
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return Err(SandboxError::Backend("injected directory failure".into()));
        }
        self.directories
            .lock()
            .expect("directory lock should work")
            .insert(path.to_path_buf());
        if path.parent() == Some(Path::new("/sys/fs/cgroup/browserd")) {
            self.files
                .lock()
                .expect("file lock should work")
                .insert(path.join("cgroup.procs"), "4242\n".into());
        }
        Ok(())
    }

    fn write_file(&self, path: &Path, value: &str) -> Result<(), SandboxError> {
        if self
            .failing_writes
            .lock()
            .expect("failing write lock should work")
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return Err(SandboxError::Backend("injected write failure".into()));
        }
        self.events
            .lock()
            .expect("event lock should work")
            .push(format!("write:{}={value}", path.display()));
        self.files
            .lock()
            .expect("file lock should work")
            .insert(path.to_path_buf(), value.into());
        Ok(())
    }

    fn read_file(&self, path: &Path) -> Result<String, SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push(format!("read:{}", path.display()));
        if path.ends_with("cgroup.procs") {
            let barriers = self
                .cgroup_procs_read_barriers
                .lock()
                .expect("cgroup read barrier lock should work")
                .clone();
            if let Some(barriers) = barriers {
                barriers.entered.wait();
                barriers.proceed.wait();
            }
            if let Some(value) = self
                .cgroup_procs_override
                .lock()
                .expect("cgroup override lock should work")
                .clone()
            {
                return Ok(value);
            }
        }
        self.files
            .lock()
            .expect("file lock should work")
            .get(path)
            .cloned()
            .ok_or_else(|| SandboxError::Backend(format!("missing {}", path.display())))
    }

    fn remove_directory(&self, path: &Path) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push(format!("remove:{}", path.display()));
        let barriers = self
            .remove_barriers
            .lock()
            .expect("remove barrier lock should work")
            .clone();
        if let Some(barriers) = barriers
            && path.ends_with(&barriers.suffix)
        {
            barriers.entered.wait();
            barriers.proceed.wait();
        }
        if self
            .failing_removes
            .lock()
            .expect("failing remove lock should work")
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return Err(SandboxError::Backend("injected remove failure".into()));
        }
        let one_shot_failure = self
            .failing_removes_once
            .lock()
            .expect("one-shot remove failure lock should work")
            .iter()
            .find(|suffix| path.ends_with(suffix.as_str()))
            .cloned();
        if let Some(suffix) = one_shot_failure {
            self.failing_removes_once
                .lock()
                .expect("one-shot remove failure lock should work")
                .remove(&suffix);
            return Err(SandboxError::Backend(
                "injected one-shot remove failure".into(),
            ));
        }
        self.directories
            .lock()
            .expect("directory lock should work")
            .retain(|directory| !directory.starts_with(path));
        self.files
            .lock()
            .expect("file lock should work")
            .retain(|file, _| !file.starts_with(path));
        Ok(())
    }
}

#[derive(Clone)]
struct FakeProcess {
    events: Arc<Mutex<Vec<String>>>,
    alive: Arc<Mutex<bool>>,
    identity_matches: bool,
}

#[async_trait]
impl LinuxProcessBackend for FakeProcess {
    async fn spawn_prepared(
        &self,
        _backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push(format!("spawn:{}", request.program().display()));
        self.events
            .lock()
            .expect("process event lock should work")
            .push(format!("argv:{:?}", request.arguments()));
        self.events
            .lock()
            .expect("process event lock should work")
            .push(format!("fds:{:?}", request.inherited_fds()));
        *self.alive.lock().expect("alive lock should work") = true;
        Ok(ChildIdentity::new(4242, 991))
    }

    async fn release_prepared(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("gate:release".into());
        Ok(())
    }

    async fn abort_spawned(
        &self,
        _backend_token: &str,
        _identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("signal:Kill".into());
        *self.alive.lock().expect("alive lock should work") = false;
        Ok(())
    }

    async fn release_spawned(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("release".into());
        Ok(())
    }

    async fn identity_matches(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("identity".into());
        Ok(self.identity_matches)
    }

    async fn signal(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push(format!("signal:{signal:?}"));
        if signal == ProcessSignal::Kill {
            *self.alive.lock().expect("alive lock should work") = false;
        }
        Ok(())
    }

    async fn is_alive(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        Ok(*self.alive.lock().expect("alive lock should work"))
    }

    async fn wait(&self, _duration: Duration) {}
}

#[derive(Clone)]
struct BlockingReleaseProcess {
    inner: FakeProcess,
    release_calls: Arc<AtomicUsize>,
    entered: Arc<Barrier>,
    proceed: Arc<Barrier>,
}

#[derive(Clone)]
struct BlockingTerminateProcess {
    inner: FakeProcess,
    pause: AsyncPause,
}

#[derive(Clone)]
struct CancelOnceDuringReleaseProcess {
    inner: FakeProcess,
    release_calls: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    proceed: Arc<tokio::sync::Notify>,
}

#[derive(Clone)]
struct AsyncPause {
    calls: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    proceed: Arc<tokio::sync::Notify>,
}

impl AsyncPause {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(tokio::sync::Notify::new()),
            proceed: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn pause_once(&self) {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.notify_one();
            self.proceed.notified().await;
        }
    }
}

#[derive(Clone)]
struct CancelOnceDuringSpawnProcess {
    inner: FakeProcess,
    pause: AsyncPause,
}

#[async_trait]
impl LinuxProcessBackend for CancelOnceDuringSpawnProcess {
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        let identity = self.inner.spawn_prepared(backend_token, request).await?;
        self.pause.pause_once().await;
        Ok(identity)
    }

    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_prepared(backend_token, identity).await
    }

    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.inner.abort_spawned(backend_token, identity).await
    }

    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_spawned(backend_token, identity).await
    }

    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.identity_matches(backend_token, identity).await
    }

    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.inner.signal(backend_token, identity, signal).await
    }

    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.is_alive(backend_token, identity).await
    }

    async fn wait(&self, duration: Duration) {
        self.inner.wait(duration).await;
    }
}

#[async_trait]
impl LinuxProcessBackend for CancelOnceDuringReleaseProcess {
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        if self.release_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.notify_one();
            self.proceed.notified().await;
        }
        self.inner.release_prepared(backend_token, identity).await
    }

    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.inner.abort_spawned(backend_token, identity).await
    }

    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_spawned(backend_token, identity).await
    }

    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.identity_matches(backend_token, identity).await
    }

    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.inner.signal(backend_token, identity, signal).await
    }

    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.is_alive(backend_token, identity).await
    }

    async fn wait(&self, duration: Duration) {
        self.inner.wait(duration).await;
    }
}

#[async_trait]
impl LinuxProcessBackend for BlockingReleaseProcess {
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        if self.release_calls.fetch_add(1, Ordering::SeqCst) == 1 {
            self.entered.wait();
            self.proceed.wait();
        }
        self.inner.release_prepared(backend_token, identity).await
    }

    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.inner.abort_spawned(backend_token, identity).await
    }

    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_spawned(backend_token, identity).await
    }

    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.identity_matches(backend_token, identity).await
    }

    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.inner.signal(backend_token, identity, signal).await
    }

    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.is_alive(backend_token, identity).await
    }

    async fn wait(&self, duration: Duration) {
        self.inner.wait(duration).await;
    }
}

#[async_trait]
impl LinuxProcessBackend for BlockingTerminateProcess {
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_prepared(backend_token, identity).await
    }

    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.inner.abort_spawned(backend_token, identity).await
    }

    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_spawned(backend_token, identity).await
    }

    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.identity_matches(backend_token, identity).await
    }

    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.inner.signal(backend_token, identity, signal).await?;
        if signal == ProcessSignal::Terminate {
            self.pause.pause_once().await;
        }
        Ok(())
    }

    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.is_alive(backend_token, identity).await
    }

    async fn wait(&self, duration: Duration) {
        self.inner.wait(duration).await;
    }
}

#[derive(Clone, Copy)]
enum SpawnFault {
    Spawn,
    InvalidIdentity,
    MismatchedIdentity,
    GateRelease,
}

#[derive(Clone)]
struct FaultProcess {
    fault: SpawnFault,
    events: Arc<Mutex<Vec<String>>>,
    alive: Arc<Mutex<bool>>,
}

#[async_trait]
impl LinuxProcessBackend for FaultProcess {
    async fn spawn_prepared(
        &self,
        _backend_token: &str,
        _request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("spawn".into());
        if matches!(self.fault, SpawnFault::Spawn) {
            return Err(SandboxError::Backend("injected spawn failure".into()));
        }
        *self.alive.lock().expect("alive lock should work") = true;
        Ok(match self.fault {
            SpawnFault::InvalidIdentity => ChildIdentity::new(4242, 0),
            SpawnFault::MismatchedIdentity => ChildIdentity::new(4242, 991),
            SpawnFault::GateRelease => ChildIdentity::new(4242, 991),
            SpawnFault::Spawn => unreachable!("spawn fault returned above"),
        })
    }

    async fn release_prepared(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("gate:release".into());
        if matches!(self.fault, SpawnFault::GateRelease) {
            return Err(SandboxError::Backend(
                "injected gate release failure".into(),
            ));
        }
        Ok(())
    }

    async fn abort_spawned(
        &self,
        _backend_token: &str,
        _identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("signal:Kill".into());
        *self.alive.lock().expect("alive lock should work") = false;
        Ok(())
    }

    async fn release_spawned(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn identity_matches(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        Ok(!matches!(self.fault, SpawnFault::MismatchedIdentity))
    }

    async fn signal(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push(format!("signal:{signal:?}"));
        if signal == ProcessSignal::Kill {
            *self.alive.lock().expect("alive lock should work") = false;
        }
        Ok(())
    }

    async fn is_alive(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        Ok(*self.alive.lock().expect("alive lock should work"))
    }

    async fn wait(&self, _duration: Duration) {}
}

#[derive(Clone)]
struct RetryCleanupProcess {
    inner: FakeProcess,
    gate_release_failures: Arc<AtomicUsize>,
    abort_failures: Arc<AtomicUsize>,
}

#[async_trait]
impl LinuxProcessBackend for RetryCleanupProcess {
    async fn spawn_prepared(
        &self,
        backend_token: &str,
        request: &SpawnRequest,
    ) -> Result<ChildIdentity, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn release_prepared(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        if self
            .gate_release_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            self.inner
                .events
                .lock()
                .expect("event lock should work")
                .push("gate:release".into());
            return Err(SandboxError::Backend(
                "injected gate release failure".into(),
            ));
        }
        self.inner.release_prepared(backend_token, identity).await
    }

    async fn abort_spawned(
        &self,
        backend_token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        if self
            .abort_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            self.inner
                .events
                .lock()
                .expect("event lock should work")
                .push("signal:Kill".into());
            return Err(SandboxError::Backend("injected abort failure".into()));
        }
        self.inner.abort_spawned(backend_token, identity).await
    }

    async fn release_spawned(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_spawned(backend_token, identity).await
    }

    async fn identity_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.identity_matches(backend_token, identity).await
    }

    async fn signal(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.inner.signal(backend_token, identity, signal).await
    }

    async fn is_alive(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.is_alive(backend_token, identity).await
    }

    async fn wait(&self, duration: Duration) {
        self.inner.wait(duration).await;
    }
}

#[derive(Clone, Default)]
struct FakeEgress {
    events: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<EgressCall>>>,
    active: Arc<Mutex<HashSet<ShardEgressFence>>>,
    fail_prepare: bool,
    fail_revoke: bool,
    fail_revoke_once: Arc<AtomicUsize>,
    fail_release_once: Arc<AtomicUsize>,
    prepare_pause: Option<AsyncPause>,
    revoke_pause: Option<AsyncPause>,
    release_pause: Option<AsyncPause>,
    force_inactive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EgressCall {
    Prepare(ShardEgressFence),
    Revoke(ShardEgressFence),
    Release(ShardEgressFence),
    IsActive(ShardEgressFence),
}

#[async_trait]
impl EgressRouteBackend for FakeEgress {
    async fn prepare(&self, fence: &ShardEgressFence) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:prepare".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Prepare(fence.clone()));
        if self.fail_prepare {
            self.active
                .lock()
                .expect("active lock should work")
                .insert(fence.clone());
            return Err(SandboxError::Backend("route unavailable".into()));
        }
        self.active
            .lock()
            .expect("active lock should work")
            .insert(fence.clone());
        if let Some(pause) = &self.prepare_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn revoke(&self, fence: &ShardEgressFence) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:revoke".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Revoke(fence.clone()));
        if let Some(pause) = &self.revoke_pause {
            pause.pause_once().await;
        }
        if self.fail_revoke
            || self
                .fail_revoke_once
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            return Err(SandboxError::Backend("route revoke failed".into()));
        }
        self.active
            .lock()
            .expect("active lock should work")
            .remove(fence);
        Ok(())
    }

    async fn release(&self, fence: &ShardEgressFence) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:release".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Release(fence.clone()));
        if let Some(pause) = &self.release_pause {
            pause.pause_once().await;
        }
        if self
            .fail_release_once
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(SandboxError::Backend("route release failed".into()));
        }
        Ok(())
    }

    async fn is_active(&self, fence: &ShardEgressFence) -> Result<bool, SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:is-active".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::IsActive(fence.clone()));
        Ok(!self.force_inactive
            && self
                .active
                .lock()
                .expect("active lock should work")
                .contains(fence))
    }
}

fn config() -> LinuxSandboxConfig {
    LinuxSandboxConfig::new(
        "/sys/fs/cgroup/browserd",
        "/var/lib/browserd/shards",
        "/usr/bin/bwrap",
        ChromiumRuntime::new("/opt/chromium/chrome", "/opt/browser/chrome"),
        LaunchGateRuntime::new(
            "/usr/libexec/browserd-launch-gate",
            "/opt/browser/browserd-launch-gate",
        ),
        [
            ReadOnlyMount::new("/opt/runtime", "/opt/runtime"),
            ReadOnlyMount::new("/usr/share/fonts", "/usr/share/fonts"),
        ],
        CgroupLimits::new(512 << 20, 384 << 20, 256, 100_000, 100_000)
            .expect("limits should be valid"),
        9,
        Duration::from_millis(100),
        Duration::from_millis(10),
    )
    .expect("configuration should be valid")
}

#[test]
fn planned_launch_wraps_chromium_with_a_read_only_trusted_gate() {
    let backend = backend(
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let request = backend.planned_spawn_request(&ShardId::new());
    let arguments = request.arguments();

    assert_eq!(
        arguments.first().and_then(|value| value.to_str()),
        Some("--die-with-parent")
    );
    assert!(arguments.windows(3).any(|window| {
        window
            == [
                "--ro-bind",
                "/usr/libexec/browserd-launch-gate",
                "/opt/browser/browserd-launch-gate",
            ]
    }));
    assert_eq!(
        arguments
            .iter()
            .rev()
            .take(6)
            .rev()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [
            "/opt/browser/browserd-launch-gate",
            "--",
            "/opt/browser/chrome",
            "--remote-debugging-pipe",
            "--user-data-dir=/profile",
            "--disable-features=BackForwardCache",
        ]
    );
    assert!(!arguments.iter().any(|argument| argument == "--block-fd"));
}

fn launch_spec(shard_id: ShardId) -> LaunchSpec {
    LaunchSpec::production(
        shard_id,
        WorkerId::new("worker-1").expect("worker should be valid"),
        7,
    )
}

fn backend(
    filesystem: FakeFilesystem,
    process: FakeProcess,
    egress: FakeEgress,
) -> LinuxSandboxBackend<FakeFilesystem, FakeProcess, FakeEgress> {
    LinuxSandboxBackend::new(config(), filesystem, process, egress)
}

fn assert_no_provisioning_residue(
    filesystem: &FakeFilesystem,
    egress: &FakeEgress,
    alive: &Arc<Mutex<bool>>,
    shard_id: &ShardId,
) {
    assert!(!filesystem.has_shard_residue(shard_id));
    assert!(
        !egress
            .active
            .lock()
            .expect("active route lock should work")
            .iter()
            .any(|fence| fence.shard_id() == shard_id)
    );
    assert!(!*alive.lock().expect("alive lock should work"));
}

fn run_process_helper(test_name: &str) {
    let output = Command::new(std::env::current_exe().expect("test executable should be known"))
        .arg("--ignored")
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env("BROWSERD_PROCESS_HELPER", "1")
        .output()
        .expect("process helper should start");
    assert!(
        output.status.success(),
        "process helper failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn install_required_launch_descriptors() -> File {
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("null device should open");
    for target in [3, 4, 9] {
        // SAFETY: the helper runs in an isolated subprocess and duplicates one live descriptor
        // only onto the three fixed launch descriptor numbers used by this test.
        let duplicated = unsafe { nix::libc::dup2(null.as_raw_fd(), target) };
        assert_eq!(
            duplicated, target,
            "required descriptor should be installed"
        );
        // SAFETY: `target` was just installed above and F_SETFD with zero only clears CLOEXEC.
        let result = unsafe { nix::libc::fcntl(target, nix::libc::F_SETFD, 0) };
        assert_eq!(result, 0, "required descriptor should be inheritable");
    }
    null
}

fn executable_script(contents: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("script tempdir should be created");
    let path = directory.path().join("fake-bwrap");
    std::fs::write(&path, contents).expect("fake bwrap should be written");
    let mut permissions = std::fs::metadata(&path)
        .expect("fake bwrap metadata should exist")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("fake bwrap should be executable");
    (directory, path)
}

fn process_request_for(bwrap: &Path) -> (tempfile::TempDir, SpawnRequest) {
    let cgroup_directory = tempfile::tempdir().expect("fake cgroup tempdir should be created");
    let cgroup_root = cgroup_directory.path().join("sys/fs/cgroup/browserd");
    std::fs::create_dir_all(&cgroup_root).expect("fake cgroup root should be created");
    let request = LinuxSandboxBackend::new(
        LinuxSandboxConfig::new(
            &cgroup_root,
            "/var/lib/browserd/shards",
            bwrap,
            ChromiumRuntime::new("/opt/chromium/chrome", "/opt/chromium/chrome"),
            LaunchGateRuntime::new(
                "/usr/libexec/browserd-launch-gate",
                "/opt/browser/browserd-launch-gate",
            ),
            [],
            CgroupLimits::new(512, 256, 4, 10, 100).expect("limits should be valid"),
            9,
            Duration::from_millis(10),
            Duration::from_millis(1),
        )
        .expect("config should be valid"),
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    )
    .planned_spawn_request(&ShardId::new());
    std::fs::create_dir_all(
        request
            .cgroup_procs_path()
            .parent()
            .expect("cgroup membership should have a parent"),
    )
    .expect("fake shard cgroup should be created");
    std::fs::write(request.cgroup_procs_path(), b"")
        .expect("fake cgroup membership file should be created");
    std::fs::write(
        request.cgroup_procs_path().with_file_name("cgroup.kill"),
        b"",
    )
    .expect("fake cgroup kill file should be created");
    std::fs::write(
        request.cgroup_procs_path().with_file_name("cgroup.events"),
        b"populated 1\n",
    )
    .expect("fake cgroup events file should be created");
    (cgroup_directory, request)
}

#[tokio::test]
async fn cgroup_and_bwrap_are_configured_before_shell_free_launch() {
    let filesystem = FakeFilesystem::production_tree();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let process = FakeProcess {
        events: process_events.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress::default();
    let backend = backend(filesystem.clone(), process, egress.clone());
    let shard_id = ShardId::new();
    let planned = backend.planned_spawn_request(&shard_id);
    assert_eq!(planned.program(), Path::new("/usr/bin/bwrap"));
    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("provision should succeed");

    let writes = filesystem.events().join("\n");
    for setting in [
        "memory.max=536870912",
        "memory.high=402653184",
        "pids.max=256",
        "cpu.max=100000 100000",
        "cpu.weight=100",
    ] {
        assert!(writes.contains(setting), "missing {setting}");
    }
    assert_eq!(
        planned.cgroup_procs_path(),
        PathBuf::from("/sys/fs/cgroup/browserd")
            .join(shard_id.to_string())
            .join("cgroup.procs")
    );
    assert_eq!(
        egress
            .events
            .lock()
            .expect("egress lock should work")
            .as_slice(),
        ["route:prepare", "route:is-active"]
    );
    assert!(
        process_events.lock().expect("process lock should work")[0]
            .starts_with("spawn:/usr/bin/bwrap")
    );
    let process_events = process_events
        .lock()
        .expect("process lock should work")
        .join("\n");
    for argument in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--tmpfs",
        "/tmp",
        "/dev/shm",
        "--ro-bind",
        "--seccomp",
        "--preserve-fds",
    ] {
        assert!(process_events.contains(argument), "missing {argument}");
    }
    assert!(!process_events.contains("--no-sandbox"));
    assert!(!process_events.contains("/home"));
    assert!(process_events.contains("fds:[3, 4, 9]"));
}

#[tokio::test]
async fn prepared_child_is_released_only_after_validated_cgroup_attachment() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let process = FakeProcess {
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let shard_id = ShardId::new();

    backend(filesystem, process, egress)
        .provision(&launch_spec(shard_id))
        .await
        .expect("validated attachment should release the prepared child");

    let events = trace.lock().expect("trace lock should work");
    let spawn = events
        .iter()
        .position(|event| event.starts_with("spawn:"))
        .expect("prepared spawn should be recorded");
    let validate = events
        .iter()
        .position(|event| event.ends_with("cgroup.procs"))
        .expect("cgroup membership should be read back");
    let release = events
        .iter()
        .position(|event| event == "gate:release")
        .expect("prepared child should be released");
    let exact_route_check = events
        .iter()
        .position(|event| event == "route:is-active")
        .expect("the exact route fence should be checked");
    assert!(spawn < validate);
    assert!(validate < exact_route_check);
    assert_eq!(
        exact_route_check + 1,
        release,
        "no awaitable operation may separate the exact fence check from gate release"
    );
    assert_eq!(
        events.iter().filter(|event| *event == "identity").count(),
        2,
        "PID/start-time identity must be checked before and after attachment"
    );
}

#[tokio::test]
async fn provisioning_never_targets_a_reusable_numeric_pid_through_cgroup_procs() {
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };

    backend(filesystem.clone(), process, FakeEgress::default())
        .provision(&launch_spec(ShardId::new()))
        .await
        .expect("the prepared bootstrap should already inherit its target cgroup");

    assert!(
        !filesystem
            .events()
            .iter()
            .any(|event| event.contains("cgroup.procs=")),
        "a userspace PID recheck followed by a numeric cgroup.procs write can attach a reused PID"
    );
}

#[tokio::test]
async fn inactive_exact_egress_fence_prevents_gate_release_after_attachment() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let alive = Arc::new(Mutex::new(false));
    let process = FakeProcess {
        events: trace.clone(),
        alive: alive.clone(),
        identity_matches: true,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        force_inactive: true,
        ..FakeEgress::default()
    };
    let shard_id = ShardId::new();
    let expected_fence = ShardEgressFence::new(shard_id.clone(), 7);

    backend(filesystem.clone(), process, egress.clone())
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("an inactive exact egress fence must keep the browser gated");

    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let events = trace.lock().expect("trace lock should work");
    let membership = events
        .iter()
        .position(|event| event.ends_with("cgroup.procs"))
        .expect("cgroup membership must be validated first");
    let route_check = events
        .iter()
        .position(|event| event == "route:is-active")
        .expect("the exact route fence must be revalidated");
    let revoke = events
        .iter()
        .position(|event| event == "route:revoke")
        .expect("rollback must revoke the route");
    let kill = events
        .iter()
        .position(|event| event == "signal:Kill")
        .expect("rollback must abort the prepared child");
    assert!(membership < route_check);
    assert!(route_check < revoke);
    assert!(revoke < kill);
    assert!(!events.iter().any(|event| event == "gate:release"));
    assert!(
        egress
            .calls
            .lock()
            .expect("egress call lock should work")
            .contains(&EgressCall::IsActive(expected_fence))
    );
}

#[tokio::test]
async fn duplicate_shard_provision_fails_before_spawn_and_preserves_the_runtime() {
    let filesystem = FakeFilesystem::production_tree();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let process = FakeProcess {
        events: process_events.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let backend = backend(filesystem.clone(), process, FakeEgress::default());
    let shard_id = ShardId::new();
    let first_handle = backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("first provision should succeed");
    let events_before_duplicate = process_events
        .lock()
        .expect("process event lock should work")
        .len();

    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("duplicate shard provision must fail closed");

    assert_eq!(
        process_events
            .lock()
            .expect("process event lock should work")
            .len(),
        events_before_duplicate,
        "a duplicate must fail before prepared spawn or gate release"
    );
    let cgroup_path = PathBuf::from("/sys/fs/cgroup/browserd").join(shard_id.to_string());
    {
        let mut files = filesystem.files.lock().expect("file lock should work");
        files.insert(cgroup_path.join("memory.current"), "1024\n".into());
        files.insert(cgroup_path.join("memory.peak"), "2048\n".into());
    }
    assert_eq!(
        backend
            .inspect(&first_handle)
            .await
            .expect("the original runtime handle must remain valid")
            .memory_current_bytes,
        1024
    );
}

#[tokio::test]
async fn mismatched_cgroup_membership_never_releases_and_rolls_back_fail_closed() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    *filesystem
        .cgroup_procs_override
        .lock()
        .expect("cgroup override lock should work") = Some("9999\n".into());
    let alive = Arc::new(Mutex::new(false));
    let process = FakeProcess {
        events: trace.clone(),
        alive: alive.clone(),
        identity_matches: true,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let shard_id = ShardId::new();

    backend(filesystem.clone(), process, egress.clone())
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("unverified cgroup membership must fail closed");

    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let events = trace.lock().expect("trace lock should work");
    assert!(!events.iter().any(|event| event == "gate:release"));
    let revoke = events
        .iter()
        .position(|event| event == "route:revoke")
        .expect("egress should be revoked");
    let kill = events
        .iter()
        .position(|event| event == "signal:Kill")
        .expect("owned prepared child should be killed");
    assert!(revoke < kill);
}

#[tokio::test]
async fn gate_release_failure_revokes_then_aborts_the_still_prepared_child() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let alive = Arc::new(Mutex::new(false));
    let process = FaultProcess {
        fault: SpawnFault::GateRelease,
        events: trace.clone(),
        alive: alive.clone(),
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let shard_id = ShardId::new();

    LinuxSandboxBackend::new(config(), filesystem.clone(), process, egress.clone())
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("gate release failure must roll provisioning back");

    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let events = trace.lock().expect("trace lock should work");
    let release = events
        .iter()
        .position(|event| event == "gate:release")
        .expect("gate release should be attempted");
    let revoke = events
        .iter()
        .position(|event| event == "route:revoke")
        .expect("egress should be revoked");
    let kill = events
        .iter()
        .position(|event| event == "signal:Kill")
        .expect("prepared child should be aborted");
    assert!(release < revoke);
    assert!(revoke < kill);
}

#[tokio::test]
async fn failed_route_revoke_still_aborts_the_child_and_retries_only_the_route_stage() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let alive = Arc::new(Mutex::new(false));
    let process = FaultProcess {
        fault: SpawnFault::GateRelease,
        events: trace.clone(),
        alive,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        fail_revoke_once: Arc::new(AtomicUsize::new(1)),
        ..FakeEgress::default()
    };
    let backend = LinuxSandboxBackend::new(config(), filesystem, process, egress.clone());
    let shard_id = ShardId::new();

    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("gate failure with failed revoke must leave a cleanup tombstone");
    assert_eq!(
        trace
            .lock()
            .expect("trace lock should work")
            .iter()
            .filter(|event| *event == "signal:Kill")
            .count(),
        1,
        "a failed route revoke must never keep the prepared child alive"
    );
    assert!(
        egress
            .active
            .lock()
            .expect("active route lock should work")
            .contains(&ShardEgressFence::new(shard_id.clone(), 7)),
        "a failed revoke must preserve an active-route cleanup tombstone"
    );

    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect_err("the next call must retry cleanup, not start another child");
    let events = trace.lock().expect("trace lock should work");
    assert_eq!(
        events.iter().filter(|event| *event == "spawn").count(),
        1,
        "duplicate provision must remain blocked behind rollback ownership"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "route:revoke")
            .count(),
        2,
        "the failed revoke stage should be retried"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "signal:Kill")
            .count(),
        1,
        "the already completed child abort stage must not be retried"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hung_route_revoke_cannot_delay_prepared_child_abort() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let process = FaultProcess {
        fault: SpawnFault::GateRelease,
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
    };
    let revoke_pause = AsyncPause::new();
    let egress = FakeEgress {
        events: trace.clone(),
        revoke_pause: Some(revoke_pause.clone()),
        ..FakeEgress::default()
    };
    let backend = Arc::new(LinuxSandboxBackend::new(
        config(),
        filesystem,
        process,
        egress,
    ));
    let provision = tokio::spawn({
        let backend = backend.clone();
        async move { backend.provision(&launch_spec(ShardId::new())).await }
    });

    revoke_pause.entered.notified().await;
    tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if trace
                .lock()
                .expect("trace lock should work")
                .iter()
                .any(|event| event == "signal:Kill")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("prepared child abort must proceed while route revoke is stalled");
    revoke_pause.proceed.notify_one();
    provision
        .await
        .expect("provision task should join")
        .expect_err("the injected gate release still fails provisioning");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_hung_runtime_route_revoke_cannot_delay_bounded_child_termination() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let revoke_pause = AsyncPause::new();
    let egress = FakeEgress {
        events: trace.clone(),
        revoke_pause: Some(revoke_pause.clone()),
        ..FakeEgress::default()
    };
    let backend = Arc::new(backend(
        filesystem.clone(),
        FakeProcess {
            events: trace.clone(),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        egress,
    ));
    let shard_id = ShardId::new();
    let handle = backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("runtime should provision");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(shard_id.to_string())
                .join("cgroup.events"),
            "populated 0\n".into(),
        );
    let revoke = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move {
            backend
                .revoke_egress(&handle, CleanupReason::Administrative)
                .await
        }
    });
    revoke_pause.entered.notified().await;
    let kill = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move {
            backend
                .kill_cgroup(&handle, CleanupReason::Administrative)
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let kill_completed_while_revoke_was_blocked = kill.is_finished();
    revoke_pause.proceed.notify_one();
    revoke
        .await
        .expect("revoke task should join")
        .expect("revoke should complete after its barrier opens");
    kill.await
        .expect("kill task should join")
        .expect("kill should complete");
    assert!(
        kill_completed_while_revoke_was_blocked,
        "network cleanup serialization must never put child termination behind a hung revoke"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn namespace_cleanup_cannot_release_process_ownership_during_termination() {
    let filesystem = FakeFilesystem::production_tree();
    let terminate_pause = AsyncPause::new();
    let process = BlockingTerminateProcess {
        inner: FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        pause: terminate_pause.clone(),
    };
    let backend = Arc::new(LinuxSandboxBackend::new(
        config(),
        filesystem.clone(),
        process,
        FakeEgress::default(),
    ));
    let shard_id = ShardId::new();
    let handle = backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("runtime should provision");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(shard_id.to_string())
                .join("cgroup.events"),
            "populated 0\n".into(),
        );
    let kill = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move {
            backend
                .kill_cgroup(&handle, CleanupReason::Administrative)
                .await
        }
    });
    terminate_pause.entered.notified().await;
    let cleanup = tokio::spawn({
        let backend = backend.clone();
        async move { backend.cleanup_namespaces(&handle).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let cleanup_finished_before_termination = cleanup.is_finished();
    terminate_pause.proceed.notify_one();
    let kill_result = kill.await.expect("kill task should join");
    let cleanup_result = cleanup.await.expect("cleanup task should join");

    assert!(
        !cleanup_finished_before_termination,
        "namespace cleanup must not release the pidfd/process handle while termination is active"
    );
    kill_result.expect("termination should complete before cleanup");
    cleanup_result.expect("cleanup should complete after termination");
}

#[tokio::test]
async fn one_shot_rollback_failures_resume_at_only_the_first_unfinished_stage() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let shard_id = ShardId::new();
    {
        let mut failures = filesystem
            .failing_removes_once
            .lock()
            .expect("one-shot failure lock should work");
        failures.insert(format!("shards/{shard_id}"));
        failures.insert(format!("browserd/{shard_id}"));
    }
    let alive = Arc::new(Mutex::new(false));
    let process = RetryCleanupProcess {
        inner: FakeProcess {
            events: trace.clone(),
            alive: alive.clone(),
            identity_matches: true,
        },
        gate_release_failures: Arc::new(AtomicUsize::new(1)),
        abort_failures: Arc::new(AtomicUsize::new(1)),
    };
    let egress = FakeEgress {
        events: trace.clone(),
        fail_revoke_once: Arc::new(AtomicUsize::new(1)),
        fail_release_once: Arc::new(AtomicUsize::new(1)),
        ..FakeEgress::default()
    };
    let backend = LinuxSandboxBackend::new(config(), filesystem, process, egress);

    for expected_stage in [
        "initial revoke and abort",
        "resource removals",
        "route release",
        "cleanup completion",
    ] {
        let result = backend.provision(&launch_spec(shard_id.clone())).await;
        assert!(
            result.is_err(),
            "{expected_stage} retry must not spawn a replacement"
        );
    }
    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect("replacement spawn is allowed only after every rollback stage completed");

    let events = trace.lock().expect("trace lock should work");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("spawn:"))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "route:revoke")
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "signal:Kill")
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("remove:/var/lib/browserd/shards/"))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("remove:/sys/fs/cgroup/browserd/"))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "route:release")
            .count(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_provision_cannot_release_while_membership_validation_is_blocked() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let entered = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    *filesystem
        .cgroup_procs_read_barriers
        .lock()
        .expect("cgroup read barrier lock should work") = Some(CgroupReadBarriers {
        entered: entered.clone(),
        proceed: proceed.clone(),
    });
    let process = FakeProcess {
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let backend = Arc::new(backend(filesystem, process, FakeEgress::default()));
    let shard_id = ShardId::new();
    let provision = tokio::spawn({
        let backend = backend.clone();
        let shard_id = shard_id.clone();
        async move { backend.provision(&launch_spec(shard_id)).await }
    });

    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .expect("read barrier observer should run");
    assert!(
        !trace
            .lock()
            .expect("trace lock should work")
            .iter()
            .any(|event| event == "gate:release"),
        "the browser gate must remain closed during cgroup validation"
    );
    let events_before_duplicate = trace.lock().expect("trace lock should work").len();
    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect_err("an active provisioning owner must reject a concurrent duplicate");
    assert_eq!(
        trace.lock().expect("trace lock should work").len(),
        events_before_duplicate,
        "the duplicate must not clean or overwrite the active provisioning tombstone"
    );
    tokio::task::spawn_blocking(move || proceed.wait())
        .await
        .expect("read barrier release should run");
    provision
        .await
        .expect("provision task should join")
        .expect("provision should finish after membership validation");
    assert!(
        trace
            .lock()
            .expect("trace lock should work")
            .iter()
            .any(|event| event == "gate:release")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn blocked_gate_release_does_not_hold_the_global_runtime_mutex() {
    let filesystem = FakeFilesystem::production_tree();
    let entered = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    let process = BlockingReleaseProcess {
        inner: FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        release_calls: Arc::new(AtomicUsize::new(0)),
        entered: entered.clone(),
        proceed: proceed.clone(),
    };
    let backend = Arc::new(LinuxSandboxBackend::new(
        config(),
        filesystem.clone(),
        process,
        FakeEgress::default(),
    ));
    let inspect_shard = ShardId::new();
    let inspect_handle = backend
        .provision(&launch_spec(inspect_shard.clone()))
        .await
        .expect("first runtime should provision");
    let inspect_cgroup = PathBuf::from("/sys/fs/cgroup/browserd").join(inspect_shard.to_string());
    {
        let mut files = filesystem.files.lock().expect("file lock should work");
        files.insert(inspect_cgroup.join("memory.current"), "4096\n".into());
        files.insert(inspect_cgroup.join("memory.peak"), "8192\n".into());
    }
    let provision = tokio::spawn({
        let backend = backend.clone();
        async move { backend.provision(&launch_spec(ShardId::new())).await }
    });
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .expect("release barrier observer should run");

    let inspection =
        tokio::time::timeout(Duration::from_millis(200), backend.inspect(&inspect_handle))
            .await
            .expect("inspect must not wait for another process gate")
            .expect("first runtime inspection should succeed");
    assert_eq!(inspection.memory_current_bytes, 4096);

    tokio::task::spawn_blocking(move || proceed.wait())
        .await
        .expect("release barrier should open");
    provision
        .await
        .expect("second provision task should join")
        .expect("second provision should finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn blocking_cleanup_filesystem_work_does_not_block_an_unrelated_runtime_inspection() {
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let backend = Arc::new(backend(filesystem.clone(), process, FakeEgress::default()));
    let cleanup_shard = ShardId::new();
    let inspect_shard = ShardId::new();
    let cleanup_handle = backend
        .provision(&launch_spec(cleanup_shard.clone()))
        .await
        .expect("cleanup runtime should provision");
    let inspect_handle = backend
        .provision(&launch_spec(inspect_shard.clone()))
        .await
        .expect("inspection runtime should provision");
    let cleanup_cgroup = PathBuf::from("/sys/fs/cgroup/browserd").join(cleanup_shard.to_string());
    let inspect_cgroup = PathBuf::from("/sys/fs/cgroup/browserd").join(inspect_shard.to_string());
    {
        let mut files = filesystem.files.lock().expect("file lock should work");
        files.insert(cleanup_cgroup.join("cgroup.events"), "populated 0\n".into());
        files.insert(inspect_cgroup.join("memory.current"), "12288\n".into());
        files.insert(inspect_cgroup.join("memory.peak"), "16384\n".into());
    }
    backend
        .kill_cgroup(&cleanup_handle, CleanupReason::Administrative)
        .await
        .expect("cleanup runtime should terminate");
    let entered = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    *filesystem
        .remove_barriers
        .lock()
        .expect("remove barrier lock should work") = Some(RemoveBarriers {
        suffix: PathBuf::from(format!("shards/{cleanup_shard}")),
        entered: entered.clone(),
        proceed: proceed.clone(),
    });
    let cleanup = tokio::spawn({
        let backend = backend.clone();
        async move { backend.cleanup_namespaces(&cleanup_handle).await }
    });
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .expect("cleanup barrier observer should run");

    let inspection = tokio::spawn({
        let backend = backend.clone();
        async move { backend.inspect(&inspect_handle).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let inspection_completed_while_cleanup_was_blocked = inspection.is_finished();
    tokio::task::spawn_blocking(move || proceed.wait())
        .await
        .expect("cleanup barrier should open");
    cleanup
        .await
        .expect("cleanup task should join")
        .expect("cleanup should complete");
    let inspection = inspection
        .await
        .expect("inspection task should join")
        .expect("unrelated runtime should remain inspectable");
    assert!(
        inspection_completed_while_cleanup_was_blocked,
        "unrelated inspection must not wait on blocking filesystem cleanup"
    );
    assert_eq!(inspection.memory_current_bytes, 12288);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn concurrent_egress_revocations_release_the_route_exactly_once() {
    let filesystem = FakeFilesystem::production_tree();
    let revoke_pause = AsyncPause::new();
    let release_pause = AsyncPause::new();
    let egress = FakeEgress {
        revoke_pause: Some(revoke_pause.clone()),
        release_pause: Some(release_pause.clone()),
        ..FakeEgress::default()
    };
    let backend = Arc::new(backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        egress.clone(),
    ));
    let shard_id = ShardId::new();
    let handle = backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("runtime should provision");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(shard_id.to_string())
                .join("cgroup.events"),
            "populated 0\n".into(),
        );
    backend
        .kill_cgroup(&handle, CleanupReason::Administrative)
        .await
        .expect("runtime should terminate");
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("namespaces should clean before the route revoke race");

    let first = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move {
            backend
                .revoke_egress(&handle, CleanupReason::Administrative)
                .await
        }
    });
    revoke_pause.entered.notified().await;
    let second = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move {
            backend
                .revoke_egress(&handle, CleanupReason::Administrative)
                .await
        }
    });
    tokio::task::yield_now().await;
    revoke_pause.proceed.notify_one();
    release_pause.entered.notified().await;
    tokio::task::yield_now().await;
    release_pause.proceed.notify_one();
    let _first_result = first.await.expect("first revoke task should join");
    let _second_result = second.await.expect("second revoke task should join");

    assert_eq!(
        egress
            .calls
            .lock()
            .expect("egress call lock should work")
            .iter()
            .filter(|call| matches!(call, EgressCall::Release(_)))
            .count(),
        1,
        "concurrent cleanup/revoke entry points must share one per-shard release owner"
    );
}

#[tokio::test]
async fn cancelled_provision_after_registration_keeps_retryable_cleanup_ownership() {
    let filesystem = FakeFilesystem::production_tree();
    let events = Arc::new(Mutex::new(Vec::new()));
    let alive = Arc::new(Mutex::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let process = CancelOnceDuringReleaseProcess {
        inner: FakeProcess {
            events: events.clone(),
            alive: alive.clone(),
            identity_matches: true,
        },
        release_calls: Arc::new(AtomicUsize::new(0)),
        entered: entered.clone(),
        proceed: Arc::new(tokio::sync::Notify::new()),
    };
    let backend = Arc::new(LinuxSandboxBackend::new(
        config(),
        filesystem.clone(),
        process,
        FakeEgress::default(),
    ));
    let shard_id = ShardId::new();
    let provision = tokio::spawn({
        let backend = backend.clone();
        let shard_id = shard_id.clone();
        async move { backend.provision(&launch_spec(shard_id)).await }
    });

    entered.notified().await;
    provision.abort();
    assert!(
        provision
            .await
            .expect_err("provision should be cancelled")
            .is_cancelled()
    );
    filesystem
        .unwritable
        .lock()
        .expect("unwritable lock should work")
        .insert(PathBuf::from("/sys/fs/cgroup/browserd"));

    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("the first retry must finish abandoned cleanup without spawning");
    assert!(
        events
            .lock()
            .expect("event lock should work")
            .iter()
            .any(|event| event == "signal:Kill"),
        "the abandoned prepared child must remain owned and retryably aborted"
    );
    assert!(!filesystem.has_shard_residue(&shard_id));
    filesystem
        .unwritable
        .lock()
        .expect("unwritable lock should work")
        .remove(Path::new("/sys/fs/cgroup/browserd"));

    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect("a later retry may spawn only after cleanup completed");
}

#[tokio::test]
async fn cancelled_provision_before_spawn_retains_route_and_resource_cleanup_ownership() {
    let filesystem = FakeFilesystem::production_tree();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let alive = Arc::new(Mutex::new(false));
    let pause = AsyncPause::new();
    let egress = FakeEgress {
        prepare_pause: Some(pause.clone()),
        ..FakeEgress::default()
    };
    let backend = Arc::new(backend(
        filesystem.clone(),
        FakeProcess {
            events: process_events.clone(),
            alive: alive.clone(),
            identity_matches: true,
        },
        egress.clone(),
    ));
    let shard_id = ShardId::new();
    let provision = tokio::spawn({
        let backend = backend.clone();
        let shard_id = shard_id.clone();
        async move { backend.provision(&launch_spec(shard_id)).await }
    });

    pause.entered.notified().await;
    assert!(
        process_events
            .lock()
            .expect("event lock should work")
            .is_empty()
    );
    provision.abort();
    assert!(
        provision
            .await
            .expect_err("provision should be cancelled")
            .is_cancelled()
    );

    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("the first retry must finish abandoned cleanup");
    assert!(
        process_events
            .lock()
            .expect("event lock should work")
            .is_empty()
    );
    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);

    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect("a later retry may spawn after pre-spawn cleanup completed");
}

#[tokio::test]
async fn cancelled_provision_after_spawn_retains_the_unknown_child_token_for_abort() {
    let filesystem = FakeFilesystem::production_tree();
    let events = Arc::new(Mutex::new(Vec::new()));
    let alive = Arc::new(Mutex::new(false));
    let pause = AsyncPause::new();
    let process = CancelOnceDuringSpawnProcess {
        inner: FakeProcess {
            events: events.clone(),
            alive: alive.clone(),
            identity_matches: true,
        },
        pause: pause.clone(),
    };
    let egress = FakeEgress::default();
    let backend = Arc::new(LinuxSandboxBackend::new(
        config(),
        filesystem.clone(),
        process,
        egress.clone(),
    ));
    let shard_id = ShardId::new();
    let provision = tokio::spawn({
        let backend = backend.clone();
        let shard_id = shard_id.clone();
        async move { backend.provision(&launch_spec(shard_id)).await }
    });

    pause.entered.notified().await;
    assert_eq!(
        events
            .lock()
            .expect("event lock should work")
            .iter()
            .filter(|event| event.starts_with("spawn:"))
            .count(),
        1
    );
    provision.abort();
    assert!(
        provision
            .await
            .expect_err("provision should be cancelled")
            .is_cancelled()
    );

    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("the first retry must abort by durable spawn token");
    {
        let recorded = events.lock().expect("event lock should work");
        assert_eq!(
            recorded
                .iter()
                .filter(|event| event.starts_with("spawn:"))
                .count(),
            1,
            "cleanup retry must not start a replacement child"
        );
        assert!(recorded.iter().any(|event| event == "signal:Kill"));
    }
    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);

    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect("a later retry may spawn after unknown-child cleanup completed");
}

#[tokio::test]
async fn unavailable_or_unwritable_cgroup_v2_fails_closed() {
    let filesystem = FakeFilesystem::production_tree();
    filesystem
        .unwritable
        .lock()
        .expect("unwritable lock should work")
        .insert("/sys/fs/cgroup/browserd".into());
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let process = FakeProcess {
        events: process_events.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    assert!(
        backend(filesystem.clone(), process, FakeEgress::default())
            .provision(&launch_spec(ShardId::new()))
            .await
            .is_err()
    );
    assert!(filesystem.events().is_empty());
    assert!(
        process_events
            .lock()
            .expect("process lock should work")
            .is_empty()
    );

    let filesystem = FakeFilesystem::production_tree();
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            "/sys/fs/cgroup/browserd/cgroup.controllers".into(),
            "cpu pids".into(),
        );
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    assert!(
        backend(filesystem, process, FakeEgress::default())
            .provision(&launch_spec(ShardId::new()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn mandatory_route_failure_prevents_process_launch() {
    let filesystem = FakeFilesystem::production_tree();
    let filesystem_view = filesystem.clone();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let alive = Arc::new(Mutex::new(false));
    let process = FakeProcess {
        events: process_events.clone(),
        alive: alive.clone(),
        identity_matches: true,
    };
    let egress = FakeEgress {
        fail_prepare: true,
        ..FakeEgress::default()
    };
    let egress_view = egress.clone();
    let shard_id = ShardId::new();
    let backend = backend(filesystem, process, egress);
    assert!(
        backend
            .provision(&launch_spec(shard_id.clone()))
            .await
            .is_err()
    );
    assert!(
        process_events
            .lock()
            .expect("process lock should work")
            .is_empty()
    );
    assert_no_provisioning_residue(&filesystem_view, &egress_view, &alive, &shard_id);
}

#[tokio::test]
async fn cgroup_control_failure_removes_the_partial_cgroup() {
    for control in [
        "memory.max",
        "memory.high",
        "memory.swap.max",
        "memory.oom.group",
        "pids.max",
        "cpu.max",
        "cpu.weight",
    ] {
        let filesystem = FakeFilesystem::production_tree();
        filesystem
            .failing_writes
            .lock()
            .expect("failure lock should work")
            .insert(control.into());
        let alive = Arc::new(Mutex::new(false));
        let egress = FakeEgress::default();
        let shard_id = ShardId::new();
        assert!(
            backend(
                filesystem.clone(),
                FakeProcess {
                    events: Arc::new(Mutex::new(Vec::new())),
                    alive: alive.clone(),
                    identity_matches: true,
                },
                egress.clone(),
            )
            .provision(&launch_spec(shard_id.clone()))
            .await
            .is_err()
        );

        assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
        assert!(
            filesystem
                .events()
                .last()
                .is_some_and(|event| event.contains("remove:/sys/fs/cgroup/browserd/"))
        );
    }
}

#[tokio::test]
async fn runtime_creation_failure_removes_runtime_then_cgroup() {
    let filesystem = FakeFilesystem::production_tree();
    filesystem
        .failing_directories
        .lock()
        .expect("failure lock should work")
        .insert("profile".into());
    let alive = Arc::new(Mutex::new(false));
    let egress = FakeEgress::default();
    let shard_id = ShardId::new();
    assert!(
        backend(
            filesystem.clone(),
            FakeProcess {
                events: Arc::new(Mutex::new(Vec::new())),
                alive: alive.clone(),
                identity_matches: true,
            },
            egress.clone(),
        )
        .provision(&launch_spec(shard_id.clone()))
        .await
        .is_err()
    );

    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let removals = filesystem
        .events()
        .into_iter()
        .filter(|event| event.starts_with("remove:"))
        .collect::<Vec<_>>();
    assert_eq!(removals.len(), 2);
    assert!(removals[0].contains("/var/lib/browserd/shards/"));
    assert!(removals[1].contains("/sys/fs/cgroup/browserd/"));
}

#[tokio::test]
async fn spawn_failure_revokes_route_then_aborts_token_and_removes_resources() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let alive = Arc::new(Mutex::new(false));
    let process = FaultProcess {
        fault: SpawnFault::Spawn,
        events: trace.clone(),
        alive: alive.clone(),
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let shard_id = ShardId::new();
    assert!(
        LinuxSandboxBackend::new(config(), filesystem.clone(), process, egress.clone())
            .provision(&launch_spec(shard_id.clone()))
            .await
            .is_err()
    );

    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let events = trace.lock().expect("trace lock should work");
    let spawn = events
        .iter()
        .position(|event| event == "spawn")
        .expect("spawn should be attempted");
    assert_eq!(events[spawn + 1], "route:revoke");
    assert_eq!(events[spawn + 2], "signal:Kill");
    assert!(events[spawn + 3].starts_with("remove:/var/lib/browserd/shards/"));
    assert!(events[spawn + 4].starts_with("remove:/sys/fs/cgroup/browserd/"));
}

#[tokio::test]
async fn rollback_revoke_failure_still_aborts_the_child_and_retains_route_ownership() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let shard_id = ShardId::new();
    filesystem
        .failing_removes
        .lock()
        .expect("failure lock should work")
        .insert(shard_id.to_string());
    let process = FaultProcess {
        fault: SpawnFault::Spawn,
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
    };
    let mut egress = FakeEgress {
        fail_revoke: true,
        ..FakeEgress::default()
    };
    egress.events = trace.clone();
    let egress_view = egress.clone();
    let error = LinuxSandboxBackend::new(config(), filesystem, process, egress)
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("rollback failures must be reported");

    assert!(
        error
            .to_string()
            .contains("provisioning rollback incomplete")
    );
    let events = trace.lock().expect("trace lock should work");
    let revoke = events
        .iter()
        .position(|event| event == "route:revoke")
        .expect("route cleanup should run");
    assert!(
        events.iter().any(|event| event == "signal:Kill"),
        "route failure must not defer exact prepared-child termination"
    );
    assert!(
        events[revoke + 1..]
            .iter()
            .any(|event| event.starts_with("remove:")),
        "resource cleanup should still be attempted after the child is dead"
    );
    assert!(
        !events.iter().any(|event| event == "route:release"),
        "a route whose revoke failed must not be released"
    );
    assert!(
        egress_view
            .active
            .lock()
            .expect("active route lock should work")
            .contains(&ShardEgressFence::new(shard_id, 7)),
        "the active route must remain represented by a retryable tombstone"
    );
}

#[tokio::test]
async fn invalid_or_mismatched_identity_revokes_egress_before_terminating_owned_child() {
    for fault in [SpawnFault::InvalidIdentity, SpawnFault::MismatchedIdentity] {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let mut filesystem = FakeFilesystem::production_tree();
        filesystem.events = trace.clone();
        let alive = Arc::new(Mutex::new(false));
        let process = FaultProcess {
            fault,
            events: trace.clone(),
            alive: alive.clone(),
        };
        let egress = FakeEgress {
            events: trace.clone(),
            ..FakeEgress::default()
        };
        let shard_id = ShardId::new();
        assert!(
            LinuxSandboxBackend::new(config(), filesystem.clone(), process, egress.clone())
                .provision(&launch_spec(shard_id.clone()))
                .await
                .is_err()
        );

        assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
        let events = trace.lock().expect("trace lock should work");
        let kill = events
            .iter()
            .position(|event| event == "signal:Kill")
            .expect("owned child must be killed without trusting reported identity");
        let revoke = events
            .iter()
            .position(|event| event == "route:revoke")
            .expect("route must be revoked");
        assert!(revoke < kill);
        assert!(events[kill + 1].starts_with("remove:/var/lib/browserd/shards/"));
        assert!(events[kill + 2].starts_with("remove:/sys/fs/cgroup/browserd/"));
    }
}

#[tokio::test]
async fn missing_inherited_cgroup_membership_revokes_route_and_terminates_spawned_child() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    *filesystem
        .cgroup_procs_override
        .lock()
        .expect("cgroup override lock should work") = Some(String::new());
    let process_events = trace.clone();
    let alive = Arc::new(Mutex::new(false));
    let process = FakeProcess {
        events: process_events.clone(),
        alive: alive.clone(),
        identity_matches: true,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let shard_id = ShardId::new();
    assert!(
        backend(filesystem.clone(), process, egress.clone())
            .provision(&launch_spec(shard_id.clone()))
            .await
            .is_err()
    );
    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let events = process_events.lock().expect("process lock should work");
    let kill = events
        .iter()
        .position(|event| event == "signal:Kill")
        .expect("child should be killed");
    let revoke = events
        .iter()
        .position(|event| event == "route:revoke")
        .expect("route should be revoked");
    assert!(revoke < kill);
    assert!(events[kill + 1].starts_with("remove:/var/lib/browserd/shards/"));
    assert!(events[kill + 2].starts_with("remove:/sys/fs/cgroup/browserd/"));
}

#[tokio::test]
async fn unsafe_or_symlinked_roots_fail_closed_before_mutation() {
    for unsafe_root in ["/", "/sys/fs/cgroup", "/var/lib/../etc"] {
        assert!(
            LinuxSandboxConfig::new(
                unsafe_root,
                "/var/lib/browserd/shards",
                "/usr/bin/bwrap",
                ChromiumRuntime::new("/opt/chromium/chrome", "/opt/browser/chrome"),
                LaunchGateRuntime::new(
                    "/usr/libexec/browserd-launch-gate",
                    "/opt/browser/browserd-launch-gate",
                ),
                [],
                CgroupLimits::new(10, 5, 2, 1000, 1000).expect("limits should work"),
                9,
                Duration::from_millis(10),
                Duration::from_millis(1),
            )
            .is_err()
        );
    }
    for conflicting_seccomp_fd in [3, 4] {
        assert!(
            LinuxSandboxConfig::new(
                "/sys/fs/cgroup/browserd",
                "/var/lib/browserd/shards",
                "/usr/bin/bwrap",
                ChromiumRuntime::new("/opt/chromium/chrome", "/opt/browser/chrome"),
                LaunchGateRuntime::new(
                    "/usr/libexec/browserd-launch-gate",
                    "/opt/browser/browserd-launch-gate",
                ),
                [],
                CgroupLimits::new(10, 5, 2, 1000, 1000).expect("limits should work"),
                conflicting_seccomp_fd,
                Duration::from_millis(10),
                Duration::from_millis(1),
            )
            .is_err()
        );
    }

    let filesystem = FakeFilesystem::production_tree();
    filesystem
        .symlinks
        .lock()
        .expect("symlink lock should work")
        .insert("/var/lib/browserd".into());
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let backend = backend(filesystem.clone(), process, FakeEgress::default());
    assert!(
        backend
            .provision(&launch_spec(ShardId::new()))
            .await
            .is_err()
    );
    assert!(filesystem.events().is_empty());
}

#[test]
fn launch_gate_path_cannot_be_shadowed_by_a_later_runtime_mount() {
    let configuration = LinuxSandboxConfig::new(
        "/sys/fs/cgroup/browserd",
        "/var/lib/browserd/shards",
        "/usr/bin/bwrap",
        ChromiumRuntime::new("/opt/chromium/chrome", "/opt/browser/chrome"),
        LaunchGateRuntime::new(
            "/usr/libexec/browserd-launch-gate",
            "/opt/browser/browserd-launch-gate",
        ),
        [ReadOnlyMount::new("/opt/runtime", "/opt/browser")],
        CgroupLimits::new(10, 5, 2, 1000, 1000).expect("limits should work"),
        9,
        Duration::from_millis(10),
        Duration::from_millis(1),
    );

    assert!(configuration.is_err());
}

#[test]
fn launch_gate_paths_cannot_alias_a_runtime_or_virtual_filesystem() {
    for launch_gate in [
        LaunchGateRuntime::new("/opt/chromium/chrome", "/opt/browser/launch-gate"),
        LaunchGateRuntime::new("/usr/bin/bwrap", "/opt/browser/launch-gate"),
        LaunchGateRuntime::new("/usr/libexec/browserd-launch-gate", "/opt/browser"),
        LaunchGateRuntime::new(
            "/usr/libexec/browserd-launch-gate",
            "/sys/browserd-launch-gate",
        ),
        LaunchGateRuntime::new("/tmp/browserd-launch-gate", "/opt/browser/launch-gate"),
        LaunchGateRuntime::new("/var/tmp/browserd-launch-gate", "/opt/browser/launch-gate"),
        LaunchGateRuntime::new("/dev/shm/browserd-launch-gate", "/opt/browser/launch-gate"),
        LaunchGateRuntime::new(
            "/run/user/1000/browserd-launch-gate",
            "/opt/browser/launch-gate",
        ),
        LaunchGateRuntime::new(
            "/var/lib/browserd/shards/browserd-launch-gate",
            "/opt/browser/launch-gate",
        ),
    ] {
        assert!(
            LinuxSandboxConfig::new(
                "/sys/fs/cgroup/browserd",
                "/var/lib/browserd/shards",
                "/usr/bin/bwrap",
                ChromiumRuntime::new("/opt/chromium/chrome", "/opt/browser/chrome"),
                launch_gate,
                [],
                CgroupLimits::new(10, 5, 2, 1000, 1000).expect("limits should work"),
                9,
                Duration::from_millis(10),
                Duration::from_millis(1),
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn writable_launch_gate_fails_closed_before_any_sandbox_mutation() {
    let filesystem = FakeFilesystem::production_tree();
    filesystem
        .unwritable
        .lock()
        .expect("unwritable lock should work")
        .remove(Path::new("/usr/libexec/browserd-launch-gate"));
    let result = backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    )
    .provision(&launch_spec(ShardId::new()))
    .await;

    assert!(result.is_err());
    assert!(filesystem.events().is_empty());
}

#[test]
fn production_filesystem_requires_explicit_non_broad_safe_roots() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let cgroup_root = directory.path().join("cgroups");
    let sandbox_root = directory.path().join("sandboxes");
    std::fs::create_dir(&cgroup_root).expect("cgroup root should be created");
    std::fs::create_dir(&sandbox_root).expect("sandbox root should be created");

    assert!(StdSandboxFilesystem::new(&cgroup_root, &sandbox_root).is_ok());
    assert!(StdSandboxFilesystem::new("/", &sandbox_root).is_err());
    assert!(StdSandboxFilesystem::new("/sys/fs/cgroup", &sandbox_root).is_err());
}

#[test]
fn production_filesystem_never_recursively_removes_cgroup_contents() {
    let directory = tempfile::tempdir().expect("tempdir should be created");
    let cgroup_root = directory.path().join("cgroups");
    let sandbox_root = directory.path().join("sandboxes");
    let shard_cgroup = cgroup_root.join("shard");
    std::fs::create_dir(&cgroup_root).expect("cgroup root should be created");
    std::fs::create_dir(&sandbox_root).expect("sandbox root should be created");
    std::fs::create_dir(&shard_cgroup).expect("shard cgroup should be created");
    std::fs::write(shard_cgroup.join("cgroup.events"), "populated 0\n")
        .expect("test cgroup control file should be created");
    let filesystem = StdSandboxFilesystem::new(&cgroup_root, &sandbox_root)
        .expect("filesystem roots should be accepted");

    assert!(filesystem.remove_directory(&shard_cgroup).is_err());
    assert!(shard_cgroup.join("cgroup.events").exists());
}

#[tokio::test]
async fn production_process_rejects_missing_required_launch_descriptors_before_exec() {
    let request = LinuxSandboxBackend::new(
        LinuxSandboxConfig::new(
            "/sys/fs/cgroup/browserd",
            "/var/lib/browserd/shards",
            "/definitely/missing/bwrap",
            ChromiumRuntime::new("/opt/chromium/chrome", "/opt/chromium/chrome"),
            LaunchGateRuntime::new(
                "/usr/libexec/browserd-launch-gate",
                "/opt/browser/browserd-launch-gate",
            ),
            [],
            CgroupLimits::new(512, 256, 4, 10, 100).expect("limits should be valid"),
            i32::MAX,
            Duration::from_millis(10),
            Duration::from_millis(1),
        )
        .expect("config should be valid"),
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    )
    .planned_spawn_request(&ShardId::new());

    let error = StdLinuxProcessBackend::default()
        .spawn_prepared(&LeaseId::new().to_string(), &request)
        .await
        .expect_err("a closed seccomp descriptor must fail closed");
    assert!(error.to_string().contains("required inherited descriptor"));
}

#[test]
fn production_process_signals_through_pidfds_instead_of_rechecking_proc_then_killing_pid() {
    let implementation = include_str!("../src/linux.rs");
    assert!(
        implementation.contains("SYS_pidfd_open"),
        "the exact sandbox process must be captured with pidfd_open"
    );
    assert!(
        implementation.contains("SYS_pidfd_send_signal"),
        "signals must target the captured process rather than a reusable numeric PID"
    );
}

#[test]
fn production_abort_never_signals_a_reused_bootstrap_identity_after_auto_reap() {
    let output = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount-proc",
        ])
        .arg(std::env::current_exe().expect("test executable should be known"))
        .arg("--ignored")
        .arg("--exact")
        .arg("std_process_reused_bootstrap_identity_helper")
        .arg("--nocapture")
        .env("BROWSERD_PROCESS_HELPER", "1")
        .output()
        .expect("PID namespace helper should start");
    assert!(
        output.status.success(),
        "PID namespace helper failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "runs only in an isolated PID namespace subprocess"]
fn std_process_reused_bootstrap_identity_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let bootstrap_pid_path = marker_directory.path().join("bootstrap-pid");
    let bootstrap_exit_path = marker_directory.path().join("bootstrap-exit");
    let script = r#"#!/usr/bin/python3
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    sys.stdin.buffer.read()
    os._exit(0)

bootstrap_pid_marker = "__BOOTSTRAP_PID__"
bootstrap_pid_temporary = bootstrap_pid_marker + ".tmp"
with open(bootstrap_pid_temporary, "w") as marker:
    marker.write(str(os.getpid()))
    marker.flush()
    os.fsync(marker.fileno())
os.replace(bootstrap_pid_temporary, bootstrap_pid_marker)
os.close(info_fd)
while not os.path.exists("__BOOTSTRAP_EXIT__"):
    time.sleep(0.005)
os._exit(0)
"#
    .replace(
        "__BOOTSTRAP_PID__",
        bootstrap_pid_path
            .to_str()
            .expect("bootstrap PID path should contain valid UTF-8"),
    )
    .replace(
        "__BOOTSTRAP_EXIT__",
        bootstrap_exit_path
            .to_str()
            .expect("bootstrap exit path should contain valid UTF-8"),
    );
    let (_directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let pidfd_open_syscall = u32::try_from(nix::libc::SYS_pidfd_open)
            .expect("pidfd_open syscall number should fit the seccomp operand");
        let pidfd_flags_offset = u32::try_from(
            std::mem::offset_of!(nix::libc::seccomp_data, args)
                + std::mem::size_of::<u64>()
                + if cfg!(target_endian = "big") {
                    std::mem::size_of::<u32>()
                } else {
                    0
                },
        )
        .expect("pidfd flags offset should fit the seccomp operand");
        let mut tokio_pidfd_filter = [
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_LD | nix::libc::BPF_W | nix::libc::BPF_ABS)
                    .expect("BPF load instruction should fit"),
                jt: 0,
                jf: 0,
                k: 0,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_JMP | nix::libc::BPF_JEQ | nix::libc::BPF_K)
                    .expect("BPF comparison instruction should fit"),
                jt: 0,
                jf: 3,
                k: pidfd_open_syscall,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_LD | nix::libc::BPF_W | nix::libc::BPF_ABS)
                    .expect("BPF load instruction should fit"),
                jt: 0,
                jf: 0,
                k: pidfd_flags_offset,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_JMP | nix::libc::BPF_JEQ | nix::libc::BPF_K)
                    .expect("BPF comparison instruction should fit"),
                jt: 0,
                jf: 1,
                k: nix::libc::PIDFD_NONBLOCK,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_RET | nix::libc::BPF_K)
                    .expect("BPF return instruction should fit"),
                jt: 0,
                jf: 0,
                k: nix::libc::SECCOMP_RET_ERRNO
                    | u32::try_from(nix::libc::ENOSYS).expect("errno should fit"),
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_RET | nix::libc::BPF_K)
                    .expect("BPF return instruction should fit"),
                jt: 0,
                jf: 0,
                k: nix::libc::SECCOMP_RET_ALLOW,
            },
        ];
        let tokio_pidfd_program = nix::libc::sock_fprog {
            len: u16::try_from(tokio_pidfd_filter.len())
                .expect("seccomp program length should fit"),
            filter: tokio_pidfd_filter.as_mut_ptr(),
        };
        // SAFETY: the helper is isolated and the BPF program remains live for both prctl calls.
        let no_new_privileges =
            unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        assert_eq!(no_new_privileges, 0, "no_new_privs should be enabled");
        // SAFETY: the valid filter only denies Tokio's PIDFD_NONBLOCK probe. The backend's
        // flags=0 pidfd capture remains available so exact ownership can still be established.
        let seccomp = unsafe {
            nix::libc::prctl(
                nix::libc::PR_SET_SECCOMP,
                nix::libc::SECCOMP_MODE_FILTER,
                &raw const tokio_pidfd_program,
            )
        };
        assert_eq!(seccomp, 0, "Tokio pidfd probe filter should be installed");

        let identity = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect("fake sandbox child should be prepared before its bootstrap exits");
        let bootstrap_pid = std::fs::read_to_string(&bootstrap_pid_path)
            .expect("bootstrap PID should be recorded")
            .parse::<u32>()
            .expect("bootstrap PID should be numeric");

        // SAFETY: this helper is the PID-namespace init process, runs no other tests, and exits
        // immediately afterward. Ignoring SIGCHLD forces the exited bootstrap to be auto-reaped.
        let previous_sigchld = unsafe { nix::libc::signal(nix::libc::SIGCHLD, nix::libc::SIG_IGN) };
        assert_ne!(previous_sigchld, nix::libc::SIG_ERR);
        std::fs::write(&bootstrap_exit_path, b"exit")
            .expect("the fake bootstrap should be allowed to exit after identity capture");
        tokio::time::timeout(Duration::from_secs(1), async {
            while Path::new(&format!("/proc/{bootstrap_pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the bootstrap should be auto-reaped");

        std::fs::write(
            "/proc/sys/kernel/ns_last_pid",
            bootstrap_pid
                .checked_sub(1)
                .expect("bootstrap PID should exceed one")
                .to_string(),
        )
        .expect("the isolated PID namespace should permit deterministic PID reuse");
        let mut unrelated = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("unrelated process group should start");
        assert_eq!(
            unrelated.id(),
            bootstrap_pid,
            "the test must actually reuse the auto-reaped bootstrap PID/PGID"
        );

        let abort = process.abort_spawned(&backend_token, Some(identity)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            Path::new(&format!("/proc/{bootstrap_pid}")).exists(),
            "aborting the captured sandbox must not signal a process that reused the bootstrap PID"
        );
        abort.expect("exact pidfds must prove cleanup even when the bootstrap was auto-reaped");

        // SAFETY: this PID was deterministically allocated to the helper-owned sleep process and
        // has just been proven live; the isolated namespace prevents it from naming a host process.
        let killed = unsafe { nix::libc::kill(bootstrap_pid.cast_signed(), nix::libc::SIGKILL) };
        assert_eq!(killed, 0, "unrelated helper process should be cleaned up");
        let _ = unrelated.wait();
        tokio::time::timeout(Duration::from_secs(1), async {
            while Path::new(&format!("/proc/{bootstrap_pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first unrelated helper should be auto-reaped");

        let unavailable_pidfd_directory =
            tempfile::tempdir().expect("second marker tempdir should be created");
        let unavailable_bootstrap_pid_path =
            unavailable_pidfd_directory.path().join("bootstrap-pid");
        let unavailable_bootstrap_exit_path =
            unavailable_pidfd_directory.path().join("bootstrap-exit");
        let unavailable_pidfd_script = r#"#!/usr/bin/python3
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    sys.stdin.buffer.read()
    os._exit(0)

bootstrap_pid_marker = "__BOOTSTRAP_PID__"
bootstrap_pid_temporary = bootstrap_pid_marker + ".tmp"
with open(bootstrap_pid_temporary, "w") as marker:
    marker.write(str(os.getpid()))
    marker.flush()
    os.fsync(marker.fileno())
os.replace(bootstrap_pid_temporary, bootstrap_pid_marker)
os.close(info_fd)
while not os.path.exists("__BOOTSTRAP_EXIT__"):
    time.sleep(0.005)
os._exit(0)
"#
        .replace(
            "__BOOTSTRAP_PID__",
            unavailable_bootstrap_pid_path
                .to_str()
                .expect("bootstrap PID path should contain valid UTF-8"),
        )
        .replace(
            "__BOOTSTRAP_EXIT__",
            unavailable_bootstrap_exit_path
                .to_str()
                .expect("bootstrap exit path should contain valid UTF-8"),
        );
        let (_unavailable_directory, unavailable_bwrap) =
            executable_script(&unavailable_pidfd_script);
        let (_unavailable_cgroup, unavailable_request) = process_request_for(&unavailable_bwrap);

        let syscall_number = u32::try_from(nix::libc::SYS_pidfd_open)
            .expect("pidfd_open syscall number should fit the seccomp operand");
        let clone3_syscall_number = u32::try_from(nix::libc::SYS_clone3)
            .expect("clone3 syscall number should fit the seccomp operand");
        let mut filter = [
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_LD | nix::libc::BPF_W | nix::libc::BPF_ABS)
                    .expect("BPF load instruction should fit"),
                jt: 0,
                jf: 0,
                k: 0,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_JMP | nix::libc::BPF_JEQ | nix::libc::BPF_K)
                    .expect("BPF comparison instruction should fit"),
                jt: 2,
                jf: 0,
                k: syscall_number,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_JMP | nix::libc::BPF_JEQ | nix::libc::BPF_K)
                    .expect("BPF comparison instruction should fit"),
                jt: 1,
                jf: 0,
                k: clone3_syscall_number,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_RET | nix::libc::BPF_K)
                    .expect("BPF return instruction should fit"),
                jt: 0,
                jf: 0,
                k: nix::libc::SECCOMP_RET_ALLOW,
            },
            nix::libc::sock_filter {
                code: u16::try_from(nix::libc::BPF_RET | nix::libc::BPF_K)
                    .expect("BPF return instruction should fit"),
                jt: 0,
                jf: 0,
                k: nix::libc::SECCOMP_RET_ERRNO
                    | u32::try_from(nix::libc::ENOSYS).expect("errno should fit"),
            },
        ];
        let program = nix::libc::sock_fprog {
            len: u16::try_from(filter.len()).expect("seccomp program length should fit"),
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: the helper is already isolated, the BPF program is valid for the duration of
        // both prctl calls, and it only makes future pidfd_open/clone3 calls return ENOSYS.
        let no_new_privileges =
            unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        assert_eq!(no_new_privileges, 0, "no_new_privs should be enabled");
        // SAFETY: `program` points to the live fixed-size filter above and no_new_privs is set.
        let seccomp = unsafe {
            nix::libc::prctl(
                nix::libc::PR_SET_SECCOMP,
                nix::libc::SECCOMP_MODE_FILTER,
                &raw const program,
            )
        };
        assert_eq!(seccomp, 0, "pidfd_open filter should be installed");

        let pidfdless_process = StdLinuxProcessBackend::default();
        let pidfdless_token = LeaseId::new().to_string();
        let spawn_error = pidfdless_process
            .spawn_prepared(&pidfdless_token, &unavailable_request)
            .await
            .expect_err("missing bootstrap pidfd must fail closed");
        assert!(spawn_error.to_string().contains("pidfd unavailable"));
        // SAFETY: this isolated helper deliberately restores auto-reap immediately before
        // allowing the pidfd-less bootstrap to exit.
        let previous_sigchld = unsafe { nix::libc::signal(nix::libc::SIGCHLD, nix::libc::SIG_IGN) };
        assert_ne!(previous_sigchld, nix::libc::SIG_ERR);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !unavailable_bootstrap_pid_path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the pidfd-less bootstrap should record its PID");
        let unavailable_bootstrap_pid = std::fs::read_to_string(&unavailable_bootstrap_pid_path)
            .expect("pidfd-less bootstrap PID should be readable")
            .parse::<u32>()
            .expect("pidfd-less bootstrap PID should be numeric");
        std::fs::write(&unavailable_bootstrap_exit_path, b"exit")
            .expect("the pidfd-less bootstrap should be allowed to exit");
        tokio::time::timeout(Duration::from_secs(1), async {
            while Path::new(&format!("/proc/{unavailable_bootstrap_pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the pidfd-less bootstrap should be auto-reaped");

        std::fs::write(
            "/proc/sys/kernel/ns_last_pid",
            unavailable_bootstrap_pid
                .checked_sub(1)
                .expect("bootstrap PID should exceed one")
                .to_string(),
        )
        .expect("the second bootstrap PID should be made reusable");
        let mut pidfdless_unrelated = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("second unrelated process should start");
        assert_eq!(
            pidfdless_unrelated.id(),
            unavailable_bootstrap_pid,
            "the pidfd-less bootstrap PID must actually be reused"
        );
        assert!(
            pidfdless_process
                .abort_spawned(&pidfdless_token, None)
                .await
                .is_err(),
            "without exact pidfds the prepared child must remain quarantined"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            Path::new(&format!("/proc/{unavailable_bootstrap_pid}")).exists(),
            "pidfd unavailability must never fall back to signalling a reusable numeric PID"
        );
        // SAFETY: the reused PID belongs to this isolated helper and was just proven live.
        let killed =
            unsafe { nix::libc::kill(unavailable_bootstrap_pid.cast_signed(), nix::libc::SIGKILL) };
        assert_eq!(killed, 0, "second unrelated helper should be cleaned up");
        let _ = pidfdless_unrelated.wait();
    });
}

#[test]
fn production_process_info_read_has_an_absolute_timeout() {
    run_process_helper("std_process_info_timeout_helper");
}

#[test]
fn production_process_rejects_a_reported_pid_not_parented_by_the_exact_bootstrap() {
    run_process_helper("std_process_unrelated_info_pid_helper");
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_unrelated_info_pid_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let script = r#"#!/usr/bin/python3
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

unrelated_pid = os.getppid()
sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.close(info_fd)
    if sys.stdin.buffer.read() == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
    os._exit(0)

os.write(info_fd, json.dumps({"child-pid": unrelated_pid}).encode() + b"\n")
os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    );
    let (_directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let error = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect_err("a PID outside the exact bootstrap parent must never be captured");
        assert!(
            error.to_string().contains("bootstrap parent"),
            "unexpected identity rejection: {error}"
        );
        assert!(
            process.abort_spawned(&backend_token, None).await.is_err(),
            "an unidentifiable child must retain its fail-closed gate quarantine"
        );
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !marker.exists(),
            "rejecting an unrelated PID must neither signal it nor release the real child"
        );
    });
}

#[test]
fn timed_out_info_is_quarantined_and_retryably_recovers_exact_child_ownership() {
    run_process_helper("std_process_info_timeout_recovery_helper");
}

#[test]
fn cancelled_info_read_retains_a_retryable_backend_owned_gate_tombstone() {
    run_process_helper("std_process_info_cancellation_recovery_helper");
}

#[test]
fn malformed_info_retains_an_unidentified_sandbox_child_gate_quarantine() {
    run_process_helper("std_process_malformed_info_quarantine_helper");
}

#[test]
fn malformed_info_recovers_only_after_exact_cgroup_kill_proves_population_zero() {
    run_process_helper("std_process_malformed_info_cgroup_recovery_helper");
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_malformed_info_cgroup_recovery_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let script = r#"#!/usr/bin/python3
import os
import signal
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

control_path = os.path.join(os.path.dirname(__file__), "cgroup-kill-path")
with open(control_path) as control:
    cgroup_kill_path = control.read()
cgroup_events_path = os.path.join(os.path.dirname(cgroup_kill_path), "cgroup.events")

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.close(info_fd)
    if sys.stdin.buffer.read() == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
    os._exit(0)

os.write(info_fd, b"not-json\n")
os.close(info_fd)
while True:
    with open(cgroup_kill_path) as cgroup_kill:
        if cgroup_kill.read().strip() == "1":
            break
    time.sleep(0.005)
os.kill(sandbox_pid, signal.SIGKILL)
os.waitpid(sandbox_pid, 0)
with open(cgroup_events_path, "w") as cgroup_events:
    cgroup_events.write("populated 0\n")
os._exit(0)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    );
    let (directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let cgroup_kill_path = request.cgroup_procs_path().with_file_name("cgroup.kill");
    let cgroup_events_path = request.cgroup_procs_path().with_file_name("cgroup.events");
    std::fs::write(&cgroup_kill_path, b"").expect("fake cgroup.kill should be created");
    std::fs::write(&cgroup_events_path, b"populated 1\n")
        .expect("fake cgroup.events should be created");
    std::fs::write(
        directory.path().join("cgroup-kill-path"),
        cgroup_kill_path.as_os_str().as_encoded_bytes(),
    )
    .expect("fake cgroup kill locator should be written");

    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let error = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect_err("malformed info must fail prepared spawn");
        assert!(error.to_string().contains("invalid sandbox PID response"));

        process
            .abort_spawned(&backend_token, None)
            .await
            .expect("exact cgroup kill and populated-zero proof must release unidentified ownership");
        process
            .abort_spawned(&backend_token, None)
            .await
            .expect("completed unidentified cleanup must be idempotent");
        assert_eq!(
            std::fs::read(&cgroup_kill_path).expect("cgroup kill record should be readable"),
            b"1",
            "cleanup must request exact cgroup-wide termination"
        );
        assert_eq!(
            std::fs::read(&cgroup_events_path).expect("cgroup events should be readable"),
            b"populated 0\n",
            "cleanup may release ownership only after cgroup emptiness is proven"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !marker.exists(),
            "dropping the quarantined gate after proven cgroup emptiness must not execute the browser"
        );
    });
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_malformed_info_quarantine_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let script = r#"#!/usr/bin/python3
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    os.write(info_fd, b"not-json\n")
    os.close(info_fd)
    if sys.stdin.buffer.read() == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
    os._exit(0)

os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    );
    let (_directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    let error = runtime
        .block_on(
            StdLinuxProcessBackend::default().spawn_prepared(&LeaseId::new().to_string(), &request),
        )
        .expect_err("malformed info must fail prepared spawn");
    assert!(error.to_string().contains("invalid sandbox PID response"));
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !marker.exists(),
        "an unidentified sandbox child must remain blocked behind the retained gate"
    );
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_info_timeout_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let (_directory, bwrap) = executable_script("#!/bin/sh\nexec /bin/sleep 3\n");
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let started = Instant::now();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    let error = runtime
        .block_on(
            StdLinuxProcessBackend::default().spawn_prepared(&LeaseId::new().to_string(), &request),
        )
        .expect_err("an unterminated info response must time out");

    assert!(error.to_string().contains("sandbox PID response timed out"));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the absolute timeout must bound the entire info-fd read"
    );
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_info_timeout_recovery_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let script = r#"#!/usr/bin/python3
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    time.sleep(1.2)
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    if sys.stdin.buffer.read() == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
    os._exit(0)

os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    );
    let (_directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let error = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect_err("the first absolute info deadline must expire");
        assert!(error.to_string().contains("sandbox PID response timed out"));

        StdLinuxProcessBackend::default()
            .abort_spawned(&backend_token, None)
            .await
            .expect(
                "a fresh backend handle must recover the delayed identity, pidfd-kill it, and prove both deaths",
            );
        assert!(
            process
                .release_prepared(&backend_token, ChildIdentity::new(1, 1))
                .await
                .is_err(),
            "the quarantine tombstone is removed only after completed cleanup"
        );
        assert!(
            !marker.exists(),
            "timeout cleanup must not release the browser through gate EOF"
        );
    });
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_info_cancellation_recovery_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let ready = marker_directory.path().join("bootstrap-ready");
    let script = r#"#!/usr/bin/python3
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

open("__READY_MARKER__", "w").close()
sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    time.sleep(0.3)
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    if sys.stdin.buffer.read() == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
    os._exit(0)

os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    )
    .replace(
        "__READY_MARKER__",
        ready
            .to_str()
            .expect("ready path should contain valid UTF-8"),
    );
    let (_directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let spawn = tokio::spawn({
            let backend_token = backend_token.clone();
            async move { process.spawn_prepared(&backend_token, &request).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fake bootstrap must reach its cancellable info read");
        spawn.abort();
        assert!(
            spawn
                .await
                .expect_err("spawn should be cancelled")
                .is_cancelled()
        );

        process
            .abort_spawned(&backend_token, None)
            .await
            .expect("cancellation tombstone must recover identity and prove exact cleanup");
        assert!(
            !marker.exists(),
            "cancellation must not drop the writer and release the browser through EOF"
        );
    });
}

#[test]
fn production_abort_confirms_the_exact_sandbox_child_exited_before_forgetting_ownership() {
    run_process_helper("std_process_exact_abort_helper");
}

#[test]
fn production_release_reaps_the_naturally_exited_bootstrap_before_forgetting_ownership() {
    run_process_helper("std_process_natural_release_helper");
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_natural_release_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let script = r#"#!/usr/bin/python3
import json
import os
import sys

info_fd = None
block_fd_seen = False
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        block_fd_seen = True
        next(arguments)
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

control_path = os.path.join(os.path.dirname(__file__), "cgroup-kill-path")
with open(control_path) as control:
    cgroup_kill_path = control.read()
cgroup_events_path = os.path.join(os.path.dirname(cgroup_kill_path), "cgroup.events")

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.close(info_fd)
    approval = sys.stdin.buffer.read()
    if not block_fd_seen and approval == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
    os._exit(0)

os.write(info_fd, json.dumps({"child-pid": sandbox_pid}).encode() + b"\n")
os.close(info_fd)
os.waitpid(sandbox_pid, 0)
with open(cgroup_events_path, "w") as cgroup_events:
    cgroup_events.write("populated 0\n")
os._exit(0)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    );
    let (directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let cgroup_kill_path = request.cgroup_procs_path().with_file_name("cgroup.kill");
    let cgroup_events_path = request.cgroup_procs_path().with_file_name("cgroup.events");
    std::fs::write(
        directory.path().join("cgroup-kill-path"),
        cgroup_kill_path.as_os_str().as_encoded_bytes(),
    )
    .expect("fake cgroup kill locator should be written");

    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let identity = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect("fake sandbox child should be prepared");
        process
            .release_prepared(&backend_token, identity)
            .await
            .expect("the exact prepared child should be released");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if marker.exists()
                    && std::fs::read_to_string(&cgroup_events_path)
                        .is_ok_and(|events| events.lines().any(|line| line == "populated 0"))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the released sandbox and its bootstrap should exit naturally");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match process.release_spawned(&backend_token, identity).await {
                    Ok(()) => break,
                    Err(error) => {
                        assert!(
                            error.to_string().contains("live spawned child"),
                            "unexpected natural release failure: {error}"
                        );
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        })
        .await
        .expect("the exited bootstrap must become reapable through its exact pidfd");
        assert!(
            !process
                .identity_matches(&backend_token, identity)
                .await
                .expect("released ownership should be absent")
        );
    });
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_exact_abort_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("marker tempdir should be created");
    let marker = marker_directory.path().join("browser-executed");
    let script = r#"#!/usr/bin/python3
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--block-fd":
        raise RuntimeError("legacy block-fd must not be used")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    if sys.stdin.buffer.read() == b"browserd-launch-gate/v1 approve\n":
        open("__EXEC_MARKER__", "w").close()
        os.execl("/bin/sleep", "sleep", "30")
    os._exit(77)

os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__EXEC_MARKER__",
        marker
            .to_str()
            .expect("marker path should contain valid UTF-8"),
    );
    let (_directory, bwrap) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("helper runtime should build");
    runtime.block_on(async {
        let identity = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect("fake sandbox child should be prepared");
        assert_eq!(
            std::fs::read(request.cgroup_procs_path())
                .expect("bootstrap cgroup attachment record should be readable"),
            b"0\n",
            "the bootstrap must self-attach before exec instead of resolving a reusable PID"
        );
        assert!(
            process
                .identity_matches(&backend_token, identity)
                .await
                .expect("prepared child identity should be readable")
        );
        let stale_identity = ChildIdentity::new(identity.pid(), 1);
        process
            .signal(&backend_token, stale_identity, ProcessSignal::Kill)
            .await
            .expect_err("a reused numeric PID with another start time must not be signalled");
        assert!(
            process
                .identity_matches(&backend_token, identity)
                .await
                .expect("the captured pidfd should still identify the prepared child"),
            "rejecting the stale identity must leave the exact prepared child alive and gated"
        );

        process
            .abort_spawned(&backend_token, Some(identity))
            .await
            .expect("abort should kill and confirm the exact sandbox child");

        assert!(
            !process
                .identity_matches(&backend_token, identity)
                .await
                .expect("exited identity check should work"),
            "abort must not return while the exact sandbox child still exists"
        );
        assert!(
            process
                .release_prepared(&backend_token, identity)
                .await
                .is_err(),
            "ownership may be removed only after confirmed exit"
        );
        assert!(
            !marker.exists(),
            "gate EOF must never let the browser path execute during abort"
        );
    });
}

#[tokio::test]
async fn termination_validates_identity_then_terms_waits_kills_and_checks_populated_zero() {
    let filesystem = FakeFilesystem::production_tree();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let process = FakeProcess {
        events: process_events.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress::default();
    let backend = backend(filesystem.clone(), process, egress);
    let shard_id = ShardId::new();
    let handle = backend
        .provision(&launch_spec(shard_id))
        .await
        .expect("provision should work");
    let cgroup_events = filesystem
        .files
        .lock()
        .expect("file lock should work")
        .keys()
        .find(|path| path.ends_with("cgroup.procs"))
        .expect("cgroup should exist")
        .parent()
        .expect("parent should exist")
        .join("cgroup.events");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(cgroup_events, "populated 0\n".into());

    backend
        .kill_cgroup(&handle, CleanupReason::Administrative)
        .await
        .expect("kill should complete");
    let events = process_events
        .lock()
        .expect("process lock should work")
        .clone();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.as_str() == "identity")
            .count(),
        4
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.starts_with("signal:"))
            .cloned()
            .collect::<Vec<_>>(),
        ["signal:Terminate", "signal:Kill"]
    );
    assert!(
        filesystem
            .events()
            .iter()
            .any(|event| event.ends_with("cgroup.kill=1"))
    );
}

#[tokio::test]
async fn provisioning_rollback_revokes_the_exact_attempted_worker_epoch_fence() {
    let filesystem = FakeFilesystem::production_tree();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let process = FaultProcess {
        fault: SpawnFault::Spawn,
        events: trace,
        alive: Arc::new(Mutex::new(false)),
    };
    let egress = FakeEgress::default();
    let egress_view = egress.clone();
    let shard_id = ShardId::new();
    let expected = ShardEgressFence::new(shard_id.clone(), 47);

    LinuxSandboxBackend::new(config(), filesystem, process, egress)
        .provision(&LaunchSpec::production(
            shard_id,
            WorkerId::new("worker-rollback").expect("worker should be valid"),
            47,
        ))
        .await
        .expect_err("spawn failure should roll provisioning back");

    assert_eq!(
        egress_view
            .calls
            .lock()
            .expect("egress call lock should work")
            .as_slice(),
        [
            EgressCall::Prepare(expected.clone()),
            EgressCall::Revoke(expected.clone()),
            EgressCall::Release(expected),
        ]
    );
}

#[tokio::test]
async fn concurrent_cleanup_and_inspect_use_each_runtimes_exact_egress_fence() {
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress::default();
    let egress_view = egress.clone();
    let backend = Arc::new(backend(filesystem.clone(), process, egress));
    let inspect_shard = ShardId::new();
    let cleanup_shard = ShardId::new();
    let inspect_fence = ShardEgressFence::new(inspect_shard.clone(), 101);
    let cleanup_fence = ShardEgressFence::new(cleanup_shard.clone(), 202);
    let inspect_handle = backend
        .provision(&LaunchSpec::production(
            inspect_shard.clone(),
            WorkerId::new("worker-inspect").expect("worker should be valid"),
            101,
        ))
        .await
        .expect("inspect runtime should provision");
    let cleanup_handle = backend
        .provision(&LaunchSpec::production(
            cleanup_shard,
            WorkerId::new("worker-cleanup").expect("worker should be valid"),
            202,
        ))
        .await
        .expect("cleanup runtime should provision");
    let inspect_cgroup = PathBuf::from("/sys/fs/cgroup/browserd").join(inspect_shard.to_string());
    {
        let mut files = filesystem.files.lock().expect("file lock should work");
        files.insert(inspect_cgroup.join("memory.current"), "4096\n".into());
        files.insert(inspect_cgroup.join("memory.peak"), "8192\n".into());
    }

    let (inspection, revocation) = tokio::join!(
        backend.inspect(&inspect_handle),
        backend.revoke_egress(&cleanup_handle, CleanupReason::Administrative),
    );
    assert!(
        inspection
            .expect("inspection should succeed")
            .egress_route_active
    );
    revocation.expect("route revocation should succeed");

    let calls = egress_view
        .calls
        .lock()
        .expect("egress call lock should work");
    assert!(calls.contains(&EgressCall::IsActive(inspect_fence)));
    assert!(calls.contains(&EgressCall::Revoke(cleanup_fence)));
}

#[tokio::test]
async fn failed_revoke_retains_the_exact_fence_after_namespace_cleanup_for_retry() {
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress {
        fail_revoke: true,
        ..FakeEgress::default()
    };
    let egress_view = egress.clone();
    let backend = backend(filesystem.clone(), process, egress);
    let shard_id = ShardId::new();
    let expected = ShardEgressFence::new(shard_id.clone(), 303);
    let handle = backend
        .provision(&LaunchSpec::production(
            shard_id.clone(),
            WorkerId::new("worker-retry").expect("worker should be valid"),
            303,
        ))
        .await
        .expect("runtime should provision");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(shard_id.to_string())
                .join("cgroup.events"),
            "populated 0\n".into(),
        );

    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect_err("first route revoke should fail");
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("namespace cleanup should still make progress");
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect_err("retry should reach the still-failing egress backend");

    let calls = egress_view
        .calls
        .lock()
        .expect("egress call lock should work");
    assert_eq!(
        calls
            .iter()
            .filter(|call| **call == EgressCall::Revoke(expected.clone()))
            .count(),
        2
    );
}

#[tokio::test]
async fn namespace_cleanup_releases_the_exact_fence_only_after_cgroup_is_empty() {
    let filesystem = FakeFilesystem::production_tree();
    let trace = filesystem.events.clone();
    let process = FakeProcess {
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let egress_view = egress.clone();
    let backend = backend(filesystem.clone(), process, egress);
    let shard_id = ShardId::new();
    let expected = ShardEgressFence::new(shard_id.clone(), 7);
    let handle = backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("runtime should provision");
    let cgroup_events = PathBuf::from("/sys/fs/cgroup/browserd")
        .join(shard_id.to_string())
        .join("cgroup.events");

    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("route revoke should succeed");
    assert!(
        backend.cleanup_namespaces(&handle).await.is_err(),
        "a populated or unverified cgroup must not release its shard"
    );
    assert!(
        !egress_view
            .calls
            .lock()
            .expect("egress call lock should work")
            .contains(&EgressCall::Release(expected.clone()))
    );

    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(cgroup_events, "populated 0\n".into());
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("empty cgroup cleanup should release its shard");

    let calls = egress_view
        .calls
        .lock()
        .expect("egress call lock should work");
    let revoke = calls
        .iter()
        .position(|call| *call == EgressCall::Revoke(expected.clone()))
        .expect("route revoke should be recorded");
    let release = calls
        .iter()
        .position(|call| *call == EgressCall::Release(expected.clone()))
        .expect("shard release should be recorded");
    assert!(revoke < release);
    let trace = trace.lock().expect("cleanup trace lock should work");
    let process_release = trace
        .iter()
        .position(|event| event == "release")
        .expect("process handle should be released");
    let runtime_remove = trace
        .iter()
        .position(|event| event.starts_with("remove:/var/lib/browserd/shards/"))
        .expect("runtime directory should be removed");
    let cgroup_remove = trace
        .iter()
        .position(|event| event.starts_with("remove:/sys/fs/cgroup/browserd/"))
        .expect("cgroup should be removed");
    let route_release = trace
        .iter()
        .position(|event| event == "route:release")
        .expect("route shard should be released");
    assert!(process_release < runtime_remove);
    assert!(runtime_remove < cgroup_remove);
    assert!(cgroup_remove < route_release);
}

#[tokio::test]
async fn partial_namespace_cleanup_retries_only_unfinished_stages_before_release() {
    let filesystem = FakeFilesystem::production_tree();
    let trace = filesystem.events.clone();
    let process = FakeProcess {
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress {
        events: trace.clone(),
        ..FakeEgress::default()
    };
    let backend = backend(filesystem.clone(), process, egress);
    let shard_id = ShardId::new();
    let handle = backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("runtime should provision");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(shard_id.to_string())
                .join("cgroup.events"),
            "populated 0\n".into(),
        );
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("route revoke should succeed");
    filesystem
        .failing_removes
        .lock()
        .expect("remove failpoint lock should work")
        .insert(format!("browserd/{shard_id}"));

    assert!(backend.cleanup_namespaces(&handle).await.is_err());
    filesystem
        .failing_removes
        .lock()
        .expect("remove failpoint lock should work")
        .clear();
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("retry should finish only the remaining cleanup stages");

    let trace = trace.lock().expect("cleanup trace lock should work");
    assert_eq!(trace.iter().filter(|event| *event == "release").count(), 1);
    assert_eq!(
        trace
            .iter()
            .filter(|event| event.starts_with("remove:/var/lib/browserd/shards/"))
            .count(),
        1
    );
    assert_eq!(
        trace
            .iter()
            .filter(|event| *event == "route:release")
            .count(),
        1
    );
}

#[tokio::test]
async fn forged_or_stale_backend_handle_cannot_target_the_current_runtime() {
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress::default();
    let egress_view = egress.clone();
    let backend = backend(filesystem, process, egress);
    let shard_id = ShardId::new();
    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect("runtime should provision");
    let forged = browserd_sandbox::SandboxHandle::new(shard_id, LeaseId::new().to_string());

    assert!(
        backend
            .revoke_egress(&forged, CleanupReason::Administrative)
            .await
            .is_err()
    );
    assert!(
        !egress_view
            .calls
            .lock()
            .expect("egress call lock should work")
            .iter()
            .any(|call| matches!(call, EgressCall::Revoke(_)))
    );
}
