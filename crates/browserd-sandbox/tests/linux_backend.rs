#![allow(clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, LeaseId, OwnerFence, PreparedShardState, RouteGeneration,
    SessionId, SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD, CgroupLimits, ChildIdentity, ChromiumBinaryDigest,
    ChromiumRuntime, CleanupReason, DedicatedEgressSpec, EgressPolicyBinding, EgressRouteBackend,
    FilePreparedShardJournal, LaunchGateRuntime, LaunchSpec, LinuxProcessBackend,
    LinuxSandboxBackend, LinuxSandboxConfig, NetworkNamespaceIdentity, PinnedNetworkNamespace,
    PreparedLinuxChild, PreparedShardCleanupStage, PreparedShardCleanupStageStatus,
    PreparedShardJournalLimits, PreparedShardRecoveryDisposition, PreparedShardRecoveryRoots,
    ProcessSignal, ReadOnlyMount, SandboxBackend, SandboxError, SandboxFilesystem,
    ShardEgressFence, ShardEgressReservation, ShardIngressLease, ShardIngressReceipt, SpawnRequest,
    StdLinuxProcessBackend, StdSandboxFilesystem,
};
use sha2::{Digest, Sha256};

const TEST_CHROMIUM_BYTES: &[u8] = b"browserd test Chromium";

fn chromium_digest(bytes: &[u8]) -> ChromiumBinaryDigest {
    ChromiumBinaryDigest::new(Sha256::digest(bytes).into())
}

fn chromium_runtime(sandbox_executable: impl Into<PathBuf>) -> ChromiumRuntime {
    ChromiumRuntime::from_bytes(
        TEST_CHROMIUM_BYTES,
        sandbox_executable,
        chromium_digest(TEST_CHROMIUM_BYTES),
    )
    .expect("test Chromium bytes should be pinned")
}

fn current_network_namespace() -> Result<PinnedNetworkNamespace, SandboxError> {
    let descriptor: OwnedFd = File::open("/proc/self/ns/net")
        .map_err(|error| SandboxError::Backend(format!("open fake network namespace: {error}")))?
        .into();
    PinnedNetworkNamespace::from_owned_fd(descriptor)
}

fn prepared_child(identity: ChildIdentity) -> Result<PreparedLinuxChild, SandboxError> {
    Ok(PreparedLinuxChild::new(
        identity,
        current_network_namespace()?,
    ))
}

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
    directory_entries_override: Arc<Mutex<Option<Vec<PathBuf>>>>,
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

    fn read_directory(&self, path: &Path) -> Result<Vec<PathBuf>, SandboxError> {
        if let Some(entries) = self
            .directory_entries_override
            .lock()
            .expect("directory entries override")
            .clone()
        {
            return Ok(entries);
        }
        let mut children = self
            .directories
            .lock()
            .expect("directory entries")
            .iter()
            .filter(|child| child.parent() == Some(path))
            .cloned()
            .collect::<Vec<_>>();
        children.extend(
            self.files
                .lock()
                .expect("file entries")
                .keys()
                .filter(|child| child.parent() == Some(path))
                .cloned(),
        );
        children.extend(
            self.symlinks
                .lock()
                .expect("symlink entries")
                .iter()
                .filter(|child| child.parent() == Some(path))
                .cloned(),
        );
        children.sort();
        children.dedup();
        Ok(children)
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
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
        prepared_child(ChildIdentity::new(4242, 991))
    }

    async fn claim_cdp_pipes(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
    ) -> Result<browserd_sandbox::ChromiumCdpPipes, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("cdp:claim".into());
        let (command_reader, command_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        let (event_reader, event_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|error| SandboxError::Backend(error.to_string()))?;
        drop(command_reader);
        drop(event_writer);
        browserd_sandbox::ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
    }

    async fn network_namespace_matches(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
        _network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("netns:revalidate".into());
        Ok(true)
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
struct ClaimNamespaceProcess {
    inner: FakeProcess,
    namespace_matches: Arc<AtomicBool>,
}

#[async_trait]
impl LinuxProcessBackend for ClaimNamespaceProcess {
    async fn spawn_prepared(
        &self,
        token: &str,
        request: &SpawnRequest,
    ) -> Result<PreparedLinuxChild, SandboxError> {
        self.inner.spawn_prepared(token, request).await
    }
    async fn claim_cdp_pipes(
        &self,
        token: &str,
        identity: ChildIdentity,
    ) -> Result<browserd_sandbox::ChromiumCdpPipes, SandboxError> {
        self.inner.claim_cdp_pipes(token, identity).await
    }
    async fn network_namespace_matches(
        &self,
        token: &str,
        identity: ChildIdentity,
        namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        if !self.namespace_matches.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.inner
            .network_namespace_matches(token, identity, namespace)
            .await
    }
    async fn release_prepared(
        &self,
        token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_prepared(token, identity).await
    }
    async fn abort_spawned(
        &self,
        token: &str,
        identity: Option<ChildIdentity>,
    ) -> Result<(), SandboxError> {
        self.inner.abort_spawned(token, identity).await
    }
    async fn release_spawned(
        &self,
        token: &str,
        identity: ChildIdentity,
    ) -> Result<(), SandboxError> {
        self.inner.release_spawned(token, identity).await
    }
    async fn identity_matches(
        &self,
        token: &str,
        identity: ChildIdentity,
    ) -> Result<bool, SandboxError> {
        self.inner.identity_matches(token, identity).await
    }
    async fn signal(
        &self,
        token: &str,
        identity: ChildIdentity,
        signal: ProcessSignal,
    ) -> Result<(), SandboxError> {
        self.inner.signal(token, identity, signal).await
    }
    async fn is_alive(&self, token: &str, identity: ChildIdentity) -> Result<bool, SandboxError> {
        self.inner.is_alive(token, identity).await
    }
    async fn wait(&self, duration: Duration) {
        self.inner.wait(duration).await;
    }
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

async fn wait_for_commit_pause(pause: &AsyncPause, operation: &str) {
    assert!(
        tokio::time::timeout(Duration::from_secs(1), pause.entered.notified())
            .await
            .is_ok(),
        "{operation} did not reach its post-commit pause"
    );
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
        let child = self.inner.spawn_prepared(backend_token, request).await?;
        self.pause.pause_once().await;
        Ok(child)
    }

    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.inner
            .network_namespace_matches(backend_token, identity, network_namespace)
            .await
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.inner
            .network_namespace_matches(backend_token, identity, network_namespace)
            .await
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.inner
            .network_namespace_matches(backend_token, identity, network_namespace)
            .await
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.inner
            .network_namespace_matches(backend_token, identity, network_namespace)
            .await
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
    MismatchedNetworkNamespace,
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("spawn".into());
        if matches!(self.fault, SpawnFault::Spawn) {
            return Err(SandboxError::Backend("injected spawn failure".into()));
        }
        *self.alive.lock().expect("alive lock should work") = true;
        prepared_child(match self.fault {
            SpawnFault::InvalidIdentity => ChildIdentity::new(4242, 0),
            SpawnFault::MismatchedIdentity => ChildIdentity::new(4242, 991),
            SpawnFault::MismatchedNetworkNamespace => ChildIdentity::new(4242, 991),
            SpawnFault::GateRelease => ChildIdentity::new(4242, 991),
            SpawnFault::Spawn => unreachable!("spawn fault returned above"),
        })
    }

    async fn network_namespace_matches(
        &self,
        _backend_token: &str,
        _identity: ChildIdentity,
        _network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("netns:revalidate".into());
        Ok(!matches!(
            self.fault,
            SpawnFault::MismatchedNetworkNamespace
        ))
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
    ) -> Result<PreparedLinuxChild, SandboxError> {
        self.inner.spawn_prepared(backend_token, request).await
    }

    async fn network_namespace_matches(
        &self,
        backend_token: &str,
        identity: ChildIdentity,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<bool, SandboxError> {
        self.inner
            .network_namespace_matches(backend_token, identity, network_namespace)
            .await
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
    state: Arc<Mutex<FakeEgressState>>,
    attached_descriptors: Arc<Mutex<HashMap<ShardEgressReservation, i32>>>,
    fail_prepare: bool,
    fail_revoke: bool,
    fail_revoke_once: Arc<AtomicUsize>,
    fail_release_once: Arc<AtomicUsize>,
    prepare_pause: Option<AsyncPause>,
    prepare_linearization_pause: Option<AsyncPause>,
    attach_commit_pause: Option<AsyncPause>,
    revoke_pause: Option<AsyncPause>,
    release_pause: Option<AsyncPause>,
    cancel_commit_pause: Option<AsyncPause>,
    release_reservation_commit_pause: Option<AsyncPause>,
    renew_commit_pause: Option<AsyncPause>,
    revoke_commit_pause: Option<AsyncPause>,
    release_commit_pause: Option<AsyncPause>,
    force_inactive: bool,
    omit_proxy_address: bool,
}

#[derive(Default)]
struct FakeEgressState {
    routes: HashMap<ShardEgressReservation, FakeRouteLifecycle>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FakeIngressAttachment {
    network_namespace: NetworkNamespaceIdentity,
    receipt: ShardIngressReceipt,
}

impl FakeIngressAttachment {
    fn from_lease(lease: &ShardIngressLease) -> Self {
        Self {
            network_namespace: lease.namespace_identity(),
            receipt: lease.receipt().clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FakeRouteLifecycle {
    Prepared(Option<FakeIngressAttachment>),
    Cancelled,
    ReservationReleased,
    Revoked(FakeIngressAttachment),
    LeaseReleased(FakeIngressAttachment),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EgressCall {
    Prepare(ShardEgressReservation),
    Attach(
        ShardEgressReservation,
        NetworkNamespaceIdentity,
        ShardIngressReceipt,
    ),
    CancelReservation(ShardEgressReservation),
    ReleaseReservation(ShardEgressReservation),
    Renew(ShardIngressLease, Duration),
    Revoke(ShardIngressLease),
    Release(ShardIngressLease),
    IsActive(ShardIngressLease),
    RetireShard(browserd_core::ShardFence),
}

#[async_trait]
impl EgressRouteBackend for FakeEgress {
    async fn retire_shard(&self, fence: &browserd_core::ShardFence) -> Result<(), SandboxError> {
        let state = self.state.lock().expect("route state");
        if state.routes.iter().any(|(reservation, state)| {
            reservation
                .egress_fence()
                .is_some_and(|route| route.shard() == fence)
                && !matches!(
                    state,
                    FakeRouteLifecycle::ReservationReleased | FakeRouteLifecycle::LeaseReleased(_)
                )
        }) {
            return Err(SandboxError::InvalidEgressLease);
        }
        self.calls
            .lock()
            .expect("calls")
            .push(EgressCall::RetireShard(fence.clone()));
        Ok(())
    }

    async fn prepare(&self, reservation: &ShardEgressReservation) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:prepare".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Prepare(reservation.clone()));
        if let Some(pause) = &self.prepare_linearization_pause {
            pause.pause_once().await;
        }
        {
            let mut state = self.state.lock().expect("route state lock should work");
            match state.routes.get(reservation) {
                None => {
                    state
                        .routes
                        .insert(reservation.clone(), FakeRouteLifecycle::Prepared(None));
                }
                Some(FakeRouteLifecycle::Prepared(_)) => {}
                Some(_) => {
                    return Err(SandboxError::Backend(
                        "route reservation is permanently terminal".into(),
                    ));
                }
            }
        }
        if self.fail_prepare {
            return Err(SandboxError::Backend("route unavailable".into()));
        }
        if let Some(pause) = &self.prepare_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn attach(
        &self,
        reservation: &ShardEgressReservation,
        network_namespace: &PinnedNetworkNamespace,
    ) -> Result<ShardIngressReceipt, SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:attach".into());
        let namespace_identity = network_namespace.identity();
        let receipt = {
            let mut state = self.state.lock().expect("route state lock should work");
            let route = state
                .routes
                .get_mut(reservation)
                .ok_or_else(|| SandboxError::Backend("route reservation missing".into()))?;
            match route {
                FakeRouteLifecycle::Prepared(attachment @ None) => {
                    let receipt = if self.omit_proxy_address {
                        ShardIngressReceipt::new()
                    } else {
                        ShardIngressReceipt::with_proxy_address(
                            "127.0.0.1:43117"
                                .parse()
                                .expect("fixed test listener endpoint"),
                        )?
                    };
                    *attachment = Some(FakeIngressAttachment {
                        network_namespace: namespace_identity,
                        receipt: receipt.clone(),
                    });
                    receipt
                }
                FakeRouteLifecycle::Prepared(Some(attachment))
                    if attachment.network_namespace == namespace_identity =>
                {
                    attachment.receipt.clone()
                }
                FakeRouteLifecycle::Prepared(Some(_)) => {
                    return Err(SandboxError::Backend(
                        "route reservation namespace mismatch".into(),
                    ));
                }
                _ => {
                    return Err(SandboxError::Backend(
                        "route reservation is permanently terminal".into(),
                    ));
                }
            }
        };
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Attach(
                reservation.clone(),
                namespace_identity,
                receipt.clone(),
            ));
        self.attached_descriptors
            .lock()
            .expect("attached descriptor lock should work")
            .insert(reservation.clone(), network_namespace.as_fd().as_raw_fd());
        if let Some(pause) = &self.attach_commit_pause {
            pause.pause_once().await;
        }
        Ok(receipt)
    }

    async fn cancel_reservation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:cancel-reservation".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::CancelReservation(reservation.clone()));
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
        let committed = {
            let mut state = self.state.lock().expect("route state lock should work");
            match state.routes.get(reservation) {
                None | Some(FakeRouteLifecycle::Prepared(_)) => {
                    state
                        .routes
                        .insert(reservation.clone(), FakeRouteLifecycle::Cancelled);
                    true
                }
                Some(FakeRouteLifecycle::Cancelled | FakeRouteLifecycle::ReservationReleased) => {
                    false
                }
                Some(FakeRouteLifecycle::Revoked(_) | FakeRouteLifecycle::LeaseReleased(_)) => {
                    return Err(SandboxError::Backend(
                        "route reservation belongs to an ingress lease".into(),
                    ));
                }
            }
        };
        if committed && let Some(pause) = &self.cancel_commit_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn release_reservation(
        &self,
        reservation: &ShardEgressReservation,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:release-reservation".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::ReleaseReservation(reservation.clone()));
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
        let committed = {
            let mut state = self.state.lock().expect("route state lock should work");
            match state.routes.get(reservation) {
                Some(FakeRouteLifecycle::Cancelled) => {
                    state
                        .routes
                        .insert(reservation.clone(), FakeRouteLifecycle::ReservationReleased);
                    true
                }
                Some(FakeRouteLifecycle::ReservationReleased) => false,
                Some(_) | None => {
                    return Err(SandboxError::Backend(
                        "route reservation was not cancelled".into(),
                    ));
                }
            }
        };
        if committed && let Some(pause) = &self.release_reservation_commit_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn renew(
        &self,
        lease: &ShardIngressLease,
        lease_ttl: Duration,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:renew".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Renew(lease.clone(), lease_ttl));
        if lease_ttl.is_zero() {
            return Err(SandboxError::InvalidEgressLease);
        }
        let expected = FakeIngressAttachment::from_lease(lease);
        match self
            .state
            .lock()
            .expect("route state lock should work")
            .routes
            .get(lease.reservation())
        {
            Some(FakeRouteLifecycle::Prepared(Some(attachment))) if *attachment == expected => {}
            Some(_) | None => {
                return Err(SandboxError::Backend(
                    "active ingress lease receipt mismatch".into(),
                ));
            }
        }
        if let Some(pause) = &self.renew_commit_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn revoke(&self, lease: &ShardIngressLease) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:revoke".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Revoke(lease.clone()));
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
        let expected = FakeIngressAttachment::from_lease(lease);
        let committed = {
            let mut state = self.state.lock().expect("route state lock should work");
            match state.routes.get(lease.reservation()).cloned() {
                Some(FakeRouteLifecycle::Prepared(Some(attachment))) if attachment == expected => {
                    state.routes.insert(
                        lease.reservation().clone(),
                        FakeRouteLifecycle::Revoked(attachment),
                    );
                    true
                }
                Some(
                    FakeRouteLifecycle::Revoked(attachment)
                    | FakeRouteLifecycle::LeaseReleased(attachment),
                ) if attachment == expected => false,
                Some(_) | None => {
                    return Err(SandboxError::Backend(
                        "active ingress lease receipt mismatch".into(),
                    ));
                }
            }
        };
        if committed && let Some(pause) = &self.revoke_commit_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn release(&self, lease: &ShardIngressLease) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:release".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::Release(lease.clone()));
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
        let expected = FakeIngressAttachment::from_lease(lease);
        let committed = {
            let mut state = self.state.lock().expect("route state lock should work");
            match state.routes.get(lease.reservation()).cloned() {
                Some(FakeRouteLifecycle::Revoked(attachment)) if attachment == expected => {
                    state.routes.insert(
                        lease.reservation().clone(),
                        FakeRouteLifecycle::LeaseReleased(attachment),
                    );
                    true
                }
                Some(FakeRouteLifecycle::LeaseReleased(attachment)) if attachment == expected => {
                    false
                }
                Some(_) | None => {
                    return Err(SandboxError::Backend(
                        "revoked ingress lease receipt mismatch".into(),
                    ));
                }
            }
        };
        if committed && let Some(pause) = &self.release_commit_pause {
            pause.pause_once().await;
        }
        Ok(())
    }

    async fn is_active(&self, lease: &ShardIngressLease) -> Result<bool, SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:is-active".into());
        self.calls
            .lock()
            .expect("egress call lock should work")
            .push(EgressCall::IsActive(lease.clone()));
        Ok(!self.force_inactive
            && matches!(
                self.state
                    .lock()
                    .expect("route state lock should work")
                    .routes
                    .get(lease.reservation()),
                Some(FakeRouteLifecycle::Prepared(Some(attachment)))
                    if attachment == &FakeIngressAttachment::from_lease(lease)
            ))
    }
}

fn config() -> LinuxSandboxConfig {
    config_for_executable("/opt/browser/chrome")
}

fn config_for_executable(executable: &str) -> LinuxSandboxConfig {
    config_for_runtime_paths(executable, "/opt/browser/browserd-launch-gate")
}

fn config_for_runtime_paths(executable: &str, gate: &str) -> LinuxSandboxConfig {
    LinuxSandboxConfig::new(
        "/sys/fs/cgroup/browserd",
        "/var/lib/browserd/shards",
        "/usr/bin/bwrap",
        chromium_runtime(executable),
        LaunchGateRuntime::new("/usr/libexec/browserd-launch-gate", gate),
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

fn config_with_resource_mounts(
    executable: &str,
    mounts: impl IntoIterator<Item = ReadOnlyMount>,
) -> Result<LinuxSandboxConfig, SandboxError> {
    LinuxSandboxConfig::new(
        "/sys/fs/cgroup/browserd",
        "/var/lib/browserd/shards",
        "/usr/bin/bwrap",
        chromium_runtime(executable),
        LaunchGateRuntime::new("/usr/libexec/browserd-launch-gate", "/browserd/launch-gate"),
        mounts,
        CgroupLimits::new(512 << 20, 384 << 20, 256, 100_000, 100_000).expect("resource limits"),
        9,
        Duration::from_millis(100),
        Duration::from_millis(10),
    )
}

#[test]
fn chromium_parent_resources_precede_pinned_executable_gate_and_native_overlays() {
    use browserd_sandbox::{ChromiumProcessProfile, NativeProcessResources};

    let directory = tempfile::tempdir().expect("native resource fixture directory");
    let icu = directory.path().join("icudtl.dat");
    let pak = directory.path().join("ko.pak");
    std::fs::write(&icu, b"approved ICU").expect("ICU fixture");
    std::fs::write(&pak, b"approved locale").expect("locale fixture");
    let catalog_digest = chromium_digest(b"approved catalog");
    let resources = NativeProcessResources::new(
        chromium_digest(TEST_CHROMIUM_BYTES),
        catalog_digest,
        &icu,
        chromium_digest(b"approved ICU"),
        vec![(
            "ko-KR".to_owned(),
            pak.clone(),
            chromium_digest(b"approved locale"),
        )],
        vec!["Asia/Seoul".to_owned()],
    )
    .expect("pin native resources");
    let config = config_with_resource_mounts(
        "/browserd-chromium/chromium",
        [
            ReadOnlyMount::new("/opt/chromium", "/browserd-chromium"),
            ReadOnlyMount::new("/opt/runtime", "/opt/runtime"),
        ],
    )
    .expect("exact parent runtime directory")
    .with_native_profiles(resources.clone())
    .expect("parent resources can be overlaid by pinned native data");
    std::fs::write(&icu, b"changed source ICU").expect("change original ICU");
    std::fs::write(&pak, b"changed source locale").expect("change original locale");
    let filesystem = FakeFilesystem::production_tree();
    filesystem
        .unwritable
        .lock()
        .expect("immutable parent fixture")
        .insert("/opt/chromium".into());
    filesystem
        .directories
        .lock()
        .expect("resource directories")
        .insert("/opt/chromium/locales".into());
    for resource in [
        "chromium",
        "icudtl.dat",
        "headless_lib_data.pak",
        "v8_context_snapshot.bin",
    ] {
        filesystem.files.lock().expect("resource files").insert(
            Path::new("/opt/chromium").join(resource),
            "baseline resource".into(),
        );
    }
    let backend = LinuxSandboxBackend::new(
        config,
        filesystem,
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    for native in [false, true] {
        let base = launch_spec(ShardId::new());
        let spec = if native {
            base.with_process_profile(
                ChromiumProcessProfile::native_locale(
                    "ko-KR",
                    "Asia/Seoul",
                    catalog_digest,
                    chromium_digest(b"approved locale"),
                    chromium_digest(b"approved ICU"),
                )
                .expect("native profile"),
            )
            .expect("bind native profile")
        } else {
            base
        };
        let request = backend
            .planned_spawn_request(&spec)
            .expect("ordered resource launch");
        let args = request.arguments();
        assert!(
            !args
                .windows(3)
                .any(|window| window == ["--ro-bind", "/opt/chromium", "/browserd-chromium"])
        );
        assert!(!args.windows(3).any(|window| window
            == [
                "--ro-bind",
                "/opt/chromium/chromium",
                "/browserd-chromium/chromium"
            ]));
        let mount = args
            .windows(3)
            .position(|window| {
                window
                    == [
                        "--ro-bind",
                        "/opt/chromium/icudtl.dat",
                        "/browserd-chromium/icudtl.dat",
                    ]
            })
            .expect("baseline ICU projection");
        let locale_mount = args
            .windows(3)
            .position(|window| {
                window
                    == [
                        "--ro-bind",
                        "/opt/chromium/locales",
                        "/browserd-chromium/locales",
                    ]
            })
            .expect("baseline locales projection");
        let other_mount = args
            .windows(3)
            .position(|window| window == ["--ro-bind", "/opt/runtime", "/opt/runtime"])
            .expect("other runtime mount");
        let executable = args
            .windows(3)
            .position(|window| window[0] == "--file" && window[2] == "/browserd-chromium/chromium")
            .expect("named executable copy from sealed capability");
        let gate = args
            .windows(3)
            .position(|window| {
                window
                    == [
                        "--ro-bind",
                        "/usr/libexec/browserd-launch-gate",
                        "/browserd/launch-gate",
                    ]
            })
            .expect("trusted gate overlay");
        assert!(
            mount < executable
                && locale_mount < executable
                && other_mount < executable
                && executable < gate
        );
        let root_read_only = args
            .windows(2)
            .position(|window| window == ["--remount-ro", "/"])
            .expect("private guest root becomes immutable");
        let seccomp = args
            .iter()
            .position(|arg| arg == "--seccomp")
            .expect("seccomp admission");
        assert!(gate < root_read_only && root_read_only < seccomp);
        assert_eq!(
            args.windows(2)
                .filter(|window| *window == ["--remount-ro", "/"])
                .count(),
            1
        );
        let executable_fd = args[executable + 1]
            .to_str()
            .expect("executable FD")
            .parse::<i32>()
            .expect("numeric executable FD");
        assert_eq!(executable_fd, request.chromium_executable_fd().as_raw_fd());
        assert!(request.inherited_fds().contains(&executable_fd));
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{executable_fd}")).expect("pinned Chromium bytes"),
            TEST_CHROMIUM_BYTES
        );
        let seals = nix::fcntl::fcntl(
            request.chromium_executable_fd(),
            nix::fcntl::FcntlArg::F_GET_SEALS,
        )
        .expect("executable seals");
        assert!(nix::fcntl::SealFlag::from_bits_truncate(seals).contains(
            nix::fcntl::SealFlag::F_SEAL_WRITE
                | nix::fcntl::SealFlag::F_SEAL_GROW
                | nix::fcntl::SealFlag::F_SEAL_SHRINK
                | nix::fcntl::SealFlag::F_SEAL_SEAL
        ));
        for (destination, expected) in [
            ("/browserd-chromium/icudtl.dat", b"approved ICU".as_slice()),
            (
                "/browserd-chromium/locales/ko-KR.pak",
                b"approved locale".as_slice(),
            ),
        ] {
            let overlay = args
                .windows(3)
                .position(|window| window[0] == "--ro-bind-data" && window[2] == destination);
            if native {
                let overlay = overlay.expect("native resource overlay");
                assert!(
                    gate < overlay && overlay < root_read_only,
                    "native data must follow every runtime/executable/gate bind"
                );
                let descriptor = args[overlay + 1]
                    .to_str()
                    .expect("resource FD")
                    .parse::<i32>()
                    .expect("numeric resource FD");
                assert!(request.inherited_fds().contains(&descriptor));
                assert_eq!(
                    std::fs::read(format!("/proc/self/fd/{descriptor}"))
                        .expect("pinned native bytes"),
                    expected
                );
            } else {
                assert!(
                    overlay.is_none(),
                    "baseline uses the approved parent directory resources"
                );
            }
        }
    }
    for destination in [
        "/browserd-chromium/icudtl.dat",
        "/browserd-chromium/locales",
        "/browserd-chromium/locales/ko-KR.pak",
    ] {
        assert!(
            config_with_resource_mounts(
                "/browserd-chromium/chromium",
                [ReadOnlyMount::new("/opt/runtime", destination)]
            )
            .expect("sibling mount has no executable overlap")
            .with_native_profiles(resources.clone())
            .is_err(),
            "individual native resource overlaps remain forbidden: {destination}"
        );
    }
}

#[test]
fn chromium_resource_mount_accepts_only_the_exact_private_executable_parent() {
    for destination in [
        "/",
        "/browserd-chromium",
        "/browserd-chromium/nested/chromium",
        "/browserd-chromium/nested/chromium/child",
        "/browserd",
        "/browserd/launch-gate",
    ] {
        assert!(
            config_with_resource_mounts(
                "/browserd-chromium/nested/chromium",
                [ReadOnlyMount::new("/opt/chromium", destination)]
            )
            .is_err(),
            "broader ancestors and executable/gate overlaps stay forbidden: {destination}"
        );
    }
    assert!(
        config_with_resource_mounts(
            "/browserd-chromium/nested/chromium",
            [ReadOnlyMount::new(
                "/opt/chromium",
                "/browserd-chromium/nested"
            )]
        )
        .is_ok()
    );
    for source in [
        "/tmp/resources",
        "/dev/shm/resources",
        "/var/lib/browserd/shards/resources",
        "/sys/fs/cgroup/browserd/resources",
    ] {
        assert!(
            config_with_resource_mounts(
                "/browserd-chromium/chromium",
                [ReadOnlyMount::new(source, "/browserd-chromium")]
            )
            .is_err(),
            "mutable launch state cannot supply executable-parent resources: {source}"
        );
    }
}

#[test]
fn named_chromium_executable_cannot_be_materialized_in_a_writable_or_virtual_mount() {
    for executable in [
        "/proc/chromium",
        "/dev/chromium",
        "/dev/shm/chromium",
        "/sys/chromium",
        "/tmp/chromium",
        "/profile/chromium",
        "/profile/browserd-files/chromium",
    ] {
        assert!(
            config_with_resource_mounts(executable, []).is_err(),
            "named executable must be protected by the guest root remount: {executable}"
        );
    }
}

#[test]
fn production_directory_projection_requires_root_owned_immutable_non_symlink_source() {
    let directory = tempfile::tempdir().expect("directory projection fixture");
    let source = directory.path().join("resources");
    std::fs::create_dir(&source).expect("runtime source fixture");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
        .expect("writable source mode");
    let filesystem =
        StdSandboxFilesystem::new("/sys/fs/cgroup/browserd", "/var/lib/browserd/shards")
            .expect("filesystem configuration");
    assert!(
        filesystem.read_directory(&source).is_err(),
        "writable directories cannot supply the projection"
    );
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&source, &alias).expect("source symlink fixture");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o555))
        .expect("immutable source mode");
    assert!(
        filesystem.read_directory(&alias).is_err(),
        "symlinked sources cannot supply the projection"
    );
    if !nix::unistd::geteuid().is_root() {
        assert!(
            filesystem.read_directory(&source).is_err(),
            "a non-root owner can change permissions and must be rejected"
        );
    }
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
        .expect("restore fixture for cleanup");
}

#[tokio::test]
async fn chromium_parent_runtime_requires_an_immutable_directory_before_any_effect() {
    for kind in ["writable", "file", "symlink"] {
        let filesystem = FakeFilesystem::production_tree();
        if kind == "file" {
            filesystem
                .directories
                .lock()
                .expect("directory fixtures")
                .remove(Path::new("/opt/chromium"));
            filesystem
                .files
                .lock()
                .expect("file fixtures")
                .insert(PathBuf::from("/opt/chromium"), String::new());
        } else if kind == "symlink" {
            filesystem
                .symlinks
                .lock()
                .expect("symlink fixtures")
                .insert(PathBuf::from("/opt/chromium"));
        }
        let process_events = Arc::new(Mutex::new(Vec::new()));
        let egress = FakeEgress::default();
        let backend = LinuxSandboxBackend::new(
            config_with_resource_mounts(
                "/browserd-chromium/chromium",
                [ReadOnlyMount::new("/opt/chromium", "/browserd-chromium")],
            )
            .expect("parent mount configuration"),
            filesystem.clone(),
            FakeProcess {
                events: process_events.clone(),
                alive: Arc::new(Mutex::new(false)),
                identity_matches: true,
            },
            egress.clone(),
        );
        assert!(
            backend
                .provision_gated(&launch_spec(ShardId::new()))
                .await
                .is_err(),
            "unsafe source kind: {kind}"
        );
        assert!(filesystem.events().is_empty());
        assert!(process_events.lock().expect("process events").is_empty());
        assert!(egress.events.lock().expect("egress events").is_empty());
    }
}

#[tokio::test]
async fn chromium_parent_projection_rejects_symlink_special_and_escaped_entries_before_any_effect()
{
    for kind in ["symlink", "special", "escaped", "too_many"] {
        let filesystem = FakeFilesystem::production_tree();
        filesystem
            .unwritable
            .lock()
            .expect("immutable source")
            .insert("/opt/chromium".into());
        let child = PathBuf::from("/opt/chromium/resource");
        let entries = match kind {
            "escaped" => vec![PathBuf::from("/opt/foreign-resource")],
            "too_many" => (0..4097)
                .map(|index| Path::new("/opt/chromium").join(format!("resource-{index}")))
                .collect(),
            _ => vec![child.clone()],
        };
        if kind == "symlink" {
            filesystem
                .symlinks
                .lock()
                .expect("symlink entry")
                .insert(child);
        }
        *filesystem
            .directory_entries_override
            .lock()
            .expect("directory fixture") = Some(entries);
        let process_events = Arc::new(Mutex::new(Vec::new()));
        let egress = FakeEgress::default();
        let backend = LinuxSandboxBackend::new(
            config_with_resource_mounts(
                "/browserd-chromium/chromium",
                [ReadOnlyMount::new("/opt/chromium", "/browserd-chromium")],
            )
            .expect("exact parent configuration"),
            filesystem.clone(),
            FakeProcess {
                events: process_events.clone(),
                alive: Arc::new(Mutex::new(false)),
                identity_matches: true,
            },
            egress.clone(),
        );
        assert!(
            backend
                .provision_gated(&launch_spec(ShardId::new()))
                .await
                .is_err(),
            "unsafe child kind: {kind}"
        );
        assert!(filesystem.events().is_empty());
        assert!(process_events.lock().expect("process effects").is_empty());
        assert!(egress.events.lock().expect("egress effects").is_empty());
    }
}

#[test]
fn native_profile_launch_seals_resources_and_clears_ambient_environment() {
    use browserd_sandbox::{ChromiumProcessProfile, NativeProcessResources};
    let directory = tempfile::tempdir().expect("resource directory");
    let pak_path = directory.path().join("ko.pak");
    let icu_path = directory.path().join("icudtl.dat");
    std::fs::write(&pak_path, b"approved locale data").expect("pak fixture");
    std::fs::write(&icu_path, b"approved ICU data").expect("ICU fixture");
    let pak_digest = chromium_digest(b"approved locale data");
    let icu_digest = chromium_digest(b"approved ICU data");
    let catalog_digest = chromium_digest(b"approved catalog");
    let resources = NativeProcessResources::new(
        chromium_digest(TEST_CHROMIUM_BYTES),
        catalog_digest,
        &icu_path,
        icu_digest,
        vec![("ko-KR".to_owned(), pak_path.clone(), pak_digest)],
        vec!["Asia/Seoul".to_owned()],
    )
    .expect("approved resources");
    for executable in ["/opt/browser/locales", "/opt/browser/icudtl.dat"] {
        assert!(
            config_for_executable(executable)
                .with_native_profiles(resources.clone())
                .is_err(),
            "resource overlays must not replace the executable"
        );
    }
    assert!(
        config_for_runtime_paths("/opt/browser/chrome", "/opt/browser/icudtl.dat/gate")
            .with_native_profiles(resources.clone())
            .is_err(),
        "resource overlays must not collide with the launch gate"
    );
    // Launch must use the sealed snapshot even if the source changes later.
    std::fs::write(&pak_path, b"replaced locale data").expect("replace source");
    std::fs::write(&icu_path, b"replaced ICU data").expect("replace source");
    let config = config()
        .with_native_profiles(resources)
        .expect("native configuration");
    let backend = LinuxSandboxBackend::new(
        config,
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let profile = ChromiumProcessProfile::native_locale(
        "ko-KR",
        "Asia/Seoul",
        catalog_digest,
        pak_digest,
        icu_digest,
    )
    .expect("profile")
    .with_user_agent(Some("browserd-native-workers/1.0".to_owned()))
    .expect("immutable UA");
    let spec = launch_spec(ShardId::new())
        .with_process_profile(profile)
        .expect("native launch");
    let request = backend
        .planned_spawn_request(&spec)
        .expect("native launch plan");
    let args = request.arguments();
    assert!(args.iter().any(|arg| arg == "--clearenv"));
    for (key, value) in [
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("LANGUAGE", "ko-KR"),
        ("TZ", "Asia/Seoul"),
    ] {
        assert!(
            args.windows(3)
                .any(|window| window == ["--setenv", key, value])
        );
    }
    assert!(
        args.windows(2)
            .any(|window| window == ["--remount-ro", "/opt/browser/locales"])
    );
    for (destination, expected) in [
        (
            "/opt/browser/locales/ko-KR.pak",
            b"approved locale data".as_slice(),
        ),
        ("/opt/browser/icudtl.dat", b"approved ICU data".as_slice()),
    ] {
        let window = args
            .windows(3)
            .find(|window| window[0] == "--ro-bind-data" && window[2] == destination)
            .expect("sealed resource overlay");
        let fd: i32 = window[1]
            .to_str()
            .expect("FD string")
            .parse()
            .expect("FD number");
        assert!(request.inherited_fds().contains(&fd));
        let bytes = std::fs::read(format!("/proc/self/fd/{fd}")).expect("sealed resource read");
        assert_eq!(bytes, expected);
    }
    assert!(args.iter().any(|arg| arg == "--lang=ko-KR"));
    assert!(args.iter().any(|arg| arg == "--accept-lang=ko-KR"));
    assert!(
        args.iter()
            .any(|arg| arg == "--user-agent=browserd-native-workers/1.0")
    );
}

#[tokio::test]
async fn native_profile_without_approved_resources_has_no_provisioning_effects() {
    use browserd_sandbox::ChromiumProcessProfile;
    let filesystem = FakeFilesystem::production_tree();
    let backend = backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let digest = chromium_digest(b"unavailable resource");
    let profile =
        ChromiumProcessProfile::native_locale("ko-KR", "Asia/Seoul", digest, digest, digest)
            .expect("valid profile");
    let spec = launch_spec(ShardId::new())
        .with_process_profile(profile)
        .expect("native launch");
    let before = filesystem.events();
    assert!(backend.provision_gated(&spec).await.is_err());
    assert_eq!(filesystem.events(), before);
}

#[test]
fn native_resources_reject_changed_digest_and_symlink_sources() {
    use browserd_sandbox::NativeProcessResources;
    let directory = tempfile::tempdir().expect("resource directory");
    let icu = directory.path().join("icudtl.dat");
    let pak = directory.path().join("ko.pak");
    let alias = directory.path().join("alias.pak");
    std::fs::write(&icu, b"ICU").expect("ICU fixture");
    std::fs::write(&pak, b"pak").expect("pak fixture");
    std::os::unix::fs::symlink(&pak, &alias).expect("symlink fixture");
    let build = |source: PathBuf, digest| {
        NativeProcessResources::new(
            chromium_digest(TEST_CHROMIUM_BYTES),
            chromium_digest(b"catalog"),
            &icu,
            chromium_digest(b"ICU"),
            vec![("ko-KR".to_owned(), source, digest)],
            vec!["Asia/Seoul".to_owned()],
        )
    };
    assert!(build(pak, chromium_digest(b"wrong bytes")).is_err());
    assert!(build(alias, chromium_digest(b"pak")).is_err());
}

#[test]
fn browser_file_launch_has_private_bounded_tmpfs_and_requires_gate_export() {
    let backend = LinuxSandboxBackend::new(
        config().with_browser_files(),
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let request = backend
        .planned_spawn_request(&launch_spec(ShardId::new()))
        .expect("browser-file launch should be valid");
    let arguments = request.arguments();
    for key in ["LANG", "LC_ALL"] {
        assert!(
            arguments
                .windows(3)
                .any(|window| window == ["--setenv", key, "C.UTF-8"])
        );
    }
    assert!(arguments.windows(6).any(|window| window
        == [
            "--perms",
            "0700",
            "--size",
            "33554432",
            "--tmpfs",
            "/profile/browserd-files"
        ]));
    assert!(arguments.windows(3).any(|window| window
        == [
            "/opt/browser/browserd-launch-gate",
            "--export-scratch",
            "--"
        ]));
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
    let request = backend
        .planned_spawn_request(&launch_spec(ShardId::new()))
        .expect("sealed Chromium launch capability should be available");
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
    let executable_fd = request.chromium_executable_fd().as_raw_fd();
    assert!(arguments.windows(5).any(|window| {
        window[0] == "--perms"
            && window[1] == "0555"
            && window[2] == "--file"
            && window[3]
                .to_str()
                .and_then(|descriptor| descriptor.parse::<i32>().ok())
                == Some(executable_fd)
            && window[4] == "/opt/browser/chrome"
    }));
    assert!(request.inherited_fds().contains(&executable_fd));
    assert!(![CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD].contains(&executable_fd));
    assert!(
        !arguments
            .iter()
            .any(|argument| argument == "/opt/chromium/chrome"),
        "the mutable host path must not be re-resolved during launch",
    );
    assert_eq!(
        arguments
            .iter()
            .rev()
            .take(8)
            .rev()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [
            "/opt/browser/browserd-launch-gate",
            "--",
            "/opt/browser/chrome",
            "--remote-debugging-pipe",
            "--headless",
            "--no-startup-window",
            "--user-data-dir=/profile",
            "--disable-features=BackForwardCache",
        ]
    );
    assert!(
        arguments.iter().any(|argument| argument == "--headless"),
        "the production launch profile must explicitly select Chromium headless mode"
    );
    assert!(
        arguments
            .iter()
            .any(|argument| argument == "--no-startup-window"),
        "the production launch profile must suppress automatic browser windows and tabs"
    );
    assert!(
        arguments
            .iter()
            .all(|argument| argument != "test-public-web"),
        "tenant policy profile data must not become a Chromium argument"
    );
    assert!(!arguments.iter().any(|argument| argument == "--block-fd"));
}

#[test]
fn chromium_runtime_pins_the_verified_bytes_in_a_sealed_executable() {
    let temporary = tempfile::tempdir().expect("temporary directory should be created");
    let source = temporary.path().join("chrome");
    let approved_bytes = b"approved Chromium bytes";
    std::fs::write(&source, approved_bytes).expect("Chromium source should be written");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
        .expect("Chromium source should be executable");
    let runtime = ChromiumRuntime::from_path(
        &source,
        "/opt/browser/chrome",
        chromium_digest(approved_bytes),
    )
    .expect("verified Chromium source should be pinned");

    std::fs::write(&source, b"mutated Chromium bytes")
        .expect("the original source path should remain independently mutable");
    let base_spec = launch_spec(ShardId::new());
    let approved_spec = LaunchSpec::production(
        base_spec.tenant_id().clone(),
        base_spec.dedicated_egress().clone(),
        chromium_digest(approved_bytes),
    );
    let request = LinuxSandboxBackend::new(
        LinuxSandboxConfig::new(
            "/sys/fs/cgroup/browserd",
            "/var/lib/browserd/shards",
            "/usr/bin/bwrap",
            runtime,
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
        .expect("configuration should be valid"),
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    )
    .planned_spawn_request(&approved_spec)
    .expect("sealed Chromium launch capability should be available");
    let executable = request.chromium_executable_fd();
    let descriptor_flags = nix::fcntl::fcntl(executable, nix::fcntl::FcntlArg::F_GETFD)
        .expect("Chromium executable descriptor flags should be readable");
    assert!(
        nix::fcntl::FdFlag::from_bits_truncate(descriptor_flags)
            .contains(nix::fcntl::FdFlag::FD_CLOEXEC),
        "the parent capability must not leak through a concurrent unrelated spawn",
    );
    let metadata =
        nix::sys::stat::fstat(executable).expect("Chromium executable metadata should be readable");
    assert_eq!(metadata.st_mode & 0o555, 0o555);
    let seals = nix::fcntl::fcntl(executable, nix::fcntl::FcntlArg::F_GET_SEALS)
        .expect("Chromium executable seals should be readable");
    let seals = nix::fcntl::SealFlag::from_bits_truncate(seals);
    assert!(seals.contains(
        nix::fcntl::SealFlag::F_SEAL_WRITE
            | nix::fcntl::SealFlag::F_SEAL_GROW
            | nix::fcntl::SealFlag::F_SEAL_SHRINK
            | nix::fcntl::SealFlag::F_SEAL_SEAL
    ));

    let duplicate = nix::fcntl::fcntl(executable, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(128))
        .expect("sealed executable should be duplicable");
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this test.
    let mut pinned = unsafe { File::from_raw_fd(duplicate) };
    pinned
        .seek(SeekFrom::Start(0))
        .expect("pinned executable should seek");
    let mut bytes = Vec::new();
    pinned
        .read_to_end(&mut bytes)
        .expect("pinned executable should remain readable");
    assert_eq!(bytes, approved_bytes);
}

#[test]
fn chromium_runtime_rejects_a_mismatched_or_symlinked_source() {
    let temporary = tempfile::tempdir().expect("temporary directory should be created");
    let source = temporary.path().join("chrome");
    std::fs::write(&source, b"approved Chromium bytes").expect("Chromium source should be written");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
        .expect("Chromium source should be executable");
    assert!(
        ChromiumRuntime::from_path(
            &source,
            "/opt/browser/chrome",
            ChromiumBinaryDigest::new([0x7d; 32]),
        )
        .is_err()
    );

    let symlink = temporary.path().join("chrome-link");
    std::os::unix::fs::symlink(&source, &symlink).expect("test symlink should be created");
    assert!(
        ChromiumRuntime::from_path(
            symlink,
            "/opt/browser/chrome",
            chromium_digest(b"approved Chromium bytes"),
        )
        .is_err()
    );
}

#[test]
fn concurrent_launch_requests_own_independent_chromium_readers() {
    let backend = backend(
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            backend
                .planned_spawn_request(&launch_spec(ShardId::new()))
                .expect("first launch capability should be available")
        });
        let second = scope.spawn(|| {
            backend
                .planned_spawn_request(&launch_spec(ShardId::new()))
                .expect("second launch capability should be available")
        });
        (
            first.join().expect("first planner should not panic"),
            second.join().expect("second planner should not panic"),
        )
    });
    assert_ne!(
        first.chromium_executable_fd().as_raw_fd(),
        second.chromium_executable_fd().as_raw_fd(),
    );
    nix::unistd::lseek(
        first.chromium_executable_fd(),
        7,
        nix::unistd::Whence::SeekSet,
    )
    .expect("first launch reader should seek independently");

    let duplicate = nix::fcntl::fcntl(
        second.chromium_executable_fd(),
        nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(128),
    )
    .expect("second launch reader should duplicate");
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this test.
    let mut second_reader = unsafe { File::from_raw_fd(duplicate) };
    let mut bytes = Vec::new();
    second_reader
        .read_to_end(&mut bytes)
        .expect("second reader should remain at its independent initial offset");
    assert_eq!(bytes, TEST_CHROMIUM_BYTES);
}

#[tokio::test]
async fn chromium_digest_mismatch_fails_before_any_sandbox_effect() {
    let filesystem = FakeFilesystem::production_tree();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let egress = FakeEgress::default();
    let valid = launch_spec(ShardId::new());
    let mismatched = LaunchSpec::production(
        valid.tenant_id().clone(),
        valid.dedicated_egress().clone(),
        ChromiumBinaryDigest::new([0x7d; 32]),
    );
    let backend = backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::clone(&process_events),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        egress.clone(),
    );
    assert!(matches!(
        backend.planned_spawn_request(&mismatched),
        Err(SandboxError::ChromiumBinaryDigestMismatch)
    ));
    let result = backend.provision(&mismatched).await;

    assert_eq!(result, Err(SandboxError::ChromiumBinaryDigestMismatch));
    assert!(filesystem.events().is_empty());
    assert!(
        process_events
            .lock()
            .expect("process lock should work")
            .is_empty()
    );
    assert!(
        egress
            .events
            .lock()
            .expect("egress lock should work")
            .is_empty()
    );
}

fn launch_spec(shard_id: ShardId) -> LaunchSpec {
    launch_spec_for(
        shard_id,
        WorkerId::new("worker-1").expect("worker should be valid"),
        7,
    )
}

fn launch_spec_for(shard_id: ShardId, worker_id: WorkerId, worker_epoch: u64) -> LaunchSpec {
    launch_spec_for_generation(shard_id, worker_id, worker_epoch, 1)
}

fn launch_spec_for_generation(
    shard_id: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    launch_generation: u64,
) -> LaunchSpec {
    launch_spec_for_generation_and_tenant(
        TenantId::new(),
        shard_id,
        worker_id,
        worker_epoch,
        launch_generation,
    )
}

fn launch_spec_for_generation_and_tenant(
    tenant_id: TenantId,
    shard_id: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    launch_generation: u64,
) -> LaunchSpec {
    let worker_epoch = WorkerEpoch::new(worker_epoch).expect("worker epoch is positive");
    let egress_fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(worker_id, worker_epoch),
            shard_id,
            LaunchGeneration::new(launch_generation).expect("launch generation is positive"),
        ),
        RouteGeneration::new(1).expect("route generation is positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation is positive"),
    );
    let policy_binding =
        EgressPolicyBinding::new("test-public-web", [1; 32]).expect("policy binding is valid");
    let dedicated_egress =
        DedicatedEgressSpec::new(egress_fence, policy_binding, Duration::from_secs(5))
            .expect("dedicated egress spec is valid");
    LaunchSpec::production(
        tenant_id,
        dedicated_egress,
        chromium_digest(TEST_CHROMIUM_BYTES),
    )
}

#[test]
fn route_reservations_for_the_same_shard_epoch_never_alias() {
    let fence = ShardEgressFence::new(ShardId::new(), 7);

    let first = ShardEgressReservation::new(fence.clone());
    let second = ShardEgressReservation::new(fence);

    assert_ne!(first.generation(), second.generation());
}

#[tokio::test]
async fn cancelled_route_generation_cannot_be_reprepared_or_reattached() {
    let egress = FakeEgress::default();
    let reservation = ShardEgressReservation::new(ShardEgressFence::new(ShardId::new(), 7));
    let namespace = current_network_namespace().expect("network namespace should be pinnable");

    egress
        .prepare(&reservation)
        .await
        .expect("reservation should prepare once");
    assert!(
        egress.release_reservation(&reservation).await.is_err(),
        "an active reservation must not be released before permanent cancellation"
    );
    egress
        .cancel_reservation(&reservation)
        .await
        .expect("reservation should cancel");
    egress
        .cancel_reservation(&reservation)
        .await
        .expect("the exact cancellation must be idempotent");

    assert!(egress.prepare(&reservation).await.is_err());
    assert!(egress.attach(&reservation, &namespace).await.is_err());
    egress
        .release_reservation(&reservation)
        .await
        .expect("the cancelled reservation should release");
    egress
        .release_reservation(&reservation)
        .await
        .expect("the exact reservation release must be idempotent");
}

#[tokio::test]
async fn cancellation_wins_a_prepare_race_before_route_state_is_published() {
    let pause = AsyncPause::new();
    let egress = FakeEgress {
        prepare_linearization_pause: Some(pause.clone()),
        ..FakeEgress::default()
    };
    let reservation = ShardEgressReservation::new(ShardEgressFence::new(ShardId::new(), 7));
    let prepare = tokio::spawn({
        let egress = egress.clone();
        let reservation = reservation.clone();
        async move { egress.prepare(&reservation).await }
    });
    pause.entered.notified().await;

    egress
        .cancel_reservation(&reservation)
        .await
        .expect("cancellation should become terminal");
    pause.proceed.notify_one();

    assert!(
        prepare.await.expect("prepare task should join").is_err(),
        "a late prepare completion must not resurrect a terminal route generation"
    );
    assert!(
        !egress
            .state
            .lock()
            .expect("route state lock should work")
            .routes
            .get(&reservation)
            .is_some_and(|route| matches!(route, FakeRouteLifecycle::Prepared(_)))
    );
}

#[tokio::test]
async fn exact_terminal_ingress_operations_remain_idempotent_after_release() {
    let egress = FakeEgress::default();
    let backend = backend(
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        egress.clone(),
    );
    backend
        .provision(&launch_spec(ShardId::new()))
        .await
        .expect("runtime should provision");
    let lease = egress
        .calls
        .lock()
        .expect("egress call lock should work")
        .iter()
        .find_map(|call| match call {
            EgressCall::IsActive(lease) => Some(lease.clone()),
            _ => None,
        })
        .expect("provisioning should validate one exact ingress lease");

    egress
        .revoke(&lease)
        .await
        .expect("the exact lease should revoke");
    egress
        .release(&lease)
        .await
        .expect("the exact revoked lease should release");
    egress
        .revoke(&lease)
        .await
        .expect("the exact revoke must remain successful after release");
    egress
        .release(&lease)
        .await
        .expect("the exact release must remain successful after release");
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
            .state
            .lock()
            .expect("route state lock should work")
            .routes
            .iter()
            .any(|(reservation, route)| {
                reservation.fence().shard_id() == shard_id
                    && matches!(route, FakeRouteLifecycle::Prepared(_))
            })
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

fn run_network_process_helper(test_name: &str) {
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user", "--fork"])
        .arg(std::env::current_exe().expect("test executable should be known"))
        .arg("--ignored")
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env("BROWSERD_PROCESS_HELPER", "1")
        .output()
        .expect("network namespace helper should start");
    assert!(
        output.status.success(),
        "network namespace helper failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn install_required_launch_descriptors() -> OwnedFd {
    let mut policy = tempfile::tempfile().expect("regular seccomp fixture should open");
    let code = u16::try_from(nix::libc::BPF_RET | nix::libc::BPF_K)
        .expect("BPF return opcode")
        .to_ne_bytes();
    let denied = (nix::libc::SECCOMP_RET_ERRNO
        | u32::try_from(nix::libc::EPERM).expect("EPERM operand"))
    .to_ne_bytes();
    policy
        .write_all(&[
            code[0], code[1], 0, 0, denied[0], denied[1], denied[2], denied[3],
        ])
        .expect("deny-only cBPF fixture");
    policy
        .seek(SeekFrom::Start(0))
        .expect("initial seccomp fixture offset");
    let source = policy.as_raw_fd();
    // SAFETY: the helper runs in an isolated subprocess and duplicates one live descriptor only
    // onto the fixed seccomp descriptor used by its SpawnRequest.
    let duplicated = unsafe { nix::libc::dup2(source, 9) };
    assert_eq!(duplicated, 9, "seccomp descriptor should be installed");
    // SAFETY: descriptor 9 was just installed above and F_SETFD with zero only clears CLOEXEC.
    let result = unsafe { nix::libc::fcntl(9, nix::libc::F_SETFD, 0) };
    assert_eq!(result, 0, "seccomp descriptor should be inheritable");
    if source == 9 {
        OwnedFd::from(policy)
    } else {
        drop(policy);
        // SAFETY: dup2 created descriptor 9 above and ownership has not been transferred elsewhere.
        unsafe { OwnedFd::from_raw_fd(9) }
    }
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
            chromium_runtime("/opt/chromium/chrome"),
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
    .planned_spawn_request(&launch_spec(ShardId::new()))
    .expect("sealed Chromium launch capability should be available");
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
    let spec = launch_spec(shard_id.clone());
    let planned = backend
        .planned_spawn_request(&spec)
        .expect("sealed Chromium launch capability should be available");
    assert_eq!(planned.program(), Path::new("/usr/bin/bwrap"));
    backend
        .provision(&spec)
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
            .join(format!("{shard_id}-launch-1"))
            .join("cgroup.procs")
    );
    assert_eq!(
        egress
            .events
            .lock()
            .expect("egress lock should work")
            .as_slice(),
        ["route:prepare", "route:attach", "route:is-active"]
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
        "--file",
        "--seccomp",
    ] {
        assert!(process_events.contains(argument), "missing {argument}");
    }
    assert!(
        !process_events.contains("--preserve-fds"),
        "the pinned bubblewrap CLI has no preserve-fds option"
    );
    assert!(
        !planned
            .arguments()
            .iter()
            .any(|argument| argument == "--rlimit"),
        "resource limits must be installed before exec rather than passed to bubblewrap"
    );
    assert!(!process_events.contains("--no-sandbox"));
    assert!(!process_events.contains("/home"));
    assert!(process_events.contains("fds:[9, "));
}

#[tokio::test]
async fn prepared_child_is_released_only_after_exact_network_namespace_route_attachment() {
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
    let egress_view = egress.clone();
    let shard_id = ShardId::new();
    let spec = launch_spec(shard_id.clone());
    let expected_egress = spec.dedicated_egress().clone();
    let expected_tenant = spec.tenant_id().clone();
    let expected_fence = ShardEgressFence::new(shard_id.clone(), 7);
    let expected_namespace = current_network_namespace()
        .expect("the fake child network namespace should be pinnable")
        .identity();

    backend(filesystem, process, egress)
        .provision(&spec)
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
    let route_attachment = events
        .iter()
        .position(|event| event == "route:attach")
        .expect("the route must attach to the prepared child's exact network namespace");
    let namespace_revalidation = events
        .iter()
        .rposition(|event| event == "netns:revalidate")
        .expect("the exact network namespace must be revalidated after attachment");
    let release = events
        .iter()
        .position(|event| event == "gate:release")
        .expect("prepared child should be released");
    let exact_route_check = events
        .iter()
        .rposition(|event| event == "route:is-active")
        .expect("the exact route fence should be checked");
    assert!(spawn < validate);
    assert!(validate < route_attachment);
    assert!(route_attachment < namespace_revalidation);
    assert!(namespace_revalidation < exact_route_check);
    assert!(
        exact_route_check < release,
        "the exact fence check and durable release intent must precede gate release"
    );
    assert_eq!(
        events.iter().filter(|event| *event == "identity").count(),
        2,
        "PID/start-time identity must be checked before and after attachment"
    );
    drop(events);

    let calls = egress_view
        .calls
        .lock()
        .expect("egress call lock should work");
    assert!(
        matches!(
            calls.as_slice(),
            [
                EgressCall::Prepare(_),
                EgressCall::Attach(_, _, _),
                EgressCall::IsActive(_),
            ]
        ),
        "unexpected egress calls: {calls:?}"
    );
    let [
        EgressCall::Prepare(reservation),
        EgressCall::Attach(attached_reservation, attached_namespace, attached_receipt),
        EgressCall::IsActive(active_lease),
    ] = calls.as_slice()
    else {
        return;
    };
    assert_eq!(reservation.fence(), &expected_fence);
    assert_eq!(reservation.tenant_id(), Some(&expected_tenant));
    assert_eq!(reservation.dedicated_egress(), Some(&expected_egress));
    assert_eq!(
        reservation.egress_fence(),
        Some(expected_egress.egress_fence())
    );
    assert_eq!(attached_reservation, reservation);
    assert_eq!(*attached_namespace, expected_namespace);
    assert_eq!(active_lease.reservation(), reservation);
    assert_eq!(active_lease.namespace_identity(), expected_namespace);
    assert_eq!(active_lease.receipt(), attached_receipt);
}

#[tokio::test]
async fn gated_provision_requires_cdp_claim_before_explicit_activation() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let process = FakeProcess {
        events: trace.clone(),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let backend = backend(
        filesystem,
        process,
        FakeEgress {
            events: trace.clone(),
            ..FakeEgress::default()
        },
    );

    let handle = backend
        .provision_gated(&launch_spec(ShardId::new()))
        .await
        .expect("gated provisioning should stop before Chromium release");
    assert!(
        !trace
            .lock()
            .expect("trace lock should work")
            .iter()
            .any(|event| event == "gate:release")
    );

    let pipes = backend
        .claim_cdp_pipes(&handle)
        .await
        .expect("the parent CDP capabilities should be claimable while gated");
    drop(pipes);
    backend
        .activate(&handle)
        .await
        .expect("activation should release the one-shot launch gate");

    assert_eq!(
        trace
            .lock()
            .expect("trace lock should work")
            .iter()
            .filter(|event| *event == "gate:release")
            .count(),
        1
    );
}

#[tokio::test]
async fn journaled_linux_effects_commit_in_gate_closed_handoff_order() {
    let directory = tempfile::tempdir().expect("journal directory should be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                PathBuf::from("/sys/fs/cgroup/browserd"),
                PathBuf::from("/var/lib/browserd/shards"),
            )
            .expect("test recovery roots should be safe"),
        )
        .expect("journal should open"),
    );
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let backend = backend(
        filesystem,
        FakeProcess {
            events: trace.clone(),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress {
            events: trace.clone(),
            ..FakeEgress::default()
        },
    )
    .with_prepared_journal(Arc::clone(&journal), 41)
    .expect("journal binding should be valid");
    let spec = launch_spec(ShardId::new());

    let handle = backend
        .provision_gated(&spec)
        .await
        .expect("the shard should remain gated after ingress activation");
    assert_eq!(
        journal.records().expect("record should be readable")[0]
            .lifecycle_state()
            .expect("journal lifecycle should validate"),
        PreparedShardState::IngressRegistered
    );
    assert!(
        !trace
            .lock()
            .expect("trace lock should work")
            .contains(&"gate:release".into())
    );

    drop(
        backend
            .claim_cdp_pipes(&handle)
            .await
            .expect("CDP pipes should be claimable while gated"),
    );
    backend
        .commit_cdp_claim(&handle)
        .await
        .expect("receipted CDP claim should become durable");
    backend
        .activate(&handle)
        .await
        .expect("release intent should precede the gate token");
    assert_eq!(
        journal.records().expect("record should be readable")[0]
            .lifecycle_state()
            .expect("journal lifecycle should validate"),
        PreparedShardState::Released
    );
    assert_eq!(
        trace
            .lock()
            .expect("trace lock should work")
            .iter()
            .filter(|event| *event == "gate:release")
            .count(),
        1
    );
}

#[tokio::test]
async fn journaled_prepare_failure_records_every_cleanup_before_returning() {
    let directory = tempfile::tempdir().expect("journal directory should be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                PathBuf::from("/sys/fs/cgroup/browserd"),
                PathBuf::from("/var/lib/browserd/shards"),
            )
            .expect("test recovery roots should be safe"),
        )
        .expect("journal should open"),
    );
    let filesystem = FakeFilesystem::production_tree();
    let shard_id = ShardId::new();
    let backend = backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress {
            fail_prepare: true,
            ..FakeEgress::default()
        },
    )
    .with_prepared_journal(Arc::clone(&journal), 41)
    .expect("journal binding should be valid");

    backend
        .provision_gated(&launch_spec(shard_id.clone()))
        .await
        .expect_err("mandatory route preparation should fail closed");
    let record = journal
        .records()
        .expect("journal should remain readable")
        .pop()
        .expect("failed preparation should retain a tombstone");
    assert_eq!(
        record.recovery_disposition(),
        PreparedShardRecoveryDisposition::ReleasedTombstone
    );
    assert!(!filesystem.has_shard_residue(&shard_id));
}

#[tokio::test]
async fn journaled_death_confirmation_error_remains_retryable() {
    let directory = tempfile::tempdir().expect("journal directory should be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                PathBuf::from("/sys/fs/cgroup/browserd"),
                PathBuf::from("/var/lib/browserd/shards"),
            )
            .expect("test recovery roots should be safe"),
        )
        .expect("journal should open"),
    );
    let backend = backend(
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    )
    .with_prepared_journal(Arc::clone(&journal), 41)
    .expect("journal binding should be valid");
    let handle = backend
        .provision_gated(&launch_spec(ShardId::new()))
        .await
        .expect("the shard should provision with its launch gate closed");
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("route revocation should open the independent process cleanup branch");

    backend
        .kill_cgroup(&handle, CleanupReason::Administrative)
        .await
        .expect_err("an unreadable cgroup.events must fail closed");

    let record = journal
        .records()
        .expect("journal should remain readable")
        .pop()
        .expect("the shard record should remain durable");
    assert_eq!(
        record
            .cleanup_progress(PreparedShardCleanupStage::ConfirmProcessDeath)
            .expect("cleanup progress should validate")
            .status(),
        PreparedShardCleanupStageStatus::Failed,
        "an inconclusive death check must stay retryable instead of being marked complete"
    );
}

#[tokio::test]
async fn timed_out_cleanup_attempt_is_reclaimed_by_the_same_daemon() {
    let directory = tempfile::tempdir().expect("journal directory should be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                PathBuf::from("/sys/fs/cgroup/browserd"),
                PathBuf::from("/var/lib/browserd/shards"),
            )
            .expect("test recovery roots should be safe"),
        )
        .expect("journal should open"),
    );
    let revoke_pause = AsyncPause::new();
    let backend = Arc::new(
        backend(
            FakeFilesystem::production_tree(),
            FakeProcess {
                events: Arc::new(Mutex::new(Vec::new())),
                alive: Arc::new(Mutex::new(false)),
                identity_matches: true,
            },
            FakeEgress {
                revoke_pause: Some(revoke_pause.clone()),
                ..FakeEgress::default()
            },
        )
        .with_prepared_journal(Arc::clone(&journal), 41)
        .expect("journal binding should be valid"),
    );
    let handle = backend
        .provision_gated(&launch_spec(ShardId::new()))
        .await
        .expect("the shard should provision with its launch gate closed");

    let first_attempt = {
        let backend = Arc::clone(&backend);
        let handle = handle.clone();
        tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(200),
                backend.revoke_egress(&handle, CleanupReason::Administrative),
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), revoke_pause.entered.notified())
        .await
        .expect("the exact revoke effect should start after its durable intent");
    assert!(
        first_attempt
            .await
            .expect("timed cleanup task should not panic")
            .is_err(),
        "the first exact revoke attempt should be cancelled at its stage timeout"
    );
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("the same daemon must reclaim and converge the cancelled exact attempt");
    assert_eq!(
        journal.records().expect("journal should remain readable")[0]
            .cleanup_progress(PreparedShardCleanupStage::RevokeEgress)
            .expect("cleanup progress should validate")
            .status(),
        PreparedShardCleanupStageStatus::Completed
    );
}

#[tokio::test]
async fn released_shard_generation_never_aliases_new_linux_recovery_locators() {
    let directory = tempfile::tempdir().expect("journal directory should be created");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                PathBuf::from("/sys/fs/cgroup/browserd"),
                PathBuf::from("/var/lib/browserd/shards"),
            )
            .expect("test recovery roots should be safe"),
        )
        .expect("journal should open"),
    );
    let filesystem = FakeFilesystem::production_tree();
    let backend = backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    )
    .with_prepared_journal(Arc::clone(&journal), 41)
    .expect("journal binding should be valid");
    let shard_id = ShardId::new();
    let worker_id = WorkerId::new("generation-locator-worker").expect("worker should be valid");
    let first_spec = launch_spec_for(shard_id.clone(), worker_id.clone(), 7);
    let first = backend
        .provision_gated(&first_spec)
        .await
        .expect("first launch generation should provision");
    let first_record = journal.records().expect("journal should be readable")[0].clone();
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            first_record.locators().cgroup_path().join("cgroup.events"),
            "populated 0\n".into(),
        );
    backend
        .revoke_egress(&first, CleanupReason::Administrative)
        .await
        .expect("first route should revoke");
    backend
        .kill_cgroup(&first, CleanupReason::Administrative)
        .await
        .expect("first cgroup should die");
    backend
        .cleanup_namespaces(&first)
        .await
        .expect("first generation should reach its released tombstone");

    let second_fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                worker_id,
                WorkerEpoch::new(7).expect("worker epoch should be positive"),
            ),
            shard_id,
            LaunchGeneration::new(2).expect("launch generation should be positive"),
        ),
        RouteGeneration::new(2).expect("route generation should be positive"),
        SessionId::new(),
        SessionIncarnation::new(2).expect("session incarnation should be positive"),
    );
    let second_spec = LaunchSpec::production(
        TenantId::new(),
        DedicatedEgressSpec::new(
            second_fence,
            EgressPolicyBinding::new("test-public-web", [2; 32])
                .expect("policy binding should be valid"),
            Duration::from_secs(5),
        )
        .expect("dedicated egress should be valid"),
        chromium_digest(TEST_CHROMIUM_BYTES),
    );
    backend
        .provision_gated(&second_spec)
        .await
        .expect("a newer generation must not collide with the released generation locators");

    let records = journal.records().expect("journal should remain readable");
    assert_eq!(records.len(), 2);
    assert_ne!(
        records[0].locators().cgroup_path(),
        records[1].locators().cgroup_path()
    );
    assert_ne!(
        records[0].locators().runtime_path(),
        records[1].locators().runtime_path()
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
            .iter()
            .any(|call| {
                matches!(call, EgressCall::IsActive(lease) if lease.reservation().fence() == &expected_fence)
            })
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
    let cgroup_path = PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{shard_id}-launch-1"));
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
    let cancel = events
        .iter()
        .position(|event| event == "route:cancel-reservation")
        .expect("unattached egress reservation should be cancelled");
    let kill = events
        .iter()
        .position(|event| event == "signal:Kill")
        .expect("owned prepared child should be killed");
    assert!(cancel < kill);
}

#[tokio::test]
async fn changed_network_namespace_after_attachment_revokes_and_aborts_fail_closed() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    let alive = Arc::new(Mutex::new(false));
    let process = FaultProcess {
        fault: SpawnFault::MismatchedNetworkNamespace,
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
        .expect_err("a prepared child that leaves the attached namespace must fail closed");

    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    let events = trace.lock().expect("trace lock should work");
    let attach = events
        .iter()
        .position(|event| event == "route:attach")
        .expect("the exact namespace should be attached before it is revalidated");
    let revalidate = events
        .iter()
        .position(|event| event == "netns:revalidate")
        .expect("the child namespace should be revalidated after attachment");
    assert!(attach < revalidate);
    assert!(events.iter().any(|event| event == "route:revoke"));
    assert!(events.iter().any(|event| event == "route:release"));
    assert!(events.iter().any(|event| event == "signal:Kill"));
    assert!(!events.iter().any(|event| event == "gate:release"));
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
            .state
            .lock()
            .expect("route state lock should work")
            .routes
            .iter()
            .any(|(reservation, route)| {
                reservation.fence() == &ShardEgressFence::new(shard_id.clone(), 7)
                    && matches!(route, FakeRouteLifecycle::Prepared(_))
            }),
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
                .join(format!("{shard_id}-launch-1"))
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

fn journaled_cleanup_backend(
    filesystem: FakeFilesystem,
    process: FakeProcess,
    egress: FakeEgress,
) -> (
    tempfile::TempDir,
    Arc<FilePreparedShardJournal>,
    Arc<LinuxSandboxBackend<FakeFilesystem, FakeProcess, FakeEgress>>,
) {
    let directory = tempfile::tempdir().expect("journal directory");
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            directory.path(),
            PreparedShardJournalLimits::default(),
            PreparedShardRecoveryRoots::new(
                "/sys/fs/cgroup/browserd".into(),
                "/var/lib/browserd/shards".into(),
            )
            .expect("exact test roots"),
        )
        .expect("real private journal"),
    );
    let backend = Arc::new(
        backend(filesystem, process, egress)
            .with_prepared_journal(Arc::clone(&journal), 41)
            .expect("journal binding"),
    );
    (directory, journal, backend)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn journaled_runtime_kill_waits_for_actual_revoke_intent_before_effects() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = Arc::clone(&trace);
    let (_directory, journal, backend) = journaled_cleanup_backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::clone(&trace),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let shard = ShardId::new();
    let handle = backend
        .provision_gated(&launch_spec(shard.clone()))
        .await
        .expect("gated runtime");
    filesystem.files.lock().expect("files").insert(
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{shard}-launch-1/cgroup.events")),
        "populated 0\n".into(),
    );
    let kill = tokio::spawn({
        let backend = Arc::clone(&backend);
        let handle = handle.clone();
        async move {
            backend
                .kill_cgroup(&handle, CleanupReason::Administrative)
                .await
        }
    });
    // The revoke branch deliberately does not start: scheduling delay must remain pending,
    // rather than exhaust a finite number of CPU yields and report a spurious failure.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !kill.is_finished(),
        "kill must wait for the exact durable revoke intent"
    );
    assert!(
        !trace
            .lock()
            .expect("trace")
            .iter()
            .any(|event| event.starts_with("signal:") || event.contains("cgroup.kill"))
    );
    let record = journal
        .records()
        .expect("journal")
        .pop()
        .expect("exact record");
    assert_eq!(
        record
            .cleanup_progress(PreparedShardCleanupStage::AbortGate)
            .expect("progress")
            .attempts(),
        0
    );

    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("durable revoke");
    tokio::time::timeout(Duration::from_secs(1), kill)
        .await
        .expect("bounded kill completion")
        .expect("kill task")
        .expect("positive kill");
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("exact namespace cleanup");
    let record = journal
        .records()
        .expect("journal")
        .pop()
        .expect("exact record");
    assert_eq!(
        record.recovery_disposition(),
        PreparedShardRecoveryDisposition::ReleasedTombstone
    );
    for stage in PreparedShardCleanupStage::ALL {
        let progress = record.cleanup_progress(stage).expect("progress");
        assert_eq!(
            progress.status(),
            PreparedShardCleanupStageStatus::Completed
        );
        assert_eq!(progress.attempts(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn journaled_runtime_kill_proceeds_while_the_post_intent_revoke_effect_is_blocked() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = Arc::clone(&trace);
    let pause = AsyncPause::new();
    let (_directory, journal, backend) = journaled_cleanup_backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::clone(&trace),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress {
            revoke_pause: Some(pause.clone()),
            ..FakeEgress::default()
        },
    );
    let shard = ShardId::new();
    let handle = backend
        .provision_gated(&launch_spec(shard.clone()))
        .await
        .expect("gated runtime");
    filesystem.files.lock().expect("files").insert(
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{shard}-launch-1/cgroup.events")),
        "populated 0\n".into(),
    );
    let revoke = tokio::spawn({
        let backend = Arc::clone(&backend);
        let handle = handle.clone();
        async move {
            backend
                .revoke_egress(&handle, CleanupReason::Administrative)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), pause.entered.notified())
        .await
        .expect("revoke effect started");
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        backend.kill_cgroup(&handle, CleanupReason::Administrative),
    )
    .await;
    let still_blocked = !revoke.is_finished();
    pause.proceed.notify_one();
    revoke.await.expect("revoke task").expect("exact revoke");
    result
        .expect("kill must not wait for the egress effect")
        .expect("positive kill");
    assert!(still_blocked);
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("exact cleanup");
    let record = journal
        .records()
        .expect("journal")
        .pop()
        .expect("exact record");
    assert_eq!(
        record.recovery_disposition(),
        PreparedShardRecoveryDisposition::ReleasedTombstone
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn cancelled_revoke_intent_wait_stays_bounded_and_preserves_later_exact_cleanup() {
    let filesystem = FakeFilesystem::production_tree();
    let (_directory, journal, backend) = journaled_cleanup_backend(
        filesystem.clone(),
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let shard = ShardId::new();
    let handle = backend
        .provision_gated(&launch_spec(shard.clone()))
        .await
        .expect("gated runtime");
    filesystem.files.lock().expect("files").insert(
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{shard}-launch-1/cgroup.events")),
        "populated 0\n".into(),
    );
    let pending = tokio::time::timeout(
        Duration::from_millis(30),
        backend.kill_cgroup(&handle, CleanupReason::Administrative),
    )
    .await;
    assert!(
        pending.is_err(),
        "existing caller bounds must cancel an absent-intent wait"
    );
    let record = journal
        .records()
        .expect("journal")
        .pop()
        .expect("exact record");
    assert_eq!(
        record
            .cleanup_progress(PreparedShardCleanupStage::AbortGate)
            .expect("progress")
            .attempts(),
        0
    );
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("durable revoke");
    tokio::time::timeout(
        Duration::from_secs(1),
        backend.kill_cgroup(&handle, CleanupReason::Administrative),
    )
    .await
    .expect("cancelled wait did not retain process lock")
    .expect("positive kill");
    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("exact cleanup");
    let record = journal
        .records()
        .expect("journal")
        .pop()
        .expect("exact record");
    assert_eq!(
        record.recovery_disposition(),
        PreparedShardRecoveryDisposition::ReleasedTombstone
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
                .join(format!("{shard_id}-launch-1"))
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
        failures.insert(format!("shards/{shard_id}-launch-1"));
        failures.insert(format!("browserd/{shard_id}-launch-1"));
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
    let inspect_cgroup =
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{inspect_shard}-launch-1"));
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
    let cleanup_cgroup =
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{cleanup_shard}-launch-1"));
    let inspect_cgroup =
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{inspect_shard}-launch-1"));
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
        suffix: PathBuf::from(format!("shards/{cleanup_shard}-launch-1")),
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
async fn egress_renewal_and_revoke_are_serialized_for_the_exact_runtime() {
    let filesystem = FakeFilesystem::production_tree();
    let renew_pause = AsyncPause::new();
    let revoke_pause = AsyncPause::new();
    let egress = FakeEgress {
        renew_commit_pause: Some(renew_pause.clone()),
        revoke_pause: Some(revoke_pause.clone()),
        ..FakeEgress::default()
    };
    let backend = Arc::new(backend(
        filesystem,
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        egress.clone(),
    ));
    let handle = backend
        .provision(&launch_spec(ShardId::new()))
        .await
        .expect("runtime should provision");
    let lease_ttl = Duration::from_secs(30);

    let renew = tokio::spawn({
        let backend = Arc::clone(&backend);
        let handle = handle.clone();
        async move { backend.renew_egress(&handle, lease_ttl).await }
    });
    wait_for_commit_pause(&renew_pause, "runtime egress renewal").await;

    let revoke = tokio::spawn({
        let backend = Arc::clone(&backend);
        let handle = handle.clone();
        async move {
            backend
                .revoke_egress(&handle, CleanupReason::Administrative)
                .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), revoke_pause.entered.notified())
            .await
            .is_err(),
        "revoke must not enter the egress backend while exact-route renewal is pending"
    );

    renew_pause.proceed.notify_one();
    renew
        .await
        .expect("renew task should join")
        .expect("renew should succeed");
    wait_for_commit_pause(&revoke_pause, "runtime egress revoke").await;
    revoke_pause.proceed.notify_one();
    revoke
        .await
        .expect("revoke task should join")
        .expect("revoke should succeed");

    let calls = egress.calls.lock().expect("egress call lock should work");
    let (renew_index, renewed_lease) = calls
        .iter()
        .enumerate()
        .find_map(|(index, call)| match call {
            EgressCall::Renew(lease, observed_ttl) if *observed_ttl == lease_ttl => {
                Some((index, lease))
            }
            _ => None,
        })
        .expect("exact lease renewal should be recorded");
    let (revoke_index, revoked_lease) = calls
        .iter()
        .enumerate()
        .find_map(|(index, call)| match call {
            EgressCall::Revoke(lease) => Some((index, lease)),
            _ => None,
        })
        .expect("exact lease revoke should be recorded");
    assert_eq!(renewed_lease, revoked_lease);
    assert!(renew_index < revoke_index);
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
                .join(format!("{shard_id}-launch-1"))
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
async fn cancelled_runtime_revoke_after_backend_commit_retries_the_exact_lease() {
    let filesystem = FakeFilesystem::production_tree();
    let commit_pause = AsyncPause::new();
    let egress = FakeEgress {
        revoke_commit_pause: Some(commit_pause.clone()),
        ..FakeEgress::default()
    };
    let backend = Arc::new(backend(
        filesystem,
        FakeProcess {
            events: Arc::new(Mutex::new(Vec::new())),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        egress.clone(),
    ));
    let handle = backend
        .provision(&launch_spec(ShardId::new()))
        .await
        .expect("runtime should provision");
    let revoke = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move {
            backend
                .revoke_egress(&handle, CleanupReason::Administrative)
                .await
        }
    });

    wait_for_commit_pause(&commit_pause, "runtime revoke").await;
    revoke.abort();
    assert!(
        revoke
            .await
            .expect_err("revoke caller should be cancelled after backend commit")
            .is_cancelled()
    );

    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("the exact committed revoke must be retryable");
    let calls = egress.calls.lock().expect("egress call lock should work");
    let leases = calls
        .iter()
        .filter_map(|call| match call {
            EgressCall::Revoke(lease) => Some(lease),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(leases.len(), 2);
    assert_eq!(leases[0], leases[1]);
}

#[tokio::test]
async fn cancelled_runtime_release_after_backend_commit_retries_the_exact_lease() {
    let filesystem = FakeFilesystem::production_tree();
    let commit_pause = AsyncPause::new();
    let egress = FakeEgress {
        release_commit_pause: Some(commit_pause.clone()),
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
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("route should revoke before namespace cleanup");
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(format!("{shard_id}-launch-1"))
                .join("cgroup.events"),
            "populated 0\n".into(),
        );
    let cleanup = tokio::spawn({
        let backend = backend.clone();
        let handle = handle.clone();
        async move { backend.cleanup_namespaces(&handle).await }
    });

    wait_for_commit_pause(&commit_pause, "runtime release").await;
    cleanup.abort();
    assert!(
        cleanup
            .await
            .expect_err("cleanup caller should be cancelled after route release commit")
            .is_cancelled()
    );

    backend
        .cleanup_namespaces(&handle)
        .await
        .expect("the exact committed release must be retryable");
    assert!(matches!(
        backend.inspect(&handle).await,
        Err(SandboxError::ShardNotFound)
    ));
    let calls = egress.calls.lock().expect("egress call lock should work");
    let leases = calls
        .iter()
        .filter_map(|call| match call {
            EgressCall::Release(lease) => Some(lease),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(leases.len(), 2);
    assert_eq!(leases[0], leases[1]);
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
async fn cancelled_attach_after_backend_commit_cleans_the_exact_reservation_without_a_receipt() {
    let filesystem = FakeFilesystem::production_tree();
    let process_events = Arc::new(Mutex::new(Vec::new()));
    let alive = Arc::new(Mutex::new(false));
    let commit_pause = AsyncPause::new();
    let egress = FakeEgress {
        attach_commit_pause: Some(commit_pause.clone()),
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

    wait_for_commit_pause(&commit_pause, "ingress attachment").await;
    provision.abort();
    assert!(
        provision
            .await
            .expect_err("provision caller should be cancelled before receiving the receipt")
            .is_cancelled()
    );

    backend
        .provision(&launch_spec(shard_id.clone()))
        .await
        .expect_err("the first retry must finish the receipt-less cleanup only");
    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
    assert!(
        !process_events
            .lock()
            .expect("process event lock should work")
            .iter()
            .any(|event| event == "gate:release"),
        "receipt-less cancellation must never release the prepared child"
    );
    {
        let calls = egress.calls.lock().expect("egress call lock should work");
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, EgressCall::Attach(_, _, _)))
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, EgressCall::CancelReservation(_)))
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, EgressCall::ReleaseReservation(_)))
                .count(),
            1
        );
        assert!(
            !calls
                .iter()
                .any(|call| { matches!(call, EgressCall::Revoke(_) | EgressCall::Release(_)) })
        );
    }

    backend
        .provision(&launch_spec(shard_id))
        .await
        .expect("a fresh generation may start after exact receipt-less cleanup");
}

#[tokio::test]
async fn cancelled_provision_terminal_route_commits_are_exactly_retryable() {
    for pause_after_cancel in [true, false] {
        let filesystem = FakeFilesystem::production_tree();
        *filesystem
            .cgroup_procs_override
            .lock()
            .expect("cgroup override lock should work") = Some("9999\n".into());
        let commit_pause = AsyncPause::new();
        let egress = if pause_after_cancel {
            FakeEgress {
                cancel_commit_pause: Some(commit_pause.clone()),
                ..FakeEgress::default()
            }
        } else {
            FakeEgress {
                release_reservation_commit_pause: Some(commit_pause.clone()),
                ..FakeEgress::default()
            }
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
        let provision = tokio::spawn({
            let backend = backend.clone();
            let shard_id = shard_id.clone();
            async move { backend.provision(&launch_spec(shard_id)).await }
        });

        wait_for_commit_pause(&commit_pause, "provision reservation cleanup").await;
        provision.abort();
        assert!(
            provision
                .await
                .expect_err("provision caller should be cancelled after terminal route commit")
                .is_cancelled()
        );

        backend
            .provision(&launch_spec(shard_id.clone()))
            .await
            .expect_err("the first retry must finish abandoned cleanup only");
        let (cancellations, releases) = {
            let calls = egress.calls.lock().expect("egress call lock should work");
            let cancellations = calls
                .iter()
                .filter_map(|call| match call {
                    EgressCall::CancelReservation(reservation) => Some(reservation.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let releases = calls
                .iter()
                .filter_map(|call| match call {
                    EgressCall::ReleaseReservation(reservation) => Some(reservation.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (cancellations, releases)
        };
        assert_eq!(cancellations.len(), usize::from(pause_after_cancel) + 1);
        assert_eq!(releases.len(), usize::from(!pause_after_cancel) + 1);
        assert!(
            cancellations
                .iter()
                .chain(releases.iter())
                .all(|reservation| reservation == &cancellations[0]),
            "cleanup retries must retain one exact reservation generation"
        );

        *filesystem
            .cgroup_procs_override
            .lock()
            .expect("cgroup override lock should work") = None;
        backend
            .provision(&launch_spec(shard_id))
            .await
            .expect("a fresh generation may start only after exact cleanup completes");
    }
}

#[tokio::test]
async fn cancelled_attached_lease_cleanup_commits_are_exactly_retryable() {
    for pause_after_revoke in [true, false] {
        let filesystem = FakeFilesystem::production_tree();
        let process_events = Arc::new(Mutex::new(Vec::new()));
        let alive = Arc::new(Mutex::new(false));
        let commit_pause = AsyncPause::new();
        let egress = if pause_after_revoke {
            FakeEgress {
                revoke_commit_pause: Some(commit_pause.clone()),
                ..FakeEgress::default()
            }
        } else {
            FakeEgress {
                release_commit_pause: Some(commit_pause.clone()),
                ..FakeEgress::default()
            }
        };
        let backend = Arc::new(LinuxSandboxBackend::new(
            config(),
            filesystem.clone(),
            FaultProcess {
                fault: SpawnFault::MismatchedNetworkNamespace,
                events: process_events.clone(),
                alive: alive.clone(),
            },
            egress.clone(),
        ));
        let shard_id = ShardId::new();
        let provision = tokio::spawn({
            let backend = backend.clone();
            let shard_id = shard_id.clone();
            async move { backend.provision(&launch_spec(shard_id)).await }
        });

        wait_for_commit_pause(&commit_pause, "attached lease cleanup").await;
        provision.abort();
        assert!(
            provision
                .await
                .expect_err("provision caller should be cancelled after lease cleanup commit")
                .is_cancelled()
        );

        backend
            .provision(&launch_spec(shard_id.clone()))
            .await
            .expect_err("the first retry must finish abandoned attached-lease cleanup only");
        assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
        assert!(
            !process_events
                .lock()
                .expect("process event lock should work")
                .iter()
                .any(|event| event == "gate:release"),
            "a mismatched attached namespace must never release the prepared child"
        );
        let (revokes, releases) = {
            let calls = egress.calls.lock().expect("egress call lock should work");
            let revokes = calls
                .iter()
                .filter_map(|call| match call {
                    EgressCall::Revoke(lease) => Some(lease.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let releases = calls
                .iter()
                .filter_map(|call| match call {
                    EgressCall::Release(lease) => Some(lease.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (revokes, releases)
        };
        assert_eq!(revokes.len(), usize::from(pause_after_revoke) + 1);
        assert_eq!(releases.len(), usize::from(!pause_after_revoke) + 1);
        assert!(
            revokes
                .iter()
                .chain(releases.iter())
                .all(|lease| lease == &revokes[0]),
            "cleanup retries must retain one exact attached lease"
        );
        assert!(matches!(
            egress
                .state
                .lock()
                .expect("route state lock should work")
                .routes
                .get(revokes[0].reservation()),
            Some(FakeRouteLifecycle::LeaseReleased(_))
        ));

        backend
            .provision(&launch_spec(shard_id))
            .await
            .expect_err("the next exact-namespace mismatch should be a fresh generation");
        let reservations = egress
            .calls
            .lock()
            .expect("egress call lock should work")
            .iter()
            .filter_map(|call| match call {
                EgressCall::Prepare(reservation) => Some(reservation.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(reservations.len(), 2);
        assert_ne!(reservations[0], reservations[1]);
    }
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
async fn stale_generation_cannot_claim_newer_abandoned_provision_cleanup() {
    let filesystem = FakeFilesystem::production_tree();
    let events = Arc::new(Mutex::new(Vec::new()));
    let alive = Arc::new(Mutex::new(false));
    let pause = AsyncPause::new();
    let process = CancelOnceDuringSpawnProcess {
        inner: FakeProcess {
            events: Arc::clone(&events),
            alive: Arc::clone(&alive),
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
    let worker_id = WorkerId::new("generation-aba-worker").expect("worker should be valid");
    let tenant_id = TenantId::new();
    let current = launch_spec_for_generation_and_tenant(
        tenant_id.clone(),
        shard_id.clone(),
        worker_id.clone(),
        7,
        4,
    );
    let stale = launch_spec_for_generation_and_tenant(tenant_id, shard_id.clone(), worker_id, 7, 3);

    let current_owner = tokio::spawn({
        let backend = Arc::clone(&backend);
        let current = current.clone();
        async move { backend.provision_gated(&current).await }
    });
    pause.entered.notified().await;
    current_owner.abort();
    assert!(
        current_owner
            .await
            .expect_err("current owner should be cancelled")
            .is_cancelled()
    );

    let events_before_stale = events.lock().expect("event lock should work").clone();
    let egress_before_stale = egress
        .calls
        .lock()
        .expect("egress lock should work")
        .clone();
    assert!(matches!(
        backend.provision_gated(&stale).await,
        Err(SandboxError::LaunchGenerationMismatch)
    ));
    assert_eq!(
        *events.lock().expect("event lock should work"),
        events_before_stale,
        "stale generation must be rejected before process cleanup effects"
    );
    assert_eq!(
        *egress.calls.lock().expect("egress lock should work"),
        egress_before_stale,
        "stale generation must be rejected before egress cleanup effects"
    );

    backend
        .provision_gated(&current)
        .await
        .expect_err("current generation must retain and finish its abandoned cleanup");
    assert!(
        events
            .lock()
            .expect("event lock should work")
            .iter()
            .any(|event| event == "signal:Kill"),
        "the exact current generation must retain cleanup ownership"
    );
    assert_no_provisioning_residue(&filesystem, &egress, &alive, &shard_id);
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
    assert_eq!(events[spawn + 1], "route:cancel-reservation");
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
        .position(|event| event == "route:cancel-reservation")
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
        !events
            .iter()
            .any(|event| event == "route:release-reservation"),
        "a route whose revoke failed must not be released"
    );
    assert!(
        egress_view
            .state
            .lock()
            .expect("route state lock should work")
            .routes
            .iter()
            .any(|(reservation, route)| {
                reservation.fence() == &ShardEgressFence::new(shard_id.clone(), 7)
                    && matches!(route, FakeRouteLifecycle::Prepared(_))
            }),
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
            .position(|event| event == "route:cancel-reservation")
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
        .position(|event| event == "route:cancel-reservation")
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
                chromium_runtime("/opt/browser/chrome"),
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
                chromium_runtime("/opt/browser/chrome"),
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
        chromium_runtime("/opt/browser/chrome"),
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
fn chromium_executable_path_cannot_be_shadowed_by_a_runtime_mount() {
    for destination in [
        "/",
        "/opt",
        "/opt/chromium/chrome",
        "/opt/chromium",
        "/opt/chromium/chrome/resources",
    ] {
        let configuration = LinuxSandboxConfig::new(
            "/sys/fs/cgroup/browserd",
            "/var/lib/browserd/shards",
            "/usr/bin/bwrap",
            chromium_runtime("/opt/chromium/chrome"),
            LaunchGateRuntime::new("/usr/libexec/browserd-launch-gate", "/browserd/launch-gate"),
            [ReadOnlyMount::new("/opt/runtime", destination)],
            CgroupLimits::new(10, 5, 2, 1000, 1000).expect("limits should work"),
            9,
            Duration::from_millis(10),
            Duration::from_millis(1),
        );

        assert_eq!(
            configuration.is_ok(),
            destination == "/opt/chromium",
            "only Chromium's exact parent may provide runtime resources: {destination}",
        );
    }
}

#[test]
fn launch_gate_paths_cannot_alias_a_runtime_or_virtual_filesystem() {
    let temporary = tempfile::Builder::new()
        .prefix("chromium-launch-gate-alias-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("private test directory should be created");
    let chromium_source = temporary.path().join("chrome");
    std::fs::write(&chromium_source, TEST_CHROMIUM_BYTES).expect("test Chromium should be written");
    std::fs::set_permissions(&chromium_source, std::fs::Permissions::from_mode(0o755))
        .expect("test Chromium should be executable");
    assert!(
        LinuxSandboxConfig::new(
            "/sys/fs/cgroup/browserd",
            "/var/lib/browserd/shards",
            "/usr/bin/bwrap",
            ChromiumRuntime::from_path(
                &chromium_source,
                "/opt/browser/chrome",
                chromium_digest(TEST_CHROMIUM_BYTES),
            )
            .expect("test Chromium should be pinned"),
            LaunchGateRuntime::new(chromium_source, "/opt/browser/launch-gate"),
            [],
            CgroupLimits::new(10, 5, 2, 1000, 1000).expect("limits should work"),
            9,
            Duration::from_millis(10),
            Duration::from_millis(1),
        )
        .is_err()
    );
    for launch_gate in [
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
                chromium_runtime("/opt/browser/chrome"),
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
            chromium_runtime("/opt/chromium/chrome"),
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
    .planned_spawn_request(&launch_spec(ShardId::new()))
    .expect("sealed Chromium launch capability should be available");

    let error = StdLinuxProcessBackend::default()
        .spawn_prepared(&LeaseId::new().to_string(), &request)
        .await
        .expect_err("a closed seccomp descriptor must fail closed");
    assert!(error.to_string().contains("required inherited descriptor"));
}

#[tokio::test]
async fn production_cdp_claim_rejects_missing_backend_ownership() {
    let error = StdLinuxProcessBackend::default()
        .claim_cdp_pipes(&LeaseId::new().to_string(), ChildIdentity::new(123, 456))
        .await
        .expect_err("a missing backend token must not mint CDP capabilities");

    assert!(error.to_string().contains("ownership missing"));
}

#[test]
fn received_cdp_capabilities_fail_closed_on_wrong_or_aliased_descriptors() {
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe should be created");
    let wrong_direction =
        browserd_sandbox::ChromiumCdpPipes::from_owned_fds(command_reader, event_writer);
    assert!(
        matches!(wrong_direction, Err(error) if error.to_string().contains("wrong access direction"))
    );
    drop(command_writer);
    drop(event_reader);

    let (alias_reader, alias_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("alias pipe should be created");
    let aliased = browserd_sandbox::ChromiumCdpPipes::from_owned_fds(alias_writer, alias_reader);
    assert!(matches!(aliased, Err(error) if error.to_string().contains("alias one pipe")));

    let (unused_command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let (event_reader, unused_event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe should be created");
    nix::fcntl::fcntl(
        &command_writer,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .expect("test should clear close-on-exec");
    let inheritable =
        browserd_sandbox::ChromiumCdpPipes::from_owned_fds(command_writer, event_reader);
    assert!(matches!(inheritable, Err(error) if error.to_string().contains("not close-on-exec")));
    drop(unused_command_reader);
    drop(unused_event_writer);
}

#[test]
fn received_cdp_capabilities_reject_path_only_and_named_fifo_descriptors() {
    let directory = tempfile::tempdir().expect("FIFO tempdir should be created");
    let fifo = directory.path().join("events.fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .expect("named FIFO should be created");

    let (unused_command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let path_only_event_reader = nix::fcntl::open(
        &fifo,
        nix::fcntl::OFlag::O_PATH | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .expect("path-only FIFO should open without blocking");
    let path_only =
        browserd_sandbox::ChromiumCdpPipes::from_owned_fds(command_writer, path_only_event_reader);
    assert!(matches!(
        path_only,
        Err(error) if error.to_string().contains("path-only")
    ));
    drop(unused_command_reader);

    let (unused_command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe should be created");
    let named_event_reader = nix::fcntl::open(
        &fifo,
        nix::fcntl::OFlag::O_RDONLY | nix::fcntl::OFlag::O_NONBLOCK | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .expect("nonblocking named FIFO reader should open");
    let named =
        browserd_sandbox::ChromiumCdpPipes::from_owned_fds(command_writer, named_event_reader);
    assert!(matches!(
        named,
        Err(error) if error.to_string().contains("anonymous pipe")
    ));
    drop(unused_command_reader);
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
import ctypes
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
    if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:
        os._exit(79)
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
            .expect("fake sandbox child should be prepared before its bootstrap exits")
            .identity();
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
fn production_process_rejects_a_child_left_in_the_host_network_namespace() {
    run_process_helper("std_process_host_network_namespace_helper");
}

#[test]
fn production_process_applies_child_resource_limits_and_rejects_a_hard_limit_increase() {
    run_process_helper("std_process_resource_limits_helper");
}

#[test]
fn production_seccomp_readers_keep_identity_and_independent_offsets_across_concurrent_launches() {
    run_process_helper("std_process_seccomp_offsets_helper");
}

#[test]
#[ignore = "uses the configured seccomp FD only in an isolated descriptor-owning subprocess"]
fn std_process_seccomp_offsets_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let source = install_required_launch_descriptors();
    let expected = std::fs::read("/proc/self/fd/9").expect("original cBPF bytes");
    let identity = nix::sys::stat::fstat(&source).expect("original filter identity");
    nix::unistd::lseek(&source, 0, nix::unistd::Whence::SeekEnd)
        .expect("simulate previously consumed filter");
    let marker_directory = tempfile::tempdir().expect("seccomp observations directory");
    let markers = [
        marker_directory.path().join("first.json"),
        marker_directory.path().join("second.json"),
    ];
    let script = r#"#!/usr/bin/python3
import hashlib
import json
import os
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--info-fd":
        info_fd = int(next(arguments))
    elif argument == "--seccomp":
        policy_fd = int(next(arguments))

before = os.lseek(policy_fd, 0, os.SEEK_CUR)
raw = os.read(policy_fd, 32769)
metadata = os.fstat(policy_fd)
with open("__SECCOMP_MARKER__", "w") as marker:
    json.dump({"initial_offset": before, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
               "device": metadata.st_dev, "inode": metadata.st_ino}, marker)
    marker.flush()
    os.fsync(marker.fileno())
sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    sys.stdin.buffer.read()
    os._exit(0)
os.close(info_fd)
time.sleep(30)
"#;
    let (first_directory, first_executable) = executable_script(&script.replace(
        "__SECCOMP_MARKER__",
        markers[0].to_str().expect("first marker path"),
    ));
    let (second_directory, second_executable) = executable_script(&script.replace(
        "__SECCOMP_MARKER__",
        markers[1].to_str().expect("second marker path"),
    ));
    let (_first_cgroup, first_request) = process_request_for(&first_executable);
    let (_second_cgroup, second_request) = process_request_for(&second_executable);
    let tokens = [LeaseId::new().to_string(), LeaseId::new().to_string()];
    let process = StdLinuxProcessBackend::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("seccomp helper runtime");
    runtime.block_on(async {
        let (first, second) = tokio::join!(
            process.spawn_prepared(&tokens[0], &first_request),
            process.spawn_prepared(&tokens[1], &second_request),
        );
        for result in [first, second] {
            let error = result.expect_err("fixture leaves the host network namespace unchanged");
            assert!(
                error.to_string().contains("distinct network namespace"),
                "unexpected fixture rejection: {error}"
            );
        }
        for token in &tokens {
            process
                .abort_spawned(token, None)
                .await
                .expect("exact fixture processes are reaped");
        }
    });
    for marker in markers {
        let observed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(marker).expect("child seccomp observation"))
                .expect("seccomp observation JSON");
        assert_eq!(observed["initial_offset"], serde_json::json!(0));
        assert_eq!(observed["bytes"], serde_json::json!(expected.len()));
        assert_eq!(
            observed["sha256"],
            serde_json::json!(hex::encode(Sha256::digest(&expected)))
        );
        assert_eq!(observed["device"], serde_json::json!(identity.st_dev));
        assert_eq!(observed["inode"], serde_json::json!(identity.st_ino));
    }
    assert_eq!(
        nix::unistd::lseek(&source, 0, nix::unistd::Whence::SeekCur)
            .expect("supervisor filter offset"),
        i64::try_from(expected.len()).expect("filter length fits offset"),
        "launches must not rewind or consume the supervisor's shared reader"
    );
    // Invalid inputs are rejected before exec, rather than becoming an empty/permissive filter.
    for size in [
        0,
        7,
        (usize::try_from(nix::libc::BPF_MAXINSNS).expect("filter instruction limit") + 1) * 8,
    ] {
        let invalid = tempfile::tempfile().expect("invalid seccomp fixture");
        invalid
            .set_len(u64::try_from(size).expect("fixture length fits"))
            .expect("invalid policy size");
        // SAFETY: descriptor 9 belongs only to this isolated helper. Its OwnedFd retains ownership
        // of that slot after dup2 atomically replaces the underlying file capability.
        assert_eq!(unsafe { nix::libc::dup2(invalid.as_raw_fd(), 9) }, 9);
        let error = runtime
            .block_on(process.spawn_prepared(&LeaseId::new().to_string(), &first_request))
            .expect_err("invalid seccomp input must reject before exec");
        assert!(error.to_string().contains("bounded regular cBPF file"));
    }
    let nonregular = File::open("/dev/null").expect("nonregular seccomp fixture");
    // SAFETY: the configured slot is confined to this helper, as above.
    assert_eq!(unsafe { nix::libc::dup2(nonregular.as_raw_fd(), 9) }, 9);
    let error = runtime
        .block_on(process.spawn_prepared(&LeaseId::new().to_string(), &first_request))
        .expect_err("nonregular seccomp input must reject before exec");
    assert!(error.to_string().contains("bounded regular cBPF file"));
    drop((first_directory, second_directory));
}

#[test]
#[ignore = "changes hard resource limits only in an isolated descriptor-owning subprocess"]
fn std_process_resource_limits_helper() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};

    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let marker_directory = tempfile::tempdir().expect("resource limit marker directory");
    let marker = marker_directory.path().join("limits.json");
    let supervisor_core = getrlimit(Resource::RLIMIT_CORE).expect("supervisor core limit");
    let supervisor_nofile = getrlimit(Resource::RLIMIT_NOFILE).expect("supervisor nofile limit");
    assert!(
        supervisor_nofile.1 >= 65_536,
        "test host must supply the fixed launch limit"
    );
    let script = r#"#!/usr/bin/python3
import json
import os
import resource
import sys
import time

info_fd = None
arguments = iter(sys.argv[1:])
for argument in arguments:
    if argument == "--rlimit":
        raise RuntimeError("bubblewrap does not accept --rlimit")
    elif argument == "--info-fd":
        info_fd = int(next(arguments))

bootstrap = {"core": resource.getrlimit(resource.RLIMIT_CORE),
             "nofile": resource.getrlimit(resource.RLIMIT_NOFILE)}
sandbox_pid = os.fork()
if sandbox_pid == 0:
    os.setsid()
    with open("__LIMITS_MARKER__", "w") as output:
        json.dump({"bootstrap": bootstrap,
                   "sandbox": {"core": resource.getrlimit(resource.RLIMIT_CORE),
                               "nofile": resource.getrlimit(resource.RLIMIT_NOFILE)}}, output)
        output.flush()
        os.fsync(output.fileno())
    os.write(info_fd, json.dumps({"child-pid": os.getpid()}).encode() + b"\n")
    os.close(info_fd)
    sys.stdin.buffer.read()
    os._exit(0)
os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__LIMITS_MARKER__",
        marker.to_str().expect("resource limit marker path"),
    );
    let (_directory, executable) = executable_script(&script);
    let (_cgroup_directory, request) = process_request_for(&executable);
    let process = StdLinuxProcessBackend::default();
    let token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("resource limit helper runtime");
    runtime.block_on(async {
        // Namespace rejection is expected for this small executable fixture. The actual resource
        // limits are measured after exec and fork, before the production PID/namespace checks.
        let error = process
            .spawn_prepared(&token, &request)
            .await
            .expect_err("fixture shares the host network namespace");
        assert!(
            error.to_string().contains("distinct network namespace"),
            "unexpected rejection: {error}"
        );
        process
            .abort_spawned(&token, None)
            .await
            .expect("exact fixture processes are reaped");
    });
    let observed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).expect("actual child limit observation"))
            .expect("resource limit JSON");
    for process in ["bootstrap", "sandbox"] {
        assert_eq!(observed[process]["core"], serde_json::json!([0, 0]));
        assert_eq!(
            observed[process]["nofile"],
            serde_json::json!([65_536, 65_536])
        );
    }
    assert_eq!(
        getrlimit(Resource::RLIMIT_CORE).expect("unchanged supervisor core"),
        supervisor_core
    );
    assert_eq!(
        getrlimit(Resource::RLIMIT_NOFILE).expect("unchanged supervisor nofile"),
        supervisor_nofile
    );

    // Only this isolated helper loses its hard limit. The production spawn must refuse to increase
    // it even when launched from a namespace or service with otherwise sufficient privileges.
    setrlimit(Resource::RLIMIT_NOFILE, 65_535, 65_535).expect("reduce isolated helper hard limit");
    std::fs::remove_file(&marker).expect("remove earlier child observation");
    let rejected_token = LeaseId::new().to_string();
    let error = runtime
        .block_on(process.spawn_prepared(&rejected_token, &request))
        .expect_err("fixed child limit must not raise the inherited hard limit");
    assert!(
        error
            .to_string()
            .contains(&format!("os error {}", nix::libc::EPERM)),
        "unexpected limit rejection: {error}"
    );
    assert!(!marker.exists(), "rejected bootstrap must not execute");
    assert_eq!(
        getrlimit(Resource::RLIMIT_NOFILE).expect("rejected spawn preserves hard limit"),
        (65_535, 65_535)
    );
    runtime
        .block_on(process.abort_spawned(&rejected_token, None))
        .expect("failed pre-exec leaves no child ownership");
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_host_network_namespace_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
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

os.close(info_fd)
time.sleep(30)
"#;
    let (_directory, bwrap) = executable_script(script);
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
            .expect_err("a child in browserd's host network namespace must fail closed");
        assert!(
            error.to_string().contains("distinct network namespace"),
            "unexpected namespace rejection: {error}"
        );
        process
            .abort_spawned(&backend_token, None)
            .await
            .expect("the rejected exact child should remain abortable");
    });
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
            let process = process.clone();
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
    run_network_process_helper("std_process_exact_abort_helper");
}

#[test]
fn production_release_reaps_the_naturally_exited_bootstrap_before_forgetting_ownership() {
    run_network_process_helper("std_process_natural_release_helper");
}

#[test]
fn production_cdp_pipes_are_mapped_claimed_and_released_exactly_once() {
    run_network_process_helper("std_process_cdp_round_trip_helper");
}

#[test]
fn pinned_bubblewrap_preserves_inheritable_chromium_descriptors() {
    run_process_helper("real_bwrap_cdp_inheritance_helper");
}

#[test]
fn pinned_bubblewrap_materializes_the_sealed_chromium_executable() {
    run_process_helper("real_bwrap_named_chromium_materialization_helper");
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn real_bwrap_named_chromium_materialization_helper() {
    const EXECUTABLE: &str = "/browserd-chromium/chromium";
    const STAGE: &str = "BROWSERD_NAMED_MATERIALIZATION_STAGE";
    if let Some(stage) = std::env::var_os(STAGE) {
        assert_eq!(
            std::env::current_exe().expect("named ELF executable"),
            Path::new(EXECUTABLE)
        );
        assert_eq!(
            std::fs::read_link("/proc/self/exe").expect("canonical self executable link"),
            Path::new(EXECUTABLE)
        );
        let metadata = std::fs::metadata(EXECUTABLE).expect("named executable metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o555);
        assert_eq!(
            &std::fs::read(EXECUTABLE).expect("named ELF bytes")[..4],
            b"\x7fELF"
        );
        for descriptor in std::fs::read_dir("/proc/self/fd").expect("inherited descriptors") {
            if let Ok(target) = std::fs::read_link(descriptor.expect("descriptor entry").path()) {
                assert!(!target.to_string_lossy().contains("memfd:browserd-chromium"));
            }
        }
        if stage == "reexec" {
            return;
        }
        assert_eq!(stage, "initial");
        for result in [
            std::fs::OpenOptions::new()
                .write(true)
                .open(EXECUTABLE)
                .map(|_| ()),
            std::fs::set_permissions(EXECUTABLE, std::fs::Permissions::from_mode(0o755)),
            std::fs::remove_file(EXECUTABLE),
            std::fs::write("/browserd-chromium/replacement", b"denied"),
        ] {
            let error = result.expect_err("executable and parent must remain immutable");
            assert!(
                matches!(
                    error.raw_os_error(),
                    Some(nix::libc::EROFS | nix::libc::EPERM | nix::libc::EACCES)
                ),
                "unexpected immutable boundary error: {error}"
            );
        }
        for directory in [
            "/tmp",
            "/dev/shm",
            "/profile",
            browserd_sandbox::SANDBOX_SCRATCH_PATH,
        ] {
            std::fs::write(
                Path::new(directory).join("named-executable-write-proof"),
                b"allowed",
            )
            .expect("nested private writable mount");
        }
        let reexec = Command::new(EXECUTABLE)
            .args([
                "--ignored",
                "--exact",
                "real_bwrap_named_chromium_materialization_helper",
                "--nocapture",
            ])
            .env(STAGE, "reexec")
            .output()
            .expect("ELF self-reexec should start");
        assert!(
            reexec.status.success(),
            "named ELF self-reexec failed: {}",
            String::from_utf8_lossy(&reexec.stderr)
        );
        return;
    }
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let bytes = std::fs::read(std::env::current_exe().expect("ELF fixture source"))
        .expect("read genuine test ELF");
    assert_eq!(&bytes[..4], b"\x7fELF");
    let directory = tempfile::tempdir().expect("private materialization fixture");
    let source = directory.path().join("source-elf");
    let profile = directory.path().join("profile");
    std::fs::write(&source, &bytes).expect("ELF source");
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755))
        .expect("ELF source mode");
    std::fs::create_dir(&profile).expect("private profile directory");
    let runtime = ChromiumRuntime::from_path(&source, EXECUTABLE, chromium_digest(&bytes))
        .expect("ELF bytes should be sealed before the host alias changes");
    std::fs::write(&source, b"replaced unapproved host executable")
        .expect("replace original host alias");
    let base_spec = launch_spec(ShardId::new());
    let elf_spec = LaunchSpec::production(
        base_spec.tenant_id().clone(),
        base_spec.dedicated_egress().clone(),
        chromium_digest(&bytes),
    );
    let backend = LinuxSandboxBackend::new(
        LinuxSandboxConfig::new(
            "/sys/fs/cgroup/browserd",
            "/var/lib/browserd/shards",
            "/usr/bin/bwrap",
            runtime,
            LaunchGateRuntime::new("/usr/libexec/browserd-launch-gate", "/browserd/launch-gate"),
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
    );
    for _ in 0..2 {
        let request = backend
            .planned_spawn_request(&elf_spec)
            .expect("independent sealed ELF reader");
        let args = request.arguments();
        let copy_start = args
            .windows(2)
            .position(|window| window == ["--dir", "/browserd-chromium"])
            .expect("named executable parent");
        let copy_end = args
            .windows(3)
            .position(|window| {
                window
                    == [
                        "--ro-bind",
                        "/usr/libexec/browserd-launch-gate",
                        "/browserd/launch-gate",
                    ]
            })
            .expect("trusted gate follows named copy");
        let immutable = args
            .windows(2)
            .position(|window| window == ["--remount-ro", "/"])
            .expect("production root remount");
        let executable_fd = request.chromium_executable_fd().as_raw_fd();
        let mut command = Command::new("/usr/bin/bwrap");
        command
            .args([
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
                "--bind",
            ])
            .arg(&profile)
            .arg("/profile");
        command.args(["--tmpfs", browserd_sandbox::SANDBOX_SCRATCH_PATH]);
        for path in ["/usr", "/lib", "/lib64"] {
            if Path::new(path).is_dir() {
                command.args(["--ro-bind", path, path]);
            }
        }
        command
            .args(&args[copy_start..copy_end])
            .args(&args[immutable..immutable + 2])
            .args([
                "--setenv",
                STAGE,
                "initial",
                "--",
                EXECUTABLE,
                "--ignored",
                "--exact",
                "real_bwrap_named_chromium_materialization_helper",
                "--nocapture",
            ])
            .env_clear();
        // SAFETY: the callback runs after fork and uses only async-signal-safe fcntl calls on
        // the request-owned descriptor. The parent capability remains CLOEXEC.
        unsafe {
            command.pre_exec(move || {
                let flags = nix::libc::fcntl(executable_fd, nix::libc::F_GETFD);
                if flags < 0
                    || nix::libc::fcntl(
                        executable_fd,
                        nix::libc::F_SETFD,
                        flags & !nix::libc::FD_CLOEXEC,
                    ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command
            .output()
            .expect("bubblewrap should copy the sealed ELF to a named guest inode");
        assert!(
            output.status.success(),
            "named ELF materialization failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn real_bwrap_cdp_inheritance_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let (command_reader, command_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
        .expect("CDP command pipe should be created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("CDP event pipe should be created");
    let command_reader_source =
        nix::fcntl::fcntl(&command_reader, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(10))
            .expect("CDP command child end should be relocated");
    let event_writer_source =
        nix::fcntl::fcntl(&event_writer, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(10))
            .expect("CDP event child end should be relocated");
    // SAFETY: both fcntl calls returned fresh owned descriptors.
    let command_reader_source = unsafe { OwnedFd::from_raw_fd(command_reader_source) };
    // SAFETY: both fcntl calls returned fresh owned descriptors.
    let event_writer_source = unsafe { OwnedFd::from_raw_fd(event_writer_source) };
    drop(command_reader);
    drop(event_writer);

    let executable = std::env::current_exe().expect("test executable should be known");
    let command_reader_fd = command_reader_source.as_raw_fd();
    let event_writer_fd = event_writer_source.as_raw_fd();
    let mut command = Command::new("/usr/bin/bwrap");
    // SAFETY: the callback runs after fork and uses only async-signal-safe dup2 calls. Both source
    // descriptors were moved above Chromium's fixed targets, so neither mapping clobbers a source.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::dup2(command_reader_fd, CHROMIUM_CDP_READ_FD) != CHROMIUM_CDP_READ_FD {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::dup2(event_writer_fd, CHROMIUM_CDP_WRITE_FD) != CHROMIUM_CDP_WRITE_FD {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .args(["--ro-bind", "/", "/", "--"])
        .arg(executable)
        .arg("--ignored")
        .arg("--exact")
        .arg("real_bwrap_cdp_endpoint_helper")
        .arg("--nocapture")
        .env("BROWSERD_BWRAP_CDP_ENDPOINT", "1")
        .spawn()
        .expect("pinned bubblewrap should accept its production-compatible arguments");
    drop(command_reader_source);
    drop(event_writer_source);

    let mut command_writer = File::from(command_writer);
    command_writer
        .write_all(b"ping")
        .expect("parent command end should reach bubblewrap child FD 3");
    drop(command_writer);
    let event_flags = nix::fcntl::fcntl(&event_reader, nix::fcntl::FcntlArg::F_GETFL)
        .expect("event descriptor flags should be readable");
    nix::fcntl::fcntl(
        &event_reader,
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_truncate(event_flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .expect("event descriptor should become nonblocking for a bounded test");
    let mut event_reader = File::from(event_reader);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut response = Vec::new();
    let mut read_error = None;
    while Instant::now() < deadline && response.len() < 4 {
        let mut chunk = [0_u8; 4];
        match event_reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                read_error = Some(error);
                break;
            }
        }
    }
    assert!(
        read_error.is_none(),
        "bubblewrap CDP event read should succeed"
    );
    assert_eq!(response, b"pong");
    let status = child.wait().expect("bubblewrap child should be waitable");
    assert!(
        status.success(),
        "bubblewrap CDP endpoint should exit cleanly"
    );
}

#[test]
#[ignore = "runs only inside the real bubblewrap inheritance helper"]
fn real_bwrap_cdp_endpoint_helper() {
    if std::env::var_os("BROWSERD_BWRAP_CDP_ENDPOINT").is_none() {
        return;
    }
    // SAFETY: the isolated bubblewrap subprocess owns the two fixed Chromium descriptors.
    let mut command_reader = unsafe { File::from_raw_fd(CHROMIUM_CDP_READ_FD) };
    // SAFETY: the isolated bubblewrap subprocess owns the two fixed Chromium descriptors.
    let mut event_writer = unsafe { File::from_raw_fd(CHROMIUM_CDP_WRITE_FD) };
    let mut command = [0_u8; 4];
    command_reader
        .read_exact(&mut command)
        .expect("bubblewrap child should read its command from FD 3");
    assert_eq!(command, *b"ping");
    event_writer
        .write_all(b"pong")
        .expect("bubblewrap child should write its event to FD 4");
}

#[test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
fn std_process_cdp_round_trip_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    for descriptor in [3, 4] {
        // SAFETY: this ignored helper runs in its own subprocess and intentionally frees the two
        // Chromium descriptor targets before the production backend allocates its pipes.
        unsafe {
            nix::libc::close(descriptor);
        }
    }
    let cdp_target_reservation = File::open("/dev/null")
        .expect("the isolated helper should reserve Chromium descriptor targets");
    assert_eq!(
        cdp_target_reservation.as_raw_fd(),
        CHROMIUM_CDP_READ_FD,
        "closing low descriptors must make the first CDP source collide with target FD 3"
    );
    // SAFETY: FD 3 is the live reservation above; this isolated helper reserves FD 4 until its
    // Tokio runtime has allocated all process-lifetime descriptors away from the CDP targets.
    let reserved =
        unsafe { nix::libc::dup2(cdp_target_reservation.as_raw_fd(), CHROMIUM_CDP_WRITE_FD) };
    assert_eq!(reserved, CHROMIUM_CDP_WRITE_FD);
    let _seccomp_descriptor = install_required_launch_descriptors();
    let script = r#"#!/usr/bin/python3
import ctypes
import json
import os
import sys

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
    if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:
        os._exit(79)
    os.close(info_fd)
    approval = sys.stdin.buffer.read()
    if approval != b"browserd-launch-gate/v1 approve\n":
        os._exit(77)
    if os.read(3, 4) != b"ping":
        os._exit(78)
    os.write(4, b"pong")
    os._exit(0)

os.write(info_fd, json.dumps({"child-pid": sandbox_pid}).encode() + b"\n")
os.close(info_fd)
os.waitpid(sandbox_pid, 0)
with open(cgroup_events_path, "w") as cgroup_events:
    cgroup_events.write("populated 0\n")
os._exit(0)
"#;
    let (directory, bwrap) = executable_script(script);
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let cgroup_kill_path = request.cgroup_procs_path().with_file_name("cgroup.kill");
    std::fs::write(
        directory.path().join("cgroup-kill-path"),
        cgroup_kill_path.as_os_str().as_encoded_bytes(),
    )
    .expect("fake cgroup kill locator should be written");

    let process = StdLinuxProcessBackend::default();
    let backend_token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("helper runtime should build");
    drop(cdp_target_reservation);
    // SAFETY: FD 4 is the helper-owned duplicate installed above and has no Rust owner.
    let closed = unsafe { nix::libc::close(CHROMIUM_CDP_WRITE_FD) };
    assert_eq!(closed, 0, "reserved CDP write target should close");
    for descriptor in [CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD] {
        // SAFETY: the isolated helper intentionally verifies these raw target numbers are free.
        let result = unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) };
        assert_eq!(result, -1, "CDP target must be free before pipe creation");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::EBADF)
        );
    }
    runtime.block_on(async {
        let identity = process
            .spawn_prepared(&backend_token, &request)
            .await
            .expect("fake sandbox child should be prepared")
            .identity();
        process
            .claim_cdp_pipes(&backend_token, ChildIdentity::new(identity.pid(), 1))
            .await
            .expect_err("a stale PID identity must not claim CDP capabilities");
        let claim_barrier = Arc::new(tokio::sync::Barrier::new(3));
        let first_claim = {
            let claim_barrier = Arc::clone(&claim_barrier);
            let backend_token = backend_token.clone();
            let process = process.clone();
            tokio::spawn(async move {
                claim_barrier.wait().await;
                process.claim_cdp_pipes(&backend_token, identity).await
            })
        };
        let second_claim = {
            let claim_barrier = Arc::clone(&claim_barrier);
            let backend_token = backend_token.clone();
            let process = process.clone();
            tokio::spawn(async move {
                claim_barrier.wait().await;
                process.claim_cdp_pipes(&backend_token, identity).await
            })
        };
        claim_barrier.wait().await;
        let first_claim = first_claim.await.expect("first claim task should join");
        let second_claim = second_claim.await.expect("second claim task should join");
        let claimed = match (first_claim, second_claim) {
            (Ok(claimed), Err(error)) | (Err(error), Ok(claimed)) => {
                assert!(error.to_string().contains("already claimed"));
                Some(claimed)
            }
            _ => None,
        };
        assert!(claimed.is_some(), "exactly one concurrent claim must win");
        let Some(claimed) = claimed else {
            return;
        };

        let (command_writer, event_reader) = claimed.into_owned_fds();
        for descriptor in [&command_writer, &event_reader] {
            let flags = nix::fcntl::fcntl(descriptor, nix::fcntl::FcntlArg::F_GETFD)
                .expect("parent CDP descriptor flags should be readable");
            assert!(
                nix::fcntl::FdFlag::from_bits_truncate(flags)
                    .contains(nix::fcntl::FdFlag::FD_CLOEXEC),
                "parent CDP capabilities must not leak through unrelated exec"
            );
        }
        let event_flags = nix::fcntl::fcntl(&event_reader, nix::fcntl::FcntlArg::F_GETFL)
            .expect("event descriptor flags should be readable");
        nix::fcntl::fcntl(
            &event_reader,
            nix::fcntl::FcntlArg::F_SETFL(
                nix::fcntl::OFlag::from_bits_truncate(event_flags)
                    | nix::fcntl::OFlag::O_NONBLOCK,
            ),
        )
        .expect("event descriptor should become nonblocking for the bounded test");
        let mut command_writer = File::from(command_writer);
        let mut event_reader = File::from(event_reader);
        command_writer
            .write_all(b"ping")
            .expect("parent command end should write to child FD 3");
        process
            .release_prepared(&backend_token, identity)
            .await
            .expect("a claimed prepared child should be released");

        let mut response = Vec::new();
        let event_result = tokio::time::timeout(Duration::from_secs(1), async {
            let mut chunk = [0_u8; 16];
            loop {
                match event_reader.read(&mut chunk) {
                    Ok(0) => break Ok(()),
                    Ok(read) => response.extend_from_slice(&chunk[..read]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => break Err(error),
                }
            }
        })
        .await;
        assert!(matches!(event_result, Ok(Ok(()))));
        assert_eq!(response, b"pong");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match process.release_spawned(&backend_token, identity).await {
                    Ok(()) => break,
                    Err(error) => {
                        assert!(error.to_string().contains("live spawned child"));
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        })
        .await
        .expect("exited child ownership should become releasable");
        nix::fcntl::fcntl(&command_writer, nix::fcntl::FcntlArg::F_GETFD)
            .expect("registry release must not double-close a claimed command end");
        nix::fcntl::fcntl(&event_reader, nix::fcntl::FcntlArg::F_GETFD)
            .expect("registry release must not double-close a claimed event end");

        let second_token = LeaseId::new().to_string();
        let second_identity = process
            .spawn_prepared(&second_token, &request)
            .await
            .expect("second fake sandbox child should be prepared")
            .identity();
        process
            .release_prepared(&second_token, second_identity)
            .await
            .expect("release-before-claim must preserve registry-owned parent CDP ends");
        let late_claim = process
            .claim_cdp_pipes(&second_token, second_identity)
            .await
            .expect("the exact live identity may claim registry-owned pipes after release");
        process
            .abort_spawned(&second_token, Some(second_identity))
            .await
            .expect("released child should still abort through exact pidfds");
        nix::fcntl::fcntl(
            late_claim.command_writer(),
            nix::fcntl::FcntlArg::F_GETFD,
        )
        .expect("abort must not double-close a claimed command end");
        nix::fcntl::fcntl(late_claim.event_reader(), nix::fcntl::FcntlArg::F_GETFD)
            .expect("abort must not double-close a claimed event end");

        let unclaimed_token = LeaseId::new().to_string();
        let unclaimed_identity = process
            .spawn_prepared(&unclaimed_token, &request)
            .await
            .expect("unclaimed fake sandbox child should be prepared")
            .identity();
        process
            .abort_spawned(&unclaimed_token, Some(unclaimed_identity))
            .await
            .expect("abort should close registry-owned unclaimed CDP capabilities");
        let claim_after_abort = process
            .claim_cdp_pipes(&unclaimed_token, unclaimed_identity)
            .await;
        assert!(matches!(claim_after_abort, Err(error) if error.to_string().contains("ownership missing")));
    });
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
import ctypes
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
    if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:
        os._exit(79)
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
            .expect("fake sandbox child should be prepared")
            .identity();
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
import ctypes
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
    if ctypes.CDLL(None, use_errno=True).unshare(0x40000000) != 0:
        os._exit(79)
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
            .expect("fake sandbox child should be prepared")
            .identity();
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
        .provision(&launch_spec_for(
            shard_id,
            WorkerId::new("worker-rollback").expect("worker should be valid"),
            47,
        ))
        .await
        .expect_err("spawn failure should roll provisioning back");

    assert_eq!(
        egress_view
            .events
            .lock()
            .expect("egress event lock should work")
            .as_slice(),
        [
            "route:prepare",
            "route:cancel-reservation",
            "route:release-reservation",
        ]
    );

    let calls = egress_view
        .calls
        .lock()
        .expect("egress call lock should work");
    assert!(
        matches!(
            calls.as_slice(),
            [
                EgressCall::Prepare(_),
                EgressCall::CancelReservation(_),
                EgressCall::ReleaseReservation(_),
            ]
        ),
        "unexpected egress calls: {calls:?}"
    );
    let [
        EgressCall::Prepare(reservation),
        EgressCall::CancelReservation(cancelled_reservation),
        EgressCall::ReleaseReservation(released_reservation),
    ] = calls.as_slice()
    else {
        return;
    };
    assert_eq!(reservation.fence(), &expected);
    assert_eq!(cancelled_reservation, reservation);
    assert_eq!(released_reservation, reservation);
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
        .provision(&launch_spec_for(
            inspect_shard.clone(),
            WorkerId::new("worker-inspect").expect("worker should be valid"),
            101,
        ))
        .await
        .expect("inspect runtime should provision");
    let cleanup_handle = backend
        .provision(&launch_spec_for(
            cleanup_shard,
            WorkerId::new("worker-cleanup").expect("worker should be valid"),
            202,
        ))
        .await
        .expect("cleanup runtime should provision");
    let inspect_cgroup =
        PathBuf::from("/sys/fs/cgroup/browserd").join(format!("{inspect_shard}-launch-1"));
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
    assert!(calls.iter().any(|call| {
        matches!(call, EgressCall::IsActive(lease) if lease.reservation().fence() == &inspect_fence)
    }));
    assert!(calls.iter().any(|call| {
        matches!(call, EgressCall::Revoke(lease) if lease.reservation().fence() == &cleanup_fence)
    }));
}

#[test]
fn failed_revoke_retains_the_exact_fence_and_netns_pin_until_release_retry() {
    run_process_helper(
        "failed_revoke_retains_the_exact_fence_and_netns_pin_until_release_retry_helper",
    );
}

#[tokio::test]
#[ignore = "runs only in an isolated descriptor-owning subprocess"]
async fn failed_revoke_retains_the_exact_fence_and_netns_pin_until_release_retry_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let egress = FakeEgress {
        fail_revoke_once: Arc::new(AtomicUsize::new(1)),
        ..FakeEgress::default()
    };
    let egress_view = egress.clone();
    let backend = backend(filesystem.clone(), process, egress);
    let shard_id = ShardId::new();
    let expected = ShardEgressFence::new(shard_id.clone(), 303);
    let handle = backend
        .provision(&launch_spec_for(
            shard_id.clone(),
            WorkerId::new("worker-retry").expect("worker should be valid"),
            303,
        ))
        .await
        .expect("runtime should provision");
    let (reservation, network_namespace_fd) = egress_view
        .attached_descriptors
        .lock()
        .expect("attached descriptor lock should work")
        .iter()
        .next()
        .map(|(reservation, descriptor)| (reservation.clone(), *descriptor))
        .expect("the exact namespace descriptor should be attached");
    assert_eq!(reservation.fence(), &expected);
    filesystem
        .files
        .lock()
        .expect("file lock should work")
        .insert(
            PathBuf::from("/sys/fs/cgroup/browserd")
                .join(format!("{shard_id}-launch-1"))
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
    // SAFETY: the recorded descriptor is only queried; the runtime tombstone must still own it.
    assert_ne!(
        unsafe { nix::libc::fcntl(network_namespace_fd, nix::libc::F_GETFD) },
        -1,
        "the pinned namespace must survive until exact route release"
    );
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("the retry should revoke and release the exact ingress lease");
    // SAFETY: the recorded numeric descriptor is queried immediately after terminal runtime drop.
    assert_eq!(
        unsafe { nix::libc::fcntl(network_namespace_fd, nix::libc::F_GETFD) },
        -1,
        "the namespace pin must close after route release"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(nix::libc::EBADF)
    );

    let calls = egress_view
        .calls
        .lock()
        .expect("egress call lock should work");
    assert_eq!(
        calls
            .iter()
            .filter(|call| {
                matches!(call, EgressCall::Revoke(lease) if lease.reservation() == &reservation)
            })
            .count(),
        2
    );
    assert!(calls.iter().any(|call| {
        matches!(call, EgressCall::Release(lease) if lease.reservation() == &reservation)
    }));
    drop(calls);

    let state = egress_view
        .state
        .lock()
        .expect("route state lock should work");
    assert!(matches!(
        state.routes.get(&reservation),
        Some(FakeRouteLifecycle::LeaseReleased(_))
    ));
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
        .join(format!("{shard_id}-launch-1"))
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
            .iter()
            .any(|call| {
                matches!(call, EgressCall::Release(lease) if lease.reservation().fence() == &expected)
            })
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
        .position(|call| {
            matches!(call, EgressCall::Revoke(lease) if lease.reservation().fence() == &expected)
        })
        .expect("route revoke should be recorded");
    let release = calls
        .iter()
        .position(|call| {
            matches!(call, EgressCall::Release(lease) if lease.reservation().fence() == &expected)
        })
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
                .join(format!("{shard_id}-launch-1"))
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
        .insert(format!("browserd/{shard_id}-launch-1"));

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

#[tokio::test]
async fn runtime_handle_fences_the_cdp_capability_claim() {
    let filesystem = FakeFilesystem::production_tree();
    let process = FakeProcess {
        events: Arc::new(Mutex::new(Vec::new())),
        alive: Arc::new(Mutex::new(false)),
        identity_matches: true,
    };
    let backend = backend(filesystem, process, FakeEgress::default());
    let shard_id = ShardId::new();
    let spec = launch_spec(shard_id.clone());
    let handle = backend
        .provision(&spec)
        .await
        .expect("runtime should provision");
    let forged = browserd_sandbox::SandboxHandle::new(shard_id, LeaseId::new().to_string());

    assert!(backend.claim_cdp_pipes(&forged).await.is_err());
    let pipes = backend
        .claim_cdp_pipes(&handle)
        .await
        .expect("exact active claim succeeds");
    let binding = pipes
        .egress_proxy_binding()
        .expect("production claim carries exact route binding");
    assert!(binding.matches_launch(&spec));
    assert_eq!(
        binding.proxy_address(),
        "127.0.0.1:43117"
            .parse()
            .expect("fixed test listener endpoint")
    );
}

#[tokio::test]
async fn revoked_ingress_refuses_cdp_claim_before_consuming_process_capabilities() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let backend = backend(
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: trace.clone(),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress::default(),
    );
    let handle = backend
        .provision_gated(&launch_spec(ShardId::new()))
        .await
        .expect("gated provision");
    backend
        .revoke_egress(&handle, CleanupReason::Administrative)
        .await
        .expect("exact route revokes");
    assert!(backend.claim_cdp_pipes(&handle).await.is_err());
    assert!(
        !trace
            .lock()
            .expect("trace lock")
            .iter()
            .any(|event| event == "cdp:claim"),
        "inactive route must reject before consuming the one-shot raw pipe pair"
    );
}

#[tokio::test]
async fn addressless_ingress_refuses_cdp_claim_before_consuming_process_capabilities() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let backend = backend(
        FakeFilesystem::production_tree(),
        FakeProcess {
            events: trace.clone(),
            alive: Arc::new(Mutex::new(false)),
            identity_matches: true,
        },
        FakeEgress {
            omit_proxy_address: true,
            ..FakeEgress::default()
        },
    );
    let handle = backend
        .provision_gated(&launch_spec(ShardId::new()))
        .await
        .expect("legacy gated provision");
    assert!(backend.claim_cdp_pipes(&handle).await.is_err());
    assert!(
        !trace
            .lock()
            .expect("trace lock")
            .iter()
            .any(|event| event == "cdp:claim"),
        "missing production endpoint must reject before consuming raw pipe capabilities"
    );
}

#[tokio::test]
async fn changed_namespace_refuses_cdp_claim_before_consuming_process_capabilities() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let namespace_matches = Arc::new(AtomicBool::new(true));
    let backend = LinuxSandboxBackend::new(
        config(),
        FakeFilesystem::production_tree(),
        ClaimNamespaceProcess {
            inner: FakeProcess {
                events: trace.clone(),
                alive: Arc::new(Mutex::new(false)),
                identity_matches: true,
            },
            namespace_matches: namespace_matches.clone(),
        },
        FakeEgress::default(),
    );
    let handle = backend
        .provision_gated(&launch_spec(ShardId::new()))
        .await
        .expect("gated provision");
    namespace_matches.store(false, Ordering::SeqCst);
    assert!(backend.claim_cdp_pipes(&handle).await.is_err());
    assert!(
        !trace
            .lock()
            .expect("trace lock")
            .iter()
            .any(|event| event == "cdp:claim"),
        "changed namespace must reject before consuming raw pipe capabilities"
    );
}

#[path = "support/shared_context_routes.rs"]
mod shared_context_routes;

#[path = "support/spawn_diagnostics.rs"]
mod spawn_diagnostics;

#[test]
fn private_child_stderr_rejects_public_nonempty_append_and_readable_sinks() {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = tempfile::tempdir().expect("private sink directory");
    for (name, mode, nonempty, append, readable) in [
        ("public", 0o644, false, false, false),
        ("nonempty", 0o600, true, false, false),
        ("append", 0o600, false, true, false),
        ("readable", 0o600, false, false, true),
    ] {
        let path = directory.path().join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .read(readable)
            .append(append)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .expect("sink fixture should open");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("sink mode fixture must not depend on the invoking umask");
        if nonempty {
            file.write_all(b"private-existing")
                .expect("existing sink contents");
        }
        let error = StdLinuxProcessBackend::default()
            .with_private_child_stderr(file)
            .expect_err("unsafe diagnostic sink must reject");
        assert!(
            error
                .to_string()
                .contains("empty owned mode-0600 write-only file")
        );
        let contents = std::fs::read(&path).expect("sink fixture contents should remain available");
        assert_eq!(
            contents,
            if nonempty {
                b"private-existing".as_slice()
            } else {
                b"".as_slice()
            }
        );
    }
}

#[test]
fn production_private_stderr_capture_is_bounded_and_keeps_draining_after_the_limit() {
    run_process_helper("std_process_private_stderr_helper");
}

#[test]
#[ignore = "uses configured launch descriptors only in an isolated subprocess"]
fn std_process_private_stderr_helper() {
    use std::os::unix::fs::OpenOptionsExt;
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    let directory = tempfile::tempdir().expect("private stderr test directory");
    let marker = directory.path().join("drained");
    let capture = directory.path().join("private.stderr");
    let mut sink = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&capture)
        .expect("exclusive private sink should open");
    // The implementation must use bounded positioned writes, even if an owned OFD starts beyond
    // the limit. No read position or stream position is trusted for the file size bound.
    sink.seek(SeekFrom::Start(128 * 1024))
        .expect("fixture changes only its owned sink offset");
    let configured = StdLinuxProcessBackend::default()
        .with_private_child_stderr(sink)
        .expect("empty owned write-only capability should admit");
    let script = r#"#!/usr/bin/python3
import json,os,sys,time
info_fd=None
arguments=iter(sys.argv[1:])
for argument in arguments:
 if argument=='--info-fd': info_fd=int(next(arguments))
data=b'native-private-stderr-fixture\n'+b'x'*(512*1024)
while data:
 count=os.write(2,data)
 data=data[count:]
with open('__DRAINED_MARKER__','wb') as marker: marker.write(b'all-stderr-written')
pid=os.fork()
if pid==0:
 os.setsid()
 os.write(info_fd,json.dumps({'child-pid':os.getpid()}).encode()+b'\n')
 os.close(info_fd)
 sys.stdin.buffer.read()
 os._exit(0)
os.close(info_fd)
time.sleep(30)
"#
    .replace(
        "__DRAINED_MARKER__",
        marker.to_str().expect("private marker path"),
    );
    let (_executable_directory, executable) = executable_script(&script);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("isolated stderr test runtime");
    // A clone shares the same 16KiB run budget. The default backend still sends stderr to null.
    for process in [
        configured.clone(),
        configured,
        StdLinuxProcessBackend::default(),
    ] {
        let (_cgroup_directory, request) = process_request_for(&executable);
        let token = LeaseId::new().to_string();
        runtime.block_on(async {
            let error = process
                .spawn_prepared(&token, &request)
                .await
                .expect_err("fixture intentionally leaves the host NET namespace unchanged");
            assert!(
                error.to_string().contains("distinct network namespace"),
                "unexpected spawn failure: {error}"
            );
            assert_eq!(
                std::fs::read(&marker).expect("child proves complete stderr write"),
                b"all-stderr-written"
            );
            process
                .abort_spawned(&token, None)
                .await
                .expect("exact fixture cleanup should succeed");
        });
    }
    let contents = std::fs::read(&capture).expect("bounded private capture should read");
    assert_eq!(contents.len(), 16 * 1024);
    let prefix = b"native-private-stderr-fixture\n";
    assert_eq!(&contents[..prefix.len()], prefix);
    assert!(contents[prefix.len()..].iter().all(|byte| *byte == b'x'));
    assert_eq!(
        std::fs::metadata(&capture)
            .expect("private sink metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}
