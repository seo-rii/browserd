#![allow(clippy::expect_used)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ShardId, WorkerId};
use browserd_sandbox::{
    CgroupLimits, ChildIdentity, ChromiumRuntime, CleanupReason, EgressRouteBackend, LaunchSpec,
    LinuxProcessBackend, LinuxSandboxBackend, LinuxSandboxConfig, ProcessSignal, ReadOnlyMount,
    SandboxBackend, SandboxError, SandboxFilesystem, SpawnRequest, StdLinuxProcessBackend,
    StdSandboxFilesystem,
};

#[derive(Clone, Default)]
struct FakeFilesystem {
    files: Arc<Mutex<HashMap<PathBuf, String>>>,
    directories: Arc<Mutex<HashSet<PathBuf>>>,
    symlinks: Arc<Mutex<HashSet<PathBuf>>>,
    unwritable: Arc<Mutex<HashSet<PathBuf>>>,
    failing_writes: Arc<Mutex<HashSet<String>>>,
    failing_directories: Arc<Mutex<HashSet<String>>>,
    failing_removes: Arc<Mutex<HashSet<String>>>,
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
        for file in ["/opt/chromium/chrome", "/usr/bin/bwrap"] {
            filesystem
                .files
                .lock()
                .expect("file lock should work")
                .insert(PathBuf::from(file), String::new());
        }
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
        if self
            .failing_removes
            .lock()
            .expect("failing remove lock should work")
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return Err(SandboxError::Backend("injected remove failure".into()));
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
    async fn spawn(&self, request: &SpawnRequest) -> Result<ChildIdentity, SandboxError> {
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

    async fn abort_spawned(&self, _identity: ChildIdentity) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("signal:Kill".into());
        *self.alive.lock().expect("alive lock should work") = false;
        Ok(())
    }

    async fn release_spawned(&self, _identity: ChildIdentity) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn identity_matches(&self, _identity: ChildIdentity) -> Result<bool, SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("identity".into());
        Ok(self.identity_matches)
    }

    async fn signal(
        &self,
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

    async fn is_alive(&self, _identity: ChildIdentity) -> Result<bool, SandboxError> {
        Ok(*self.alive.lock().expect("alive lock should work"))
    }

    async fn wait(&self, _duration: Duration) {}
}

#[derive(Clone, Copy)]
enum SpawnFault {
    Spawn,
    InvalidIdentity,
    MismatchedIdentity,
}

#[derive(Clone)]
struct FaultProcess {
    fault: SpawnFault,
    events: Arc<Mutex<Vec<String>>>,
    alive: Arc<Mutex<bool>>,
}

#[async_trait]
impl LinuxProcessBackend for FaultProcess {
    async fn spawn(&self, _request: &SpawnRequest) -> Result<ChildIdentity, SandboxError> {
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
            SpawnFault::Spawn => unreachable!("spawn fault returned above"),
        })
    }

    async fn abort_spawned(&self, _identity: ChildIdentity) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("process event lock should work")
            .push("signal:Kill".into());
        *self.alive.lock().expect("alive lock should work") = false;
        Ok(())
    }

    async fn release_spawned(&self, _identity: ChildIdentity) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn identity_matches(&self, _identity: ChildIdentity) -> Result<bool, SandboxError> {
        Ok(!matches!(self.fault, SpawnFault::MismatchedIdentity))
    }

    async fn signal(
        &self,
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

    async fn is_alive(&self, _identity: ChildIdentity) -> Result<bool, SandboxError> {
        Ok(*self.alive.lock().expect("alive lock should work"))
    }

    async fn wait(&self, _duration: Duration) {}
}

#[derive(Clone, Default)]
struct FakeEgress {
    events: Arc<Mutex<Vec<String>>>,
    active: Arc<Mutex<HashSet<ShardId>>>,
    fail_prepare: bool,
    fail_revoke: bool,
}

#[async_trait]
impl EgressRouteBackend for FakeEgress {
    async fn prepare(&self, shard_id: &ShardId) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:prepare".into());
        if self.fail_prepare {
            self.active
                .lock()
                .expect("active lock should work")
                .insert(shard_id.clone());
            return Err(SandboxError::Backend("route unavailable".into()));
        }
        self.active
            .lock()
            .expect("active lock should work")
            .insert(shard_id.clone());
        Ok(())
    }

    async fn revoke(&self, shard_id: &ShardId) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("egress lock should work")
            .push("route:revoke".into());
        self.active
            .lock()
            .expect("active lock should work")
            .remove(shard_id);
        if self.fail_revoke {
            return Err(SandboxError::Backend("route revoke failed".into()));
        }
        Ok(())
    }

    async fn is_active(&self, shard_id: &ShardId) -> Result<bool, SandboxError> {
        Ok(self
            .active
            .lock()
            .expect("active lock should work")
            .contains(shard_id))
    }
}

fn config() -> LinuxSandboxConfig {
    LinuxSandboxConfig::new(
        "/sys/fs/cgroup/browserd",
        "/var/lib/browserd/shards",
        "/usr/bin/bwrap",
        ChromiumRuntime::new("/opt/chromium/chrome", "/opt/browser/chrome"),
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
            .contains(shard_id)
    );
    assert!(!*alive.lock().expect("alive lock should work"));
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
        "cgroup.procs=4242",
    ] {
        assert!(writes.contains(setting), "missing {setting}");
    }
    assert_eq!(
        egress
            .events
            .lock()
            .expect("egress lock should work")
            .as_slice(),
        ["route:prepare"]
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
async fn spawn_failure_revokes_route_then_removes_runtime_and_cgroup() {
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
    assert!(events[spawn + 2].starts_with("remove:/var/lib/browserd/shards/"));
    assert!(events[spawn + 3].starts_with("remove:/sys/fs/cgroup/browserd/"));
}

#[tokio::test]
async fn rollback_reports_cleanup_failures_and_continues_in_reverse_order() {
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
    let error = LinuxSandboxBackend::new(config(), filesystem, process, egress)
        .provision(&launch_spec(shard_id))
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
    assert!(events[revoke + 1].starts_with("remove:/var/lib/browserd/shards/"));
    assert!(events[revoke + 2].starts_with("remove:/sys/fs/cgroup/browserd/"));
}

#[tokio::test]
async fn invalid_or_mismatched_identity_still_terminates_owned_child_before_rollback() {
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
        assert!(kill < revoke);
        assert!(events[revoke + 1].starts_with("remove:/var/lib/browserd/shards/"));
        assert!(events[revoke + 2].starts_with("remove:/sys/fs/cgroup/browserd/"));
    }
}

#[tokio::test]
async fn cgroup_attach_failure_revokes_route_and_terminates_spawned_child() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut filesystem = FakeFilesystem::production_tree();
    filesystem.events = trace.clone();
    filesystem
        .failing_writes
        .lock()
        .expect("failing write lock should work")
        .insert("cgroup.procs".into());
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
    assert!(kill < revoke);
    assert!(events[revoke + 1].starts_with("remove:/var/lib/browserd/shards/"));
    assert!(events[revoke + 2].starts_with("remove:/sys/fs/cgroup/browserd/"));
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
        .spawn(&request)
        .await
        .expect_err("a closed seccomp descriptor must fail closed");
    assert!(error.to_string().contains("required inherited descriptor"));
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
        3
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
