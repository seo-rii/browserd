#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use browser_egressd::allocate_daemon_epoch;
use browser_sandboxd::{
    EgressClientConfig, EgressRouteAdapter, HttpEgressControl, LinuxPreparedShardRecovery,
};
use browserd_core::WorkerId;
use browserd_sandbox::{
    CgroupLimits, ChromiumBinaryDigest, ChromiumRuntime, FilePreparedShardJournal,
    LaunchGateRuntime, LinuxSandboxBackend, LinuxSandboxConfig, PreparedShardJournalLimits,
    PreparedShardRecoveryRoots, ReadOnlyMount, SandboxRpcConfig, SandboxRpcPeerBinding,
    SandboxRpcServer, SandboxSupervisor, StartupPreparedShardReconciler, StdLinuxProcessBackend,
    StdSandboxFilesystem, SupervisorConfig,
};
use nix::fcntl::{Flock, FlockArg, OFlag, open};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat};
use serde::Deserialize;
use tokio::net::UnixListener as TokioUnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const MAX_RPC_CONNECTIONS: usize = 1024;
const MAX_RPC_FRAME_BYTES: usize = 1024 * 1024;

struct Config {
    socket_path: PathBuf,
    journal_directory: PathBuf,
    daemon_epoch_state: PathBuf,
    cgroup_root: PathBuf,
    runtime_root: PathBuf,
    worker_id: WorkerId,
    worker_epoch: u64,
    expected_peer_uid: u32,
    supervisor: SupervisorConfig,
    rpc: SandboxRpcConfig,
    linux: LinuxSandboxConfig,
    egress: EgressClientConfig,
    recovery_timeout: Duration,
    recovery_concurrency: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MountWire {
    source: PathBuf,
    destination: PathBuf,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let socket_path = required_path("BROWSERD_SANDBOX_SOCKET")?;
        validate_service_socket_path(&socket_path)?;
        let journal_directory = required_path("BROWSERD_SANDBOX_JOURNAL_DIR")?;
        let daemon_epoch_state = required_path("BROWSERD_SANDBOXD_EPOCH_STATE")?;
        let cgroup_root = required_path("BROWSERD_SANDBOX_CGROUP_ROOT")?;
        let runtime_root = required_path("BROWSERD_SANDBOX_RUNTIME_ROOT")?;
        let worker_id = WorkerId::new(required("BROWSERD_WORKER_ID")?)
            .context("BROWSERD_WORKER_ID is invalid")?;
        let worker_epoch = parse::<u64>("BROWSERD_WORKER_EPOCH")?;
        let expected_peer_uid = parse::<u32>("BROWSERD_SANDBOX_EXPECTED_PEER_UID")?;
        let supervisor_lease = duration_ms("BROWSERD_SUPERVISOR_LEASE_MILLIS")?;
        let directory_lease = duration_ms("BROWSERD_DIRECTORY_LEASE_MILLIS")?;
        let cleanup_timeout = duration_ms("BROWSERD_SANDBOX_CLEANUP_TIMEOUT_MILLIS")?;
        let supervisor = SupervisorConfig::new(supervisor_lease, directory_lease)
            .and_then(|config| config.with_cleanup_stage_timeout(cleanup_timeout))
            .context("supervisor lease or cleanup bounds are invalid")?;
        let request_timeout = duration_ms("BROWSERD_SANDBOX_RPC_TIMEOUT_MILLIS")?;
        let sweep_interval = duration_ms("BROWSERD_SANDBOX_LEASE_SWEEP_MILLIS")?;
        let max_frame_bytes = parse::<usize>("BROWSERD_SANDBOX_RPC_MAX_FRAME_BYTES")?;
        let max_connections = parse::<usize>("BROWSERD_SANDBOX_RPC_MAX_CONNECTIONS")?;
        if max_frame_bytes > MAX_RPC_FRAME_BYTES || max_connections > MAX_RPC_CONNECTIONS {
            bail!("sandbox RPC bounds exceed the production maximum");
        }
        let peer_binding =
            SandboxRpcPeerBinding::new(expected_peer_uid, worker_id.clone(), worker_epoch)
                .context("sandbox RPC peer binding is invalid")?;
        let rpc = SandboxRpcConfig::new(
            max_frame_bytes,
            max_connections,
            request_timeout,
            sweep_interval,
            Some(expected_peer_uid),
        )
        .and_then(|config| config.with_peer_binding(peer_binding))
        .context("sandbox RPC configuration is invalid")?;

        let mounts: Vec<MountWire> =
            serde_json::from_str(&required("BROWSERD_SANDBOX_READ_ONLY_MOUNTS_JSON")?)
                .context("BROWSERD_SANDBOX_READ_ONLY_MOUNTS_JSON is invalid")?;
        let chromium_digest =
            ChromiumBinaryDigest::from_hex(&required("BROWSERD_CHROMIUM_BINARY_SHA256")?)
                .context("BROWSERD_CHROMIUM_BINARY_SHA256 is invalid")?;
        let chromium = ChromiumRuntime::from_path(
            required_path("BROWSERD_CHROMIUM_HOST_EXECUTABLE")?,
            required_path("BROWSERD_CHROMIUM_SANDBOX_EXECUTABLE")?,
            chromium_digest,
        )
        .context("BROWSERD_CHROMIUM_HOST_EXECUTABLE could not be pinned")?;
        let launch_gate = LaunchGateRuntime::new(
            required_path("BROWSERD_LAUNCH_GATE_HOST_EXECUTABLE")?,
            required_path("BROWSERD_LAUNCH_GATE_SANDBOX_EXECUTABLE")?,
        );
        let cgroup_limits = CgroupLimits::new(
            parse("BROWSERD_SANDBOX_MEMORY_MAX_BYTES")?,
            parse("BROWSERD_SANDBOX_MEMORY_HIGH_BYTES")?,
            parse("BROWSERD_SANDBOX_PIDS_MAX")?,
            parse("BROWSERD_SANDBOX_CPU_QUOTA")?,
            parse("BROWSERD_SANDBOX_CPU_PERIOD")?,
        )
        .context("sandbox cgroup limits are invalid")?;
        let seccomp_fd = parse::<i32>("BROWSERD_SANDBOX_SECCOMP_FD")?;
        let linux = LinuxSandboxConfig::new(
            cgroup_root.clone(),
            runtime_root.clone(),
            required_path("BROWSERD_BWRAP_EXECUTABLE")?,
            chromium,
            launch_gate,
            mounts
                .into_iter()
                .map(|mount| ReadOnlyMount::new(mount.source, mount.destination)),
            cgroup_limits,
            seccomp_fd,
            duration_ms("BROWSERD_SANDBOX_TERMINATION_GRACE_MILLIS")?,
            duration_ms("BROWSERD_SANDBOX_PROCESS_POLL_MILLIS")?,
        )
        .context("Linux sandbox configuration is invalid")?;

        let egress = EgressClientConfig::new(
            required("BROWSERD_EGRESS_CONTROL_URL")?
                .parse()
                .context("BROWSERD_EGRESS_CONTROL_URL is invalid")?,
            required_path("BROWSERD_EGRESS_INSTALL_SOCKET")?,
            parse("BROWSERD_EGRESS_DAEMON_EPOCH")?,
            parse("BROWSERD_EGRESS_EXPECTED_SERVER_UID")?,
            required("BROWSERD_EGRESS_WORKER_TOKEN")?,
            required("BROWSERD_EGRESS_SUPERVISOR_TOKEN")?,
            duration_ms("BROWSERD_EGRESS_REQUEST_TIMEOUT_MILLIS")?,
            parse("BROWSERD_EGRESS_MAX_RESPONSE_BYTES")?,
        )
        .context("egress control configuration is invalid")?;

        let recovery_timeout = duration_ms("BROWSERD_SANDBOX_RECOVERY_TIMEOUT_MILLIS")?;
        let recovery_concurrency = parse::<usize>("BROWSERD_SANDBOX_RECOVERY_CONCURRENCY")?;
        if recovery_timeout.is_zero() || recovery_concurrency == 0 || recovery_concurrency > 64 {
            bail!("startup recovery bounds are invalid");
        }

        Ok(Self {
            socket_path,
            journal_directory,
            daemon_epoch_state,
            cgroup_root,
            runtime_root,
            worker_id,
            worker_epoch,
            expected_peer_uid,
            supervisor,
            rpc,
            linux,
            egress,
            recovery_timeout,
            recovery_concurrency,
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).with_context(|| format!("{name} is required"))
}

fn required_path(name: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(required(name)?);
    if !path.is_absolute()
        || path == Path::new("/")
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("{name} must be a normalized absolute path");
    }
    Ok(path)
}

fn parse<T>(name: &str) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    required(name)?
        .parse()
        .map_err(|error| anyhow::anyhow!("{name} is invalid: {error}"))
}

fn duration_ms(name: &str) -> anyhow::Result<Duration> {
    Ok(Duration::from_millis(parse(name)?))
}

fn validate_service_socket_path(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("sandbox socket needs an absolute parent")?;
    if path.starts_with("/tmp")
        || path.starts_with("/var/tmp")
        || path.starts_with("/run/user")
        || path.file_name().is_none()
    {
        bail!("sandbox socket path is unsafe");
    }
    let canonical = parent
        .canonicalize()
        .context("sandbox socket parent must already exist")?;
    if canonical != parent {
        bail!("sandbox socket parent must not traverse symbolic links");
    }
    let metadata = canonical
        .metadata()
        .context("sandbox socket parent metadata unavailable")?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.mode() & 0o022 != 0
    {
        bail!("sandbox socket parent ownership or mode is unsafe");
    }
    Ok(())
}

fn reclaim_stale_socket(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("sandbox socket metadata unavailable"),
    };
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("existing sandbox socket is not an owned mode-0600 Unix socket");
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!("another sandbox supervisor is already listening"),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(error).context("could not prove sandbox socket is stale"),
    }
    std::fs::remove_file(path).context("could not remove stale owned sandbox socket")
}

struct OwnedSocketPathGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
    armed: bool,
    path_pin: Option<OwnedFd>,
}

impl OwnedSocketPathGuard {
    fn new(path: PathBuf, dev: u64, ino: u64) -> Self {
        let path_pin = open(
            &path,
            OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .ok()
        .and_then(|fd| match fstat(&fd) {
            Ok(metadata) if metadata.st_dev == dev && metadata.st_ino == ino => Some(fd),
            _ => None,
        });
        Self {
            path,
            dev,
            ino,
            armed: true,
            path_pin,
        }
    }

    fn remove(&mut self) -> anyhow::Result<()> {
        let result = remove_owned_socket(&self.path, self.dev, self.ino);
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for OwnedSocketPathGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_owned_socket(&self.path, self.dev, self.ino);
        }
    }
}

struct ServiceSocketOwnership {
    socket_path: OwnedSocketPathGuard,
    _singleton_lock: Flock<OwnedFd>,
}

impl ServiceSocketOwnership {
    fn remove_socket(mut self) -> anyhow::Result<()> {
        self.socket_path.remove()
    }
}

fn bind_service_socket_owned(
    path: &Path,
) -> anyhow::Result<(std::os::unix::net::UnixListener, ServiceSocketOwnership)> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    let lock_fd = open(
        &lock_path,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    )
    .context("sandbox singleton lock open failed")?;
    let lock_metadata = fstat(&lock_fd).context("sandbox singleton lock metadata failed")?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !SFlag::from_bits_truncate(lock_metadata.st_mode).contains(SFlag::S_IFREG)
        || lock_metadata.st_uid != effective_uid
        || lock_metadata.st_nlink != 1
    {
        bail!("sandbox singleton lock ownership or type is unsafe");
    }
    fchmod(&lock_fd, Mode::from_bits_truncate(0o600))
        .context("sandbox singleton lock mode update failed")?;
    let singleton_lock =
        Flock::lock(lock_fd, FlockArg::LockExclusiveNonblock).map_err(|(_lock_fd, error)| {
            anyhow::anyhow!("sandbox singleton lock unavailable: {error}")
        })?;
    let locked_metadata = fstat(&*singleton_lock)
        .context("sandbox singleton lock metadata failed after acquisition")?;
    let path_metadata = std::fs::symlink_metadata(&lock_path)
        .context("sandbox singleton lock path metadata failed")?;
    if !path_metadata.file_type().is_file()
        || path_metadata.uid() != effective_uid
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.dev() != locked_metadata.st_dev
        || path_metadata.ino() != locked_metadata.st_ino
    {
        bail!("sandbox singleton lock path changed during acquisition");
    }

    reclaim_stale_socket(path)?;
    let listener =
        std::os::unix::net::UnixListener::bind(path).context("sandbox RPC socket bind failed")?;
    let socket_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(listener);
            let _ = std::fs::remove_file(path);
            return Err(error).context("sandbox RPC socket metadata failed after bind");
        }
    };
    let socket_guard = OwnedSocketPathGuard::new(
        path.to_path_buf(),
        socket_metadata.dev(),
        socket_metadata.ino(),
    );
    if socket_guard.path_pin.is_none() {
        bail!("sandbox RPC socket inode could not be pinned");
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("sandbox RPC socket mode update failed")?;
    let metadata = std::fs::symlink_metadata(path).context("sandbox RPC socket metadata failed")?;
    if !metadata.file_type().is_socket()
        || metadata.mode() & 0o777 != 0o600
        || metadata.dev() != socket_metadata.dev()
        || metadata.ino() != socket_metadata.ino()
    {
        bail!("sandbox RPC socket did not retain its required type and mode");
    }
    Ok((
        listener,
        ServiceSocketOwnership {
            socket_path: socket_guard,
            _singleton_lock: singleton_lock,
        },
    ))
}

fn remove_owned_socket(path: &Path, expected_dev: u64, expected_ino: u64) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("sandbox socket metadata failed at shutdown"),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected_dev
        || metadata.ino() != expected_ino
    {
        bail!("refusing to remove a replaced sandbox socket");
    }
    std::fs::remove_file(path).context("owned sandbox socket removal failed")
}

async fn shutdown_signal() -> io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let sandboxd_epoch = allocate_daemon_epoch(&config.daemon_epoch_state)
        .context("durable sandboxd epoch allocation failed")?;
    info!(
        daemon_epoch = sandboxd_epoch.get(),
        worker_id = config.worker_id.as_str(),
        worker_epoch = config.worker_epoch,
        peer_uid = config.expected_peer_uid,
        "browser-sandboxd incarnation allocated"
    );

    let recovery_roots =
        PreparedShardRecoveryRoots::new(config.cgroup_root.clone(), config.runtime_root.clone())
            .context("prepared-shard recovery roots are invalid")?;
    let journal = Arc::new(
        FilePreparedShardJournal::open_with_limits_and_roots(
            &config.journal_directory,
            PreparedShardJournalLimits::default(),
            recovery_roots,
        )
        .context("prepared-shard journal open failed")?,
    );
    let egress_control = Arc::new(HttpEgressControl::new(config.egress.clone())?);
    let authenticated_egress_epoch = egress_control
        .authenticated_current_daemon_epoch()
        .await
        .context("authenticated egress daemon epoch probe failed")?;
    if authenticated_egress_epoch != config.egress.daemon_epoch() {
        bail!(
            "configured egress daemon epoch {} does not match authenticated current epoch {}",
            config.egress.daemon_epoch(),
            authenticated_egress_epoch
        );
    }
    let recovery = Arc::new(LinuxPreparedShardRecovery::new(
        Arc::clone(&egress_control),
        config.cgroup_root.clone(),
        config.runtime_root.clone(),
    )?);
    let recovery_report = StartupPreparedShardReconciler::new(
        Arc::clone(&journal),
        recovery,
        config.recovery_timeout,
    )?
    .with_max_concurrency(config.recovery_concurrency)?
    .start_detached()
    .wait()
    .await
    .context("startup prepared-shard reconciliation failed")?;
    if recovery_report.cleanup_pending() != 0 {
        bail!(
            "startup reconciliation left {} shard(s) pending cleanup",
            recovery_report.cleanup_pending()
        );
    }
    let post_recovery_egress_epoch = egress_control
        .authenticated_current_daemon_epoch()
        .await
        .context("post-recovery egress daemon epoch probe failed")?;
    if post_recovery_egress_epoch != authenticated_egress_epoch {
        bail!(
            "egress daemon epoch changed during recovery from {} to {}",
            authenticated_egress_epoch,
            post_recovery_egress_epoch
        );
    }

    let filesystem =
        StdSandboxFilesystem::new(config.cgroup_root.clone(), config.runtime_root.clone())?;
    let backend = LinuxSandboxBackend::new(
        config.linux,
        filesystem,
        StdLinuxProcessBackend::default(),
        EgressRouteAdapter::new((*egress_control).clone()),
    )
    .with_prepared_journal(Arc::clone(&journal), config.egress.daemon_epoch())?;
    let supervisor = Arc::new(SandboxSupervisor::new(config.supervisor, backend));
    let rpc = config
        .rpc
        .with_daemon_epoch(sandboxd_epoch.get())
        .context("sandbox RPC daemon epoch binding failed")?;
    let server = SandboxRpcServer::new(supervisor, rpc);

    // Binding happens only after every durable record reached a released tombstone.
    let (listener, socket_ownership) = bind_service_socket_owned(&config.socket_path)?;
    listener
        .set_nonblocking(true)
        .context("sandbox RPC socket nonblocking mode failed")?;
    let listener =
        TokioUnixListener::from_std(listener).context("sandbox RPC socket registration failed")?;
    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        if let Err(error) = shutdown_signal().await {
            error!(%error, "sandbox shutdown signal watcher failed");
        }
        signal_shutdown.cancel();
    });
    let result = server.serve(listener, shutdown).await;
    signal_task.abort();
    let _ = signal_task.await;
    let socket_result = socket_ownership.remove_socket();
    result.context("sandbox RPC server failed")?;
    socket_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::os::unix::fs::MetadataExt;

    use super::*;

    #[test]
    fn socket_singleton_lock_outlives_listener_and_allows_exact_stale_reclaim_after_owner_drop() {
        let directory = tempfile::tempdir().expect("temporary socket directory should exist");
        let socket_path = directory.path().join("sandboxd.sock");

        let (listener, ownership) = bind_service_socket_owned(&socket_path)
            .expect("the first daemon should acquire socket ownership");
        drop(listener);
        assert!(
            bind_service_socket_owned(&socket_path).is_err(),
            "a stale-looking socket must not be reclaimed while its singleton owner is alive"
        );

        drop(ownership);
        let (replacement, replacement_ownership) = bind_service_socket_owned(&socket_path)
            .expect("dropping the singleton owner should permit exact stale inode reclamation");
        assert!(socket_path.exists());
        drop(replacement);
        drop(replacement_ownership);
    }

    #[test]
    fn owned_socket_path_guard_removes_only_its_exact_inode() {
        let directory = tempfile::tempdir().expect("temporary socket directory should exist");
        let socket_path = directory.path().join("sandboxd.sock");

        let listener =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("owned socket should bind");
        let metadata = std::fs::symlink_metadata(&socket_path).expect("metadata should exist");
        let exact_guard =
            OwnedSocketPathGuard::new(socket_path.clone(), metadata.dev(), metadata.ino());
        drop(listener);
        drop(exact_guard);
        assert!(
            !socket_path.exists(),
            "an exact owned socket inode should be cleaned on the error path"
        );

        let original = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("original socket should bind");
        let original_metadata =
            std::fs::symlink_metadata(&socket_path).expect("original metadata should exist");
        let stale_guard = OwnedSocketPathGuard::new(
            socket_path.clone(),
            original_metadata.dev(),
            original_metadata.ino(),
        );
        drop(original);
        std::fs::remove_file(&socket_path).expect("original pathname should unlink");
        let replacement = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("replacement socket should bind");
        let replacement_metadata =
            std::fs::symlink_metadata(&socket_path).expect("replacement metadata should exist");

        drop(stale_guard);
        let preserved =
            std::fs::symlink_metadata(&socket_path).expect("replacement must be preserved");
        assert_eq!(preserved.dev(), replacement_metadata.dev());
        assert_eq!(preserved.ino(), replacement_metadata.ino());
        drop(replacement);
    }
}
