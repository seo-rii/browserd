use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use browserd_core::WorkerId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{ProbeError, ProbeResultValue, RunBinding};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EngineRequest {
    pub schema_version: u32,
    pub binding: RunBinding,
    pub config_path: PathBuf,
    pub log_dir: PathBuf,
    pub deadline_seconds: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovedConfig {
    pub schema_version: u32,
    pub operator_approval: bool,
    pub isolated_validation: bool,
    pub validation_uid: u32,
    pub manifest_sha256: String,
    pub artifact_root: String,
    pub probe_executable: AssetExecutable,
    pub approved_assets: Vec<ApprovedAsset>,
    pub deployment: DeploymentConfig,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssetExecutable {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovedAsset {
    pub path: PathBuf,
    pub sha256: String,
    pub role: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeploymentConfig {
    pub sandbox: SandboxConfig,
    pub egress: EgressConfig,
    pub runtime: RuntimeConfig,
    pub worker: WorkerConfig,
    pub fixtures: FixtureConfig,
    pub assets: AssetConfig,
    #[serde(skip)]
    pub artifact_root: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SandboxConfig {
    pub socket_path: PathBuf,
    pub expected_server_uid: u32,
    pub daemon_epoch: u64,
    pub worker_id: String,
    pub worker_epoch: u64,
    pub cgroup_root: PathBuf,
    pub runtime_root: PathBuf,
    pub journal_directory: PathBuf,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EgressConfig {
    pub control_url: String,
    pub install_socket: PathBuf,
    pub expected_server_uid: u32,
    pub daemon_epoch: u64,
    pub worker_token: String,
    pub supervisor_token: String,
    pub policy_profile: String,
    pub policy_digest: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeConfig {
    pub redis_url: String,
    pub redis_prefix: String,
    pub safety_pin_path: PathBuf,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerConfig {
    pub state_root: PathBuf,
    pub max_session_count: usize,
    pub scanner: Option<ScannerConfig>,
    #[serde(default)]
    pub privileged_evaluate: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScannerConfig {
    pub socket_path: PathBuf,
    pub expected_uid: u32,
    pub max_database_age_millis: u64,
    pub max_future_skew_millis: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FixtureConfig {
    pub bind_address: SocketAddr,
    pub origin: String,
    pub host_direct_address: SocketAddr,
    pub private_direct_address: SocketAddr,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssetConfig {
    pub chromium_host_executable: PathBuf,
    pub chromium_sandbox_executable: PathBuf,
    pub launch_gate_host_executable: PathBuf,
    pub launch_gate_sandbox_executable: PathBuf,
    pub bwrap_executable: PathBuf,
    pub seccomp_filter: PathBuf,
    pub sandbox_daemon_executable: PathBuf,
    pub egress_daemon_executable: PathBuf,
    pub runtime_manifest: PathBuf,
    pub read_only_mounts: Vec<RuntimeMount>,
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeMount {
    pub source: PathBuf,
    pub destination: PathBuf,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeManifest {
    pub schema_version: u32,
    pub mounts: Vec<ManifestMount>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestMount {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub files: Vec<ManifestFile>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestFile {
    pub relative_path: PathBuf,
    pub sha256: String,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}
pub(super) fn private_directory(path: &Path) -> ProbeResultValue<()> {
    if !safe_absolute(path) {
        return Err(ProbeError::blocked(
            "private path must be absolute and normalized",
        ));
    }
    for p in path.ancestors() {
        let m =
            fs::symlink_metadata(p).map_err(|_| ProbeError::blocked("private path unavailable"))?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(ProbeError::blocked(
                "private path contains symlink or nondirectory",
            ));
        }
    }
    let m = fs::symlink_metadata(path)
        .map_err(|_| ProbeError::blocked("private directory unavailable"))?;
    if m.uid() != nix::unistd::Uid::effective().as_raw() || m.mode() & 0o777 != 0o700 {
        return Err(ProbeError::blocked(
            "private directory must be validation-UID owned mode0700",
        ));
    }
    Ok(())
}
pub(super) fn read_bounded(path: &Path, max: u64, root_owned: bool) -> ProbeResultValue<Vec<u8>> {
    if !safe_absolute(path) {
        return Err(ProbeError::blocked(
            "input path must be absolute and normalized",
        ));
    }
    for p in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)
            .map_err(|_| ProbeError::blocked("input ancestor unavailable"))?;
        if m.file_type().is_symlink()
            || !m.is_dir()
            || (root_owned && (m.uid() != 0 || m.mode() & 0o022 != 0))
        {
            return Err(ProbeError::blocked(
                "input ancestors are not approved immutable directories",
            ));
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ProbeError::blocked("approved input cannot be opened"))?;
    let before = file
        .metadata()
        .map_err(|_| ProbeError::blocked("input metadata unavailable"))?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() > max
        || before.mode() & 0o022 != 0
        || (root_owned && before.uid() != 0)
        || (!root_owned
            && (before.uid() != nix::unistd::Uid::effective().as_raw()
                || before.mode() & 0o077 != 0))
    {
        return Err(ProbeError::blocked(
            "input file is not bounded immutable regular private/approved input",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProbeError::blocked("input read failed"))?;
    let after = file
        .metadata()
        .map_err(|_| ProbeError::blocked("input metadata changed"))?;
    if bytes.len() as u64 > max
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ProbeError::blocked("approved input changed while reading"));
    }
    Ok(bytes)
}
pub(super) fn file_digest(path: &Path) -> ProbeResultValue<String> {
    let mut file = File::open(path)
        .map_err(|_| ProbeError::blocked("approved executable/file unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| ProbeError::blocked("asset metadata unavailable"))?;
    if !metadata.is_file() || metadata.len() > 2 * 1024 * 1024 * 1024 {
        return Err(ProbeError::blocked("asset file type/size invalid"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| ProbeError::blocked("asset read failed"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
fn immutable_asset_path(path: &Path) -> ProbeResultValue<()> {
    if !safe_absolute(path) {
        return Err(ProbeError::blocked(
            "approved asset path is not absolute/normalized",
        ));
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| ProbeError::blocked("approved asset ancestry unavailable"))?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (ancestor != path && !metadata.is_dir())
        {
            return Err(ProbeError::blocked(
                "approved asset ancestry is mutable/symlinked",
            ));
        }
    }
    Ok(())
}
fn inventory_files(source: &Path) -> ProbeResultValue<BTreeSet<PathBuf>> {
    immutable_asset_path(source)?;
    let mut pending = vec![source.to_path_buf()];
    let mut files = BTreeSet::new();
    let mut entries = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|_| ProbeError::blocked("runtime inventory directory unavailable"))?
        {
            entries += 1;
            if entries > 8192 {
                return Err(ProbeError::blocked(
                    "runtime directory inventory bound exceeded",
                ));
            }
            let entry =
                entry.map_err(|_| ProbeError::blocked("runtime inventory entry unavailable"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| ProbeError::blocked("runtime inventory metadata unavailable"))?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(ProbeError::blocked(
                    "runtime inventory contains mutable/symlinked content",
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                if files.len() >= 4096 || metadata.nlink() != 1 {
                    return Err(ProbeError::blocked(
                        "runtime file inventory size/link bound exceeded",
                    ));
                }
                files.insert(
                    path.strip_prefix(source)
                        .map_err(|_| ProbeError::blocked("runtime file escaped approved source"))?
                        .to_path_buf(),
                );
            } else {
                return Err(ProbeError::blocked(
                    "runtime inventory contains special file",
                ));
            }
        }
    }
    Ok(files)
}
pub(super) fn read_request(path: &Path) -> ProbeResultValue<EngineRequest> {
    let request: EngineRequest =
        serde_json::from_slice(&read_bounded(path, 1024 * 1024, false)?)
            .map_err(|_| ProbeError::blocked("invalid engine request schema"))?;
    validate_request(&request)?;
    Ok(request)
}

pub(super) fn validate_request(request: &EngineRequest) -> ProbeResultValue<()> {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|_| ProbeError::blocked("kernel identity unavailable"))?;
    let run = uuid::Uuid::parse_str(&request.binding.run_id)
        .map_err(|_| ProbeError::blocked("invalid kernel run UUID"))?;
    if request.schema_version != 1
        || run.is_nil()
        || request.binding.tier != "kernel"
        || request.binding.kernel_release != kernel.trim_end()
        || request.binding.machine != std::env::consts::ARCH
        || request.deadline_seconds != 7200
        || ![
            &request.binding.manifest_sha256,
            &request.binding.config_sha256,
            &request.binding.probe_executable_sha256,
        ]
        .into_iter()
        .all(|s| hex_digest(s))
    {
        return Err(ProbeError::blocked(
            "kernel request binding does not match this run/host",
        ));
    }
    if request
        .binding
        .source_revision
        .as_ref()
        .is_some_and(|value| {
            ![40, 64].contains(&value.len())
                || value.bytes().all(|b| b == b'0')
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        || request
            .binding
            .source_content_sha256
            .as_ref()
            .is_some_and(|value| !hex_digest(value))
        || (request.binding.source_dirty == Some(true)
            && request.binding.source_content_sha256.is_none())
    {
        return Err(ProbeError::blocked(
            "invalid source revision/content binding",
        ));
    }
    private_directory(&request.log_dir)?;
    Ok(())
}
pub(super) fn load_approved(request: &EngineRequest) -> ProbeResultValue<ApprovedConfig> {
    let bytes = read_bounded(&request.config_path, 1024 * 1024, true)?;
    if digest(&bytes) != request.binding.config_sha256 {
        return Err(ProbeError::blocked(
            "approved configuration digest mismatch",
        ));
    }
    let mut approved: ApprovedConfig = serde_json::from_slice(&bytes)
        .map_err(|_| ProbeError::blocked("invalid approved deployment schema"))?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if approved.schema_version != 1
        || !approved.operator_approval
        || !approved.isolated_validation
        || uid == 0
        || approved.validation_uid != uid
        || approved.manifest_sha256 != request.binding.manifest_sha256
        || approved.probe_executable.sha256 != request.binding.probe_executable_sha256
    {
        return Err(ProbeError::blocked(
            "explicit isolated operator approval binding is absent/mismatched",
        ));
    }
    if std::env::current_exe().map_err(|_| ProbeError::blocked("probe executable unavailable"))?
        != approved.probe_executable.path
        || file_digest(&approved.probe_executable.path)? != approved.probe_executable.sha256
    {
        return Err(ProbeError::blocked(
            "running probe executable differs from approved executable",
        ));
    }
    let roles = [
        "chromium_binary",
        "launch_gate",
        "bwrap",
        "seccomp",
        "sandbox_daemon",
        "egress_daemon",
        "runtime_manifest",
    ];
    let mut found = BTreeSet::new();
    let mut paths = BTreeSet::new();
    if approved.approved_assets.len() > 4096 {
        return Err(ProbeError::blocked("approved asset bound exceeded"));
    }
    for asset in &approved.approved_assets {
        immutable_asset_path(&asset.path)?;
        if !hex_digest(&asset.sha256)
            || !paths.insert(asset.path.clone())
            || (!roles.contains(&asset.role.as_str()) && asset.role != "runtime_file")
            || (asset.role != "runtime_file" && !found.insert(asset.role.as_str()))
        {
            return Err(ProbeError::blocked(
                "approved asset role/path/digest invalid",
            ));
        }
        let metadata = fs::symlink_metadata(&asset.path)
            .map_err(|_| ProbeError::blocked("approved asset missing"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || !safe_absolute(&asset.path)
            || file_digest(&asset.path)? != asset.sha256
        {
            return Err(ProbeError::blocked(
                "approved asset ownership/digest mismatch",
            ));
        }
    }
    if !roles.into_iter().all(|role| found.contains(role)) {
        return Err(ProbeError::blocked(
            "mandatory approved asset roles missing",
        ));
    }
    let assets = approved.deployment.assets.clone();
    for (role, path) in [
        ("chromium_binary", &assets.chromium_host_executable),
        ("launch_gate", &assets.launch_gate_host_executable),
        ("bwrap", &assets.bwrap_executable),
        ("seccomp", &assets.seccomp_filter),
        ("sandbox_daemon", &assets.sandbox_daemon_executable),
        ("egress_daemon", &assets.egress_daemon_executable),
        ("runtime_manifest", &assets.runtime_manifest),
    ] {
        if !approved
            .approved_assets
            .iter()
            .any(|a| a.role == role && &a.path == path)
        {
            return Err(ProbeError::blocked(
                "deployment assets disagree with approved roles",
            ));
        }
    }
    approved
        .deployment
        .artifact_root
        .clone_from(&approved.artifact_root);
    approved.deployment.validate()?;
    let artifact = read_bounded(
        &Path::new(&approved.artifact_root).join("compatibility.json"),
        1024 * 1024,
        true,
    )?;
    if digest(&artifact) != approved.manifest_sha256 {
        return Err(ProbeError::blocked("approved artifact manifest mismatch"));
    }
    let manifest: RuntimeManifest =
        serde_json::from_slice(&read_bounded(&assets.runtime_manifest, 1024 * 1024, true)?)
            .map_err(|_| ProbeError::blocked("invalid runtime inventory schema"))?;
    if manifest.schema_version != 1
        || manifest.mounts.len() != assets.read_only_mounts.len()
        || manifest.mounts.len() > 64
    {
        return Err(ProbeError::blocked(
            "runtime inventory differs from mount configuration",
        ));
    }
    let mut mounts = BTreeSet::new();
    let mut total_files = 0;
    for mount in manifest.mounts {
        if !mounts.insert((mount.source.clone(), mount.destination.clone())) {
            return Err(ProbeError::blocked("duplicate runtime inventory mount"));
        }
        if !assets.read_only_mounts.contains(&RuntimeMount {
            source: mount.source.clone(),
            destination: mount.destination.clone(),
        }) || mount.files.len() > 4096
        {
            return Err(ProbeError::blocked("runtime mount inventory mismatch"));
        }
        let expected = inventory_files(&mount.source)?;
        let mut listed = BTreeSet::new();
        for file in mount.files {
            total_files += 1;
            if file.relative_path.is_absolute()
                || file
                    .relative_path
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || !hex_digest(&file.sha256)
                || !listed.insert(file.relative_path.clone())
                || total_files > 4096
                || file_digest(&mount.source.join(&file.relative_path))? != file.sha256
            {
                return Err(ProbeError::blocked("runtime file inventory mismatch"));
            }
        }
        if expected != listed {
            return Err(ProbeError::blocked(
                "runtime manifest omits/adds actual source files",
            ));
        }
    }
    Ok(approved)
}
impl DeploymentConfig {
    pub fn worker_id(&self) -> ProbeResultValue<WorkerId> {
        WorkerId::new(&self.sandbox.worker_id)
            .map_err(|_| ProbeError::blocked("invalid approved worker ID"))
    }
    fn validate(&self) -> ProbeResultValue<()> {
        self.worker_id()?;
        if self.sandbox.daemon_epoch == 0
            || self.sandbox.worker_epoch == 0
            || self.egress.daemon_epoch == 0
            || !(2..=64).contains(&self.worker.max_session_count)
            || !hex_digest(&self.egress.policy_digest)
            || self.egress.worker_token.len() < 32
            || self.egress.supervisor_token.len() < 32
            || self.egress.worker_token == self.egress.supervisor_token
            || self.runtime.redis_url.is_empty()
            || self.runtime.redis_prefix.is_empty()
            || self.assets.read_only_mounts.len() > 128
        {
            return Err(ProbeError::blocked(
                "approved deployment limits/bindings invalid",
            ));
        }
        for path in [
            &self.sandbox.socket_path,
            &self.sandbox.cgroup_root,
            &self.sandbox.runtime_root,
            &self.sandbox.journal_directory,
            &self.egress.install_socket,
            &self.runtime.safety_pin_path,
            &self.worker.state_root,
            &self.assets.chromium_sandbox_executable,
            &self.assets.launch_gate_sandbox_executable,
        ] {
            if !safe_absolute(path) {
                return Err(ProbeError::blocked("deployment contains unsafe path"));
            }
        }
        let endpoint = url::Url::parse(&self.egress.control_url)
            .map_err(|_| ProbeError::blocked("invalid egress control URL"))?;
        if endpoint.scheme() != "http"
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || !endpoint
                .host_str()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback())
        {
            return Err(ProbeError::blocked(
                "egress control must use approved loopback origin",
            ));
        }
        private_directory(&self.worker.state_root)?;
        Ok(())
    }
}
pub(super) fn write_private(path: &Path, value: &Value) -> ProbeResultValue<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ProbeError::failed("private output encoding failed"))?;
    if bytes.len() >= 1024 * 1024 {
        return Err(ProbeError::failed(
            "private output exceeds one MiB protocol bound",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ProbeError::failed("output parent missing"))?;
    private_directory(parent)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ProbeError::failed("private output already exists or cannot be created"))?;
    file.write_all(&bytes)
        .map_err(|_| ProbeError::failed("private output encoding failed"))?;
    file.write_all(b"\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| ProbeError::failed("private output durability failed"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProbeError::failed("output directory durability failed"))
}
