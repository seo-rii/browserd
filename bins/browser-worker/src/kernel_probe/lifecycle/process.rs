use super::super::config::{AssetConfig, ManifestMount};
use super::super::rpc::{PeerPin, process_start};
use super::{Harness, ProbeError, ProbeResultValue, RuntimeManifest, config, record, with_session};
use browserd_core::ShardFence;
use browserd_sandbox::ChildIdentity;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

pub(super) struct ProcessProof {
    pub identity: ChildIdentity,
    pub net_namespace: u64,
    pub namespaces: BTreeMap<String, u64>,
    pub status: BTreeMap<String, String>,
    pub argv: Vec<String>,
}
fn process_argv(pid: u32) -> ProbeResultValue<Vec<String>> {
    let mut bytes = Vec::new();
    fs::File::open(format!("/proc/{pid}/cmdline"))
        .map_err(|_| ProbeError::failed("actual Chromium command line unavailable"))?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| ProbeError::failed("actual Chromium command line unavailable"))?;
    if bytes.len() > 65536 {
        return Err(ProbeError::failed("Chromium argv proof bound exceeded"));
    }
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| {
            String::from_utf8(part.to_vec())
                .map_err(|_| ProbeError::failed("Chromium argv not UTF8"))
        })
        .collect()
}
fn chromium_process_type(argv: &[String]) -> ProbeResultValue<Option<&str>> {
    let bytes = argv.iter().try_fold(0_usize, |total, argument| {
        total
            .checked_add(argument.len())
            .and_then(|total| total.checked_add(1))
    });
    if argv.len() > 4096 || bytes.is_none_or(|bytes| bytes > 65536) {
        return Err(ProbeError::failed(
            "Chromium process type proof exceeds its bound",
        ));
    }
    // Linux setproctitle rewrites a child command line into one space-separated argv[0].
    // Browser arguments retain their NUL boundaries; do not split individual browser values.
    let arguments = if argv.len() == 1 {
        argv[0].split_ascii_whitespace().collect::<Vec<_>>()
    } else {
        argv.iter().map(String::as_str).collect::<Vec<_>>()
    };
    let mut role = None;
    for (index, argument) in arguments.iter().enumerate() {
        let value = if *argument == "--type" {
            Some(
                arguments
                    .get(index + 1)
                    .copied()
                    .filter(|value| !value.starts_with('-'))
                    .unwrap_or(""),
            )
        } else {
            argument.strip_prefix("--type=")
        };
        if let Some(value) = value
            && role.replace(value).is_some()
        {
            return Err(ProbeError::failed(
                "actual Chromium process type is ambiguous",
            ));
        }
    }
    Ok(role)
}
fn main_browser_argv(argv: &[String], executable: &Path) -> bool {
    argv.first().is_some_and(|arg| Path::new(arg) == executable)
        && chromium_process_type(argv).is_ok_and(|role| role.is_none())
        && [
            "--remote-debugging-pipe",
            "--headless",
            "--user-data-dir=/profile",
        ]
        .into_iter()
        .all(|required| argv.iter().filter(|arg| arg.as_str() == required).count() == 1)
        && !argv.iter().any(|arg| {
            let flag = arg.split_once('=').map_or(arg.as_str(), |(flag, _)| flag);
            matches!(
                flag,
                "--no-sandbox"
                    | "--disable-seccomp-filter-sandbox"
                    | "--single-process"
                    | "--no-zygote"
            )
        })
}
fn executable_alias_metadata(pid: u32, alias: &Path) -> ProbeResultValue<fs::Metadata> {
    let executable = fs::metadata(format!("/proc/{pid}/exe"))
        .map_err(|_| ProbeError::failed("actual Chromium executable metadata unavailable"))?;
    let relative = alias
        .strip_prefix("/")
        .map_err(|_| ProbeError::failed("approved Chromium alias is not absolute"))?;
    let approved = fs::metadata(PathBuf::from(format!("/proc/{pid}/root")).join(relative))
        .map_err(|_| ProbeError::failed("actual approved Chromium alias unavailable"))?;
    if !executable.is_file()
        || !approved.is_file()
        || executable.dev() != approved.dev()
        || executable.ino() != approved.ino()
        || executable.len() != approved.len()
        || executable.mode() & 0o7777 != 0o555
    {
        return Err(ProbeError::failed(
            "actual Chromium executable does not occupy its approved named alias",
        ));
    }
    Ok(executable)
}
pub(super) fn cgroup_pids(path: &Path) -> ProbeResultValue<Vec<u32>> {
    let mut directories = vec![path.to_path_buf()];
    let mut pids = Vec::new();
    while let Some(directory) = directories.pop() {
        if directories.len() > 256 || pids.len() > 4096 {
            return Err(ProbeError::failed(
                "cgroup proof process/directory bound exceeded",
            ));
        }
        let entries = fs::read_to_string(directory.join("cgroup.procs")).map_err(|_| {
            ProbeError::failed("exact generation cgroup process inventory unavailable")
        })?;
        for value in entries.split_whitespace() {
            pids.push(
                value
                    .parse()
                    .map_err(|_| ProbeError::failed("invalid cgroup process ID"))?,
            );
        }
        for entry in fs::read_dir(directory)
            .map_err(|_| ProbeError::failed("cgroup inventory unavailable"))?
        {
            let entry = entry.map_err(|_| ProbeError::failed("cgroup entry unavailable"))?;
            if entry
                .file_type()
                .map_err(|_| ProbeError::failed("cgroup type unavailable"))?
                .is_dir()
            {
                directories.push(entry.path());
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}
fn process_proof(pid: u32) -> ProbeResultValue<ProcessProof> {
    let ticks = process_start(pid)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| ProbeError::failed("actual Chromium status unavailable"))?
        .lines()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.into(), value.trim().into()))
        })
        .collect();
    let argv = process_argv(pid)?;
    let mut namespaces = BTreeMap::new();
    for namespace in ["user", "pid", "mnt", "net", "ipc", "uts"] {
        let metadata = fs::metadata(format!("/proc/{pid}/ns/{namespace}"))
            .map_err(|_| ProbeError::failed("actual Chromium namespace proof unavailable"))?;
        namespaces.insert(namespace.to_owned(), metadata.ino());
    }
    if ticks != process_start(pid)? {
        return Err(ProbeError::failed(
            "Chromium PID was reused while observing",
        ));
    }
    Ok(ProcessProof {
        identity: ChildIdentity::new(pid, ticks),
        net_namespace: namespaces["net"],
        namespaces,
        status,
        argv,
    })
}
pub(super) fn browser_process(h: &Harness, shard: &ShardFence) -> ProbeResultValue<ProcessProof> {
    let record = record(h, shard)?;
    let expected = h.artifact.identity.binary_digest.to_string();
    let alias = &h.config.assets.chromium_sandbox_executable;
    let expected_size = fs::metadata(&h.config.assets.chromium_host_executable)
        .map_err(|_| ProbeError::failed("approved Chromium byte length unavailable"))?
        .len();
    let mut browsers = Vec::new();
    for pid in cgroup_pids(record.locators().cgroup_path())? {
        let Ok(argv) = process_argv(pid) else {
            continue;
        };
        if !main_browser_argv(&argv, alias) {
            continue;
        }
        let before = process_proof(pid)?;
        let metadata = executable_alias_metadata(pid, alias)?;
        if metadata.len() != expected_size || before.argv != argv {
            return Err(ProbeError::failed(
                "Chromium candidate changed before executable attestation",
            ));
        }
        let actual = config::file_digest(Path::new(&format!("/proc/{pid}/exe")))?;
        let after = process_proof(pid)?;
        let current = executable_alias_metadata(pid, alias)?;
        if before.identity != after.identity
            || before.argv != after.argv
            || before.namespaces != after.namespaces
            || metadata.dev() != current.dev()
            || metadata.ino() != current.ino()
            || metadata.len() != current.len()
            || metadata.mtime() != current.mtime()
            || metadata.mtime_nsec() != current.mtime_nsec()
            || metadata.ctime() != current.ctime()
            || metadata.ctime_nsec() != current.ctime_nsec()
        {
            return Err(ProbeError::failed(
                "Chromium process changed during executable attestation",
            ));
        }
        if actual == expected {
            browsers.push(after);
        }
    }
    if browsers.len() != 1 {
        return Err(ProbeError::failed(
            "exact cgroup must contain exactly one approved browser process",
        ));
    }
    let browser = browsers
        .pop()
        .ok_or_else(|| ProbeError::failed("approved browser process disappeared"))?;
    if !cgroup_pids(record.locators().cgroup_path())?.contains(&browser.identity.pid()) {
        return Err(ProbeError::failed(
            "approved browser left its exact generation cgroup",
        ));
    }
    Ok(browser)
}
pub(super) fn chromium_identity(h: &Harness) -> ProbeResultValue<Value> {
    with_session(h, |session| {
        let spec = h.rpc.spec_for_shard(&session.shard)?;
        let process = browser_process(h, &session.shard)?;
        let actual =
            config::file_digest(Path::new(&format!("/proc/{}/exe", process.identity.pid())))?;
        if actual != h.artifact.identity.binary_digest.to_string()
            || actual != spec.chromium_binary_digest().to_string()
            || process
                .argv
                .iter()
                .any(|arg| arg == "--no-sandbox" || arg == "--disable-seccomp-filter-sandbox")
        {
            return Err(ProbeError::failed(
                "actual native Chromium identity/sandbox launch differs from approved immutable launch",
            ));
        }
        let manifest = config::digest(&config::read_bounded(
            &Path::new(&h.config.artifact_root).join("compatibility.json"),
            1024 * 1024,
            true,
        )?);
        if manifest != h.binding.manifest_sha256 {
            return Err(ProbeError::failed(
                "approved artifact changed after admission",
            ));
        }
        Ok(
            json!({"manifest_sha256":manifest,"actual_binary_sha256":actual,"process_identity":process.identity,"shard":session.shard,
            "native_process_profile":spec.process_profile(),"actual_cgroup_membership":true,"sandbox_disabling_flags_absent":true}),
        )
    })
}
pub(super) fn chromium_sandbox(h: &Harness) -> ProbeResultValue<Value> {
    with_session(h, |session| {
        session.action(
            json!({"type":"navigate","url":h.fixture_url("chromium_sandbox")?,"wait_until":"load"}),
            h.deadline,
        )?;
        let browser = browser_process(h, &session.shard)?;
        let journal = record(h, &session.shard)?;
        let browser_filters = status_u64(&browser, "Seccomp_filters")?;
        let mut renderers = Vec::new();
        for pid in cgroup_pids(journal.locators().cgroup_path())? {
            let Ok(argv) = process_argv(pid) else {
                continue;
            };
            if chromium_process_type(&argv)? != Some("renderer") {
                continue;
            }
            let renderer = process_proof(pid)?;
            let digest = config::file_digest(Path::new(&format!("/proc/{pid}/exe")))?;
            if digest != h.artifact.identity.binary_digest.to_string()
                || status_u64(&renderer, "Seccomp")? != 2
                || status_u64(&renderer, "Seccomp_filters")? <= browser_filters
                || renderer.namespaces["pid"] == browser.namespaces["pid"]
                || renderer
                    .status
                    .get("CapEff")
                    .is_none_or(|caps| caps != "0000000000000000")
                || status_u64(&renderer, "NoNewPrivs")? != 1
            {
                return Err(ProbeError::failed(
                    "actual renderer lacks additional Chromium namespace/seccomp sandbox",
                ));
            }
            renderers.push(json!({"identity":renderer.identity,"seccomp_filters":status_u64(&renderer,"Seccomp_filters")?,"pid_namespace":renderer.namespaces["pid"]}));
        }
        if renderers.is_empty() || !h.fixture.saw("chromium_sandbox") {
            return Err(ProbeError::failed(
                "no real routed fixture renderer was witnessed",
            ));
        }
        Ok(
            json!({"browser":browser.identity,"browser_seccomp_filters":browser_filters,"sandboxed_renderers":renderers,"additional_renderer_sandbox":true}),
        )
    })
}
fn status_u64(process: &ProcessProof, key: &str) -> ProbeResultValue<u64> {
    process
        .status
        .get(key)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ProbeError::blocked(format!("kernel status {key} unavailable")))
}

struct LaunchArguments {
    seccomp_fd: u32,
    chromium_fd: u32,
    command_index: usize,
}
fn launch_arguments(argv: &[String], assets: &AssetConfig) -> ProbeResultValue<LaunchArguments> {
    let delimiter = argv
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| ProbeError::failed("actual bwrap has no gated command delimiter"))?;
    let options = &argv[..delimiter];
    for flag in [
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--clearenv",
    ] {
        if options.iter().filter(|arg| arg.as_str() == flag).count() != 1 {
            return Err(ProbeError::failed(
                "actual approved bwrap lacks the required namespace launch flags",
            ));
        }
    }
    let descriptor = |flag: &str| -> ProbeResultValue<u32> {
        let positions = options
            .iter()
            .enumerate()
            .filter_map(|(index, arg)| (arg == flag).then_some(index))
            .collect::<Vec<_>>();
        if positions.len() != 1 {
            return Err(ProbeError::failed(
                "actual bwrap input descriptor is ambiguous",
            ));
        }
        options
            .get(positions[0] + 1)
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|fd| *fd <= 4096)
            .ok_or_else(|| ProbeError::failed("actual bwrap input descriptor is invalid"))
    };
    let seccomp_fd = descriptor("--seccomp")?;
    if seccomp_fd <= 4 {
        return Err(ProbeError::failed(
            "actual seccomp input overlaps reserved launch descriptors",
        ));
    }
    let gate_host = assets
        .launch_gate_host_executable
        .to_str()
        .ok_or_else(|| ProbeError::failed("gate host path is not UTF8"))?;
    let gate_sandbox = assets
        .launch_gate_sandbox_executable
        .to_str()
        .ok_or_else(|| ProbeError::failed("gate sandbox alias is not UTF8"))?;
    let chromium_sandbox = assets
        .chromium_sandbox_executable
        .to_str()
        .ok_or_else(|| ProbeError::failed("Chromium sandbox alias is not UTF8"))?;
    if options
        .windows(3)
        .filter(|parts| {
            parts[0] == "--ro-bind" && parts[1] == gate_host && parts[2] == gate_sandbox
        })
        .count()
        != 1
    {
        return Err(ProbeError::failed(
            "actual bwrap does not mount the approved launch-gate alias",
        ));
    }
    let chromium_bind = options
        .windows(5)
        .enumerate()
        .filter(|(_, parts)| {
            parts[0] == "--perms"
                && parts[1] == "0555"
                && parts[2] == "--file"
                && parts[4] == chromium_sandbox
        })
        .collect::<Vec<_>>();
    if chromium_bind.len() != 1
        || options.windows(3).any(|parts| {
            matches!(
                parts[0].as_str(),
                "--file" | "--ro-bind-data" | "--bind-data" | "--ro-bind" | "--bind"
            ) && parts[2] == chromium_sandbox
                && parts[0] != "--file"
        })
        || options
            .windows(3)
            .filter(|parts| parts[0] == "--file" && parts[2] == chromium_sandbox)
            .count()
            != 1
    {
        return Err(ProbeError::failed(
            "actual bwrap does not materialize exactly one approved named Chromium descriptor",
        ));
    }
    let chromium_fd = chromium_bind[0].1[3]
        .parse::<u32>()
        .ok()
        .filter(|fd| *fd > 4 && *fd <= 4096 && *fd != seccomp_fd)
        .ok_or_else(|| ProbeError::failed("actual pinned Chromium descriptor is invalid"))?;
    let gate_index = options
        .windows(3)
        .position(|parts| {
            parts[0] == "--ro-bind" && parts[1] == gate_host && parts[2] == gate_sandbox
        })
        .ok_or_else(|| ProbeError::failed("actual gate overlay position is unavailable"))?;
    let root_remount = options
        .windows(2)
        .enumerate()
        .filter(|(_, parts)| parts[0] == "--remount-ro" && parts[1] == "/")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if root_remount.len() != 1
        || chromium_bind[0].0 + 5 > gate_index
        || gate_index + 3 > root_remount[0]
        || options[root_remount[0] + 2..] != ["--seccomp", &seccomp_fd.to_string()]
    {
        return Err(ProbeError::failed(
            "actual named Chromium launch does not finish with the approved read-only root boundary",
        ));
    }
    if argv.get(delimiter + 1).map(String::as_str) != Some(gate_sandbox) {
        return Err(ProbeError::failed(
            "actual bwrap command does not execute the approved launch gate",
        ));
    }
    let mut gate_end = delimiter + 2;
    if argv.get(gate_end).map(String::as_str) == Some("--export-scratch") {
        gate_end += 1;
    }
    if argv.get(gate_end).map(String::as_str) != Some("--")
        || argv.get(gate_end + 1).map(String::as_str) != Some(chromium_sandbox)
    {
        return Err(ProbeError::failed(
            "actual launch gate does not execute the approved Chromium alias",
        ));
    }
    Ok(LaunchArguments {
        seccomp_fd,
        chromium_fd,
        command_index: gate_end + 1,
    })
}
fn read_only_alias(
    pid: u32,
    alias: &Path,
    expected: &str,
    mountinfo: &str,
) -> ProbeResultValue<()> {
    alias
        .to_str()
        .ok_or_else(|| ProbeError::failed("approved executable alias is not UTF8"))?;
    let mounted = covering_mount_read_only(alias, mountinfo)?;
    let relative = alias
        .strip_prefix("/")
        .map_err(|_| ProbeError::failed("approved executable alias is not absolute"))?;
    if !mounted
        || config::file_digest(&PathBuf::from(format!("/proc/{pid}/root")).join(relative))?
            != expected
    {
        return Err(ProbeError::failed(
            "actual approved executable alias is missing, writable, or has a different digest",
        ));
    }
    Ok(())
}
fn covering_mount_read_only(path: &Path, mountinfo: &str) -> ProbeResultValue<bool> {
    let mut covering: Option<(&str, bool)> = None;
    for line in mountinfo.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 7 || fields[4].contains('\\') {
            return Err(ProbeError::failed(
                "actual mount proof has an invalid or escaped destination",
            ));
        }
        let destination = fields[4];
        if path.starts_with(destination) {
            let read_only = fields[5].split(',').any(|flag| flag == "ro");
            match covering {
                Some((previous, previous_ro)) if destination.len() == previous.len() => {
                    covering = Some((destination, previous_ro && read_only))
                }
                Some((previous, _)) if destination.len() < previous.len() => {}
                _ => covering = Some((destination, read_only)),
            }
        }
    }
    Ok(covering.is_some_and(|(_, read_only)| read_only))
}
fn runtime_mount_destinations(
    mount: &ManifestMount,
    executable: &Path,
) -> ProbeResultValue<Vec<PathBuf>> {
    let parent = executable
        .parent()
        .filter(|parent| *parent != Path::new("/"))
        .ok_or_else(|| ProbeError::failed("approved Chromium parent is unavailable"))?;
    if mount.destination != parent {
        if executable.starts_with(&mount.destination) || mount.destination.starts_with(executable) {
            return Err(ProbeError::failed(
                "runtime mount shadows the approved Chromium executable",
            ));
        }
        return Ok(vec![mount.destination.clone()]);
    }
    let source = fs::symlink_metadata(&mount.source)
        .map_err(|_| ProbeError::failed("approved projected runtime source unavailable"))?;
    if !source.is_dir()
        || source.file_type().is_symlink()
        || source.uid() != 0
        || source.mode() & 0o222 != 0
    {
        return Err(ProbeError::failed(
            "approved Chromium parent projection source is not immutable",
        ));
    }
    let executable_name = executable
        .file_name()
        .ok_or_else(|| ProbeError::failed("approved Chromium basename unavailable"))?;
    let mut destinations = Vec::new();
    for entry in fs::read_dir(&mount.source)
        .map_err(|_| ProbeError::failed("approved runtime projection inventory unavailable"))?
    {
        if destinations.len() == 4096 {
            return Err(ProbeError::failed(
                "approved runtime projection inventory exceeds its bound",
            ));
        }
        let entry = entry
            .map_err(|_| ProbeError::failed("approved runtime projection entry unavailable"))?;
        if entry.file_name() == executable_name {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| ProbeError::failed("approved runtime projection metadata unavailable"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(ProbeError::failed(
                "approved runtime projection contains an unsafe entry",
            ));
        }
        destinations.push(parent.join(entry.file_name()));
    }
    destinations.sort();
    Ok(destinations)
}
fn trusted_launch_chain(
    h: &Harness,
    shard: &ShardFence,
    browser: &ProcessProof,
    mountinfo: &str,
) -> ProbeResultValue<Value> {
    let daemon = process_proof(h.rpc.pin.identity.pid())?;
    if daemon.identity != h.rpc.pin.identity
        || config::file_digest(Path::new(&format!("/proc/{}/exe", daemon.identity.pid())))?
            != h.rpc.pin.executable_sha256
    {
        return Err(ProbeError::failed(
            "approved sandbox daemon process changed during outer attestation",
        ));
    }
    let mut ancestry = Vec::new();
    let mut pid = status_u64(browser, "PPid")?;
    let mut seen = std::collections::BTreeSet::new();
    while pid != u64::from(daemon.identity.pid()) {
        let pid_u32 = u32::try_from(pid)
            .ok()
            .filter(|pid| *pid > 1)
            .ok_or_else(|| {
                ProbeError::blocked(
                    "actual browser launch ancestry does not reach the pinned sandbox daemon",
                )
            })?;
        if ancestry.len() >= 64 || !seen.insert(pid_u32) {
            return Err(ProbeError::blocked(
                "actual browser launch ancestry exceeds the bounded pinned chain",
            ));
        }
        let parent = process_proof(pid_u32)?;
        pid = status_u64(&parent, "PPid")?;
        ancestry.push(parent);
    }
    let bwrap_digest = config::file_digest(&h.config.assets.bwrap_executable)?;
    let members = cgroup_pids(record(h, shard)?.locators().cgroup_path())?;
    let (bwrap, arguments) = ancestry
        .iter()
        .filter(|parent| members.contains(&parent.identity.pid()))
        .filter(|parent| {
            config::file_digest(Path::new(&format!("/proc/{}/exe", parent.identity.pid())))
                .is_ok_and(|digest| digest == bwrap_digest)
        })
        .find_map(|parent| {
            launch_arguments(&parent.argv, &h.config.assets)
                .ok()
                .map(|args| (parent, args))
        })
        .ok_or_else(|| {
            ProbeError::blocked(
                "exact live launch lacks an approved bwrap ancestor and consumed gated argv",
            )
        })?;
    if bwrap.argv[arguments.command_index..] != browser.argv {
        return Err(ProbeError::failed(
            "actual Chromium argv differs from its approved live bwrap command",
        ));
    }
    let filter_metadata = fs::metadata(&h.config.assets.seccomp_filter)
        .map_err(|_| ProbeError::blocked("approved filter metadata unavailable"))?;
    if filter_metadata.len() == 0
        || filter_metadata.len() % 8 != 0
        || filter_metadata.len() > 4096 * 8
    {
        return Err(ProbeError::failed(
            "approved seccomp filter is not a bounded raw cBPF program",
        ));
    }
    let seccomp = config::file_digest(&h.config.assets.seccomp_filter)?;
    let mut descriptor_owner = None;
    for identity in [bwrap.identity, daemon.identity] {
        let descriptor = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            identity.pid(),
            arguments.seccomp_fd
        ));
        if fs::metadata(&descriptor).is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.len() == filter_metadata.len()
                && metadata.dev() == filter_metadata.dev()
                && metadata.ino() == filter_metadata.ino()
        }) && config::file_digest(&descriptor).is_ok_and(|digest| digest == seccomp)
        {
            descriptor_owner = Some(identity);
            break;
        }
    }
    let descriptor_owner = descriptor_owner.ok_or_else(|| {
        ProbeError::blocked(
            "exact bwrap --seccomp descriptor is not the inherited approved daemon filter",
        )
    })?;
    let daemon_filters = status_u64(&daemon, "Seccomp_filters")?;
    let browser_filters = status_u64(browser, "Seccomp_filters")?;
    if browser_filters <= daemon_filters {
        return Err(ProbeError::failed(
            "actual approved bwrap launch did not add an outer seccomp filter",
        ));
    }
    let gate = config::file_digest(&h.config.assets.launch_gate_host_executable)?;
    read_only_alias(
        browser.identity.pid(),
        &h.config.assets.launch_gate_sandbox_executable,
        &gate,
        mountinfo,
    )?;
    read_only_alias(
        browser.identity.pid(),
        &h.config.assets.chromium_sandbox_executable,
        &h.artifact.identity.binary_digest.to_string(),
        mountinfo,
    )?;
    for process in ancestry.iter().chain([browser, &daemon]) {
        if ChildIdentity::new(
            process.identity.pid(),
            process_start(process.identity.pid())?,
        ) != process.identity
            || process_proof(process.identity.pid())?.status.get("PPid")
                != process.status.get("PPid")
        {
            return Err(ProbeError::failed(
                "actual launch process identity or ancestry changed during attestation",
            ));
        }
    }
    let argv_sha256 = config::digest(
        &serde_json::to_vec(&bwrap.argv)
            .map_err(|_| ProbeError::failed("launch argv evidence encoding failed"))?,
    );
    Ok(
        json!({"sandbox_daemon_identity":daemon.identity,"approved_sandbox_daemon_sha256":h.rpc.pin.executable_sha256,
        "ancestry":ancestry.iter().map(|parent|parent.identity).collect::<Vec<_>>(),"bwrap_identity":bwrap.identity,"actual_bwrap_sha256":bwrap_digest,
        "actual_bwrap_argv_sha256":argv_sha256,"consumed_seccomp_fd":arguments.seccomp_fd,"pinned_chromium_fd":arguments.chromium_fd,
        "consumed_seccomp_descriptor_owner":descriptor_owner,"consumed_seccomp_sha256":seccomp,
        "daemon_seccomp_filters":daemon_filters,"browser_seccomp_filters":browser_filters,"outer_filter_count_delta":browser_filters-daemon_filters,
        "launch_gate_alias":h.config.assets.launch_gate_sandbox_executable,"actual_launch_gate_alias_sha256":gate,
        "chromium_alias":h.config.assets.chromium_sandbox_executable,"actual_chromium_alias_sha256":h.artifact.identity.binary_digest.to_string(),
        "executable_aliases_read_only":true,"proof_kind":"approved_live_bwrap_consumption_and_kernel_filter_counter",
        "kernel_filter_readback":false,"browser_denied_syscall_observed":false}),
    )
}
const BWRAP_DEVICE_MOUNTS: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];
fn bwrap_device_mount_matches(fields: &[&str], host: &fs::Metadata, guest: &fs::Metadata) -> bool {
    fields.len() >= 10
        && BWRAP_DEVICE_MOUNTS.contains(&fields[4])
        && fields[5].split(',').any(|flag| flag == "nosuid")
        && fields
            .iter()
            .position(|field| *field == "-")
            .is_some_and(|separator| separator >= 6 && fields.len() == separator + 4)
        && host.file_type().is_char_device()
        && guest.file_type().is_char_device()
        && (host.dev(), host.ino(), host.rdev()) == (guest.dev(), guest.ino(), guest.rdev())
        && fields[2]
            == format!(
                "{}:{}",
                nix::sys::stat::major(host.dev()),
                nix::sys::stat::minor(host.dev())
            )
}
fn approved_bwrap_device_mount(pid: u32, fields: &[&str]) -> ProbeResultValue<bool> {
    let Some(destination) = fields
        .get(4)
        .filter(|path| BWRAP_DEVICE_MOUNTS.contains(*path))
    else {
        return Ok(false);
    };
    // --dev binds exactly these host character-device inodes. It does not authorize /dev/*.
    let host = fs::symlink_metadata(destination)
        .map_err(|_| ProbeError::failed("approved bwrap device source unavailable"))?;
    let guest = fs::symlink_metadata(format!("/proc/{pid}/root{destination}"))
        .map_err(|_| ProbeError::failed("actual bwrap device alias unavailable"))?;
    Ok(bwrap_device_mount_matches(fields, &host, &guest))
}
pub(super) fn outer_sandbox(h: &Harness) -> ProbeResultValue<Value> {
    with_session(h, |session| {
        let browser = browser_process(h, &session.shard)?;
        let pid = browser.identity.pid();
        if status_u64(&browser, "NoNewPrivs")? != 1
            || status_u64(&browser, "Seccomp")? != 2
            || browser
                .status
                .get("CapEff")
                .is_none_or(|caps| caps != "0000000000000000")
        {
            return Err(ProbeError::failed(
                "actual outer sandbox privilege/seccomp enforcement absent",
            ));
        }
        for (name, inode) in &browser.namespaces {
            if fs::metadata(format!("/proc/self/ns/{name}"))
                .map_err(|_| ProbeError::blocked("host namespace identity unavailable"))?
                .ino()
                == *inode
            {
                return Err(ProbeError::failed(
                    "actual browser shares a required host namespace",
                ));
            }
        }
        let manifest: RuntimeManifest = serde_json::from_slice(&config::read_bounded(
            &h.config.assets.runtime_manifest,
            1024 * 1024,
            true,
        )?)
        .map_err(|_| ProbeError::failed("approved runtime inventory changed/invalid"))?;
        let mountinfo = fs::read_to_string(format!("/proc/{pid}/mountinfo"))
            .map_err(|_| ProbeError::blocked("actual sandbox mount attestation unavailable"))?;
        let mut count = 0usize;
        let mut allowed = std::collections::BTreeSet::from([
            "/".to_owned(),
            "/proc".to_owned(),
            "/dev".to_owned(),
            "/dev/pts".to_owned(),
            "/dev/shm".to_owned(),
            "/tmp".to_owned(),
            "/profile".to_owned(),
            browserd_sandbox::SANDBOX_SCRATCH_PATH.to_owned(),
            h.config
                .assets
                .chromium_sandbox_executable
                .to_string_lossy()
                .into_owned(),
            h.config
                .assets
                .launch_gate_sandbox_executable
                .to_string_lossy()
                .into_owned(),
        ]);
        for mount in manifest.mounts {
            for projected in
                runtime_mount_destinations(&mount, &h.config.assets.chromium_sandbox_executable)?
            {
                let destination = projected.to_str().ok_or_else(|| {
                    ProbeError::failed("approved projected runtime path is not UTF8")
                })?;
                allowed.insert(destination.to_owned());
                if !mountinfo
                    .lines()
                    .any(|line| line.split_whitespace().nth(4) == Some(destination))
                    || !covering_mount_read_only(&projected, &mountinfo)?
                {
                    return Err(ProbeError::failed(
                        "approved runtime mount is absent or writable in actual browser",
                    ));
                }
            }
            for file in mount.files {
                let relative = mount
                    .destination
                    .strip_prefix("/")
                    .map_err(|_| ProbeError::failed("invalid approved mount destination"))?
                    .join(&file.relative_path);
                let path = PathBuf::from(format!("/proc/{pid}/root")).join(relative);
                if config::file_digest(&path)? != file.sha256
                    || config::file_digest(&mount.source.join(&file.relative_path))? != file.sha256
                {
                    return Err(ProbeError::failed(
                        "actual mounted runtime file digest mismatch",
                    ));
                }
                count += 1;
            }
        }
        let catalog = browserd_chromium::VerifiedNativeProfileCatalog::load(
            Path::new(&h.config.artifact_root),
            &h.artifact,
        )
        .map_err(|_| ProbeError::failed("native mounted resource inventory invalid"))?;
        let parent = h
            .config
            .assets
            .chromium_sandbox_executable
            .parent()
            .ok_or_else(|| ProbeError::failed("native binary destination parent absent"))?;
        let locale_dir = parent.join("locales");
        allowed.insert(locale_dir.to_string_lossy().into_owned());
        let locale = catalog
            .locale_resources()
            .iter()
            .find(|resource| resource.locale == "ko-KR")
            .ok_or_else(|| ProbeError::failed("native locale resource absent"))?;
        for (destination, expected) in [
            (locale_dir.join("ko-KR.pak"), locale.digest),
            (parent.join("icudtl.dat"), catalog.icu_data().1),
        ] {
            allowed.insert(destination.to_string_lossy().into_owned());
            let actual = PathBuf::from(format!("/proc/{pid}/root")).join(
                destination
                    .strip_prefix("/")
                    .map_err(|_| ProbeError::failed("native destination not absolute"))?,
            );
            if config::file_digest(&actual)? != expected.to_string() {
                return Err(ProbeError::failed(
                    "actual sealed native locale/ICU resource differs from approved profile",
                ));
            }
        }
        for line in mountinfo.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 7
                || fields[4].contains('\\')
                || (if BWRAP_DEVICE_MOUNTS.contains(&fields[4]) {
                    !approved_bwrap_device_mount(pid, &fields)?
                } else {
                    !allowed.contains(fields[4])
                })
            {
                return Err(ProbeError::failed(
                    "actual outer sandbox contains an unapproved effective mount",
                ));
            }
        }
        let launch_chain = trusted_launch_chain(h, &session.shard, &browser, &mountinfo)?;
        Ok(
            json!({"shard":session.shard,"process_identity":browser.identity,"namespaces":browser.namespaces,"no_new_privs":1,"effective_capabilities":"0",
            "seccomp_mode":2,"trusted_launch_chain":launch_chain,"mounted_runtime_files_verified":count,"all_inventory_mounts_read_only":true}),
        )
    })
}
pub(super) fn verify_http_listener(peer: &PeerPin, url: &str) -> ProbeResultValue<()> {
    let parsed =
        url::Url::parse(url).map_err(|_| ProbeError::blocked("approved egress URL invalid"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ProbeError::blocked("approved egress port unavailable"))?;
    let mut inodes = std::collections::BTreeSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(rows) = fs::read_to_string(path) {
            for row in rows.lines().skip(1) {
                let fields = row.split_whitespace().collect::<Vec<_>>();
                if fields.len() > 9
                    && fields[3] == "0A"
                    && fields[1]
                        .rsplit_once(':')
                        .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
                        == Some(port)
                {
                    inodes.insert(fields[9].to_owned());
                }
            }
        }
    }
    let matched = fs::read_dir(format!("/proc/{}/fd", peer.identity.pid()))
        .map_err(|_| ProbeError::blocked("approved egress listener ownership inaccessible"))?
        .take(4096)
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .any(|target| {
            target
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
                .is_some_and(|inode| inodes.contains(inode))
        });
    if !matched
        || ChildIdentity::new(peer.identity.pid(), process_start(peer.identity.pid())?)
            != peer.identity
    {
        return Err(ProbeError::blocked(
            "actual HTTP egress listener is not owned by the pinned approved daemon",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn assets() -> AssetConfig {
        AssetConfig {
            chromium_host_executable: "/approved/chromium".into(),
            chromium_sandbox_executable: "/runtime/chromium".into(),
            launch_gate_host_executable: "/approved/gate".into(),
            launch_gate_sandbox_executable: "/runtime/gate".into(),
            bwrap_executable: "/usr/bin/bwrap".into(),
            seccomp_filter: "/approved/filter.bpf".into(),
            sandbox_daemon_executable: "/approved/sandboxd".into(),
            egress_daemon_executable: "/approved/egressd".into(),
            runtime_manifest: "/approved/runtime.json".into(),
            read_only_mounts: Vec::new(),
        }
    }
    fn argv() -> Vec<String> {
        [
            "/usr/bin/bwrap",
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--clearenv",
            "--dir",
            "/runtime",
            "--perms",
            "0555",
            "--file",
            "17",
            "/runtime/chromium",
            "--ro-bind",
            "/approved/gate",
            "/runtime/gate",
            "--remount-ro",
            "/",
            "--seccomp",
            "5",
            "--",
            "/runtime/gate",
            "--export-scratch",
            "--",
            "/runtime/chromium",
            "--remote-debugging-pipe",
            "--headless",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn launch_attestation_requires_exact_consumed_gate_and_descriptor_arguments() {
        let argv = argv();
        let proof = launch_arguments(&argv, &assets());
        assert!(proof.is_ok_and(|proof| proof.seccomp_fd == 5
            && proof.chromium_fd == 17
            && argv[proof.command_index] == "/runtime/chromium"));
        let mut wrong = assets();
        wrong.launch_gate_host_executable = "/approved/unused-gate".into();
        assert!(launch_arguments(&argv, &wrong).is_err());
        let mut wrong = assets();
        wrong.chromium_sandbox_executable = "/runtime/unused-chromium".into();
        assert!(launch_arguments(&argv, &wrong).is_err());
    }
    #[test]
    fn launch_attestation_rejects_ambiguous_filters_missing_namespace_and_cdp_fd() {
        let mut duplicate = argv();
        let delimiter = duplicate
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or_default();
        let _ = duplicate.splice(delimiter..delimiter, ["--seccomp".into(), "9".into()]);
        assert!(launch_arguments(&duplicate, &assets()).is_err());
        let mut missing = argv();
        missing.retain(|arg| arg != "--unshare-net");
        assert!(launch_arguments(&missing, &assets()).is_err());
        let mut reserved = argv();
        if let Some(position) = reserved.iter().position(|arg| arg == "--seccomp") {
            reserved[position + 1] = "3".into();
        }
        assert!(launch_arguments(&reserved, &assets()).is_err());
        let mut command_only = argv();
        if let Some(position) = command_only.iter().position(|arg| arg == "--seccomp") {
            let _ = command_only.drain(position..position + 2);
        }
        command_only.extend(["--seccomp".into(), "5".into()]);
        assert!(launch_arguments(&command_only, &assets()).is_err());
    }
    fn browser_argv() -> Vec<String> {
        [
            "/runtime/chromium",
            "--remote-debugging-pipe",
            "--headless",
            "--no-startup-window",
            "--user-data-dir=/profile",
            "--disable-features=BackForwardCache",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn browser_classification_excludes_real_flattened_child_titles_before_hashing() {
        let browser = browser_argv();
        let children = [
            vec!["/runtime/chromium --type=zygote --headless".to_owned()],
            vec![
                "/runtime/chromium --type=renderer --headless --user-data-dir=/profile".to_owned(),
            ],
            vec!["/runtime/chromium --type=gpu-process --headless".to_owned()],
        ];
        assert!(main_browser_argv(
            &browser,
            &assets().chromium_sandbox_executable
        ));
        assert_eq!(
            children
                .iter()
                .chain([&browser])
                .filter(|argv| main_browser_argv(argv, &assets().chromium_sandbox_executable))
                .count(),
            1
        );
        assert!(chromium_process_type(&children[0]).is_ok_and(|role| role == Some("zygote")));
        assert!(chromium_process_type(&children[1]).is_ok_and(|role| role == Some("renderer")));
        assert!(
            !main_browser_argv(&[browser.join(" ")], &assets().chromium_sandbox_executable),
            "a title string is never a replacement for the approved browser argv"
        );
    }
    #[test]
    fn process_type_parser_handles_normal_split_and_flattened_forms_without_value_false_positives()
    {
        for argv in [
            vec!["/runtime/chromium".into(), "--type=renderer".into()],
            vec![
                "/runtime/chromium".into(),
                "--type".into(),
                "renderer".into(),
            ],
            vec!["/runtime/chromium --type=renderer --headless".into()],
            vec!["/runtime/chromium --type renderer --headless".into()],
        ] {
            assert!(chromium_process_type(&argv).is_ok_and(|role| role == Some("renderer")));
            assert!(!main_browser_argv(
                &argv,
                &assets().chromium_sandbox_executable
            ));
        }
        let mut browser = browser_argv();
        browser.extend([
            "--user-agent=label --type=renderer".into(),
            "--typewriter=renderer".into(),
            "--utility-sub-type=renderer".into(),
        ]);
        assert!(chromium_process_type(&browser).is_ok_and(|role| role.is_none()));
        assert!(main_browser_argv(
            &browser,
            &assets().chromium_sandbox_executable
        ));
        for extra in [
            "--type=",
            "--type",
            "--type=unknown",
            "--single-process",
            "--no-zygote",
            "--no-sandbox=true",
            "--disable-seccomp-filter-sandbox=true",
        ] {
            let mut invalid = browser_argv();
            invalid.push(extra.into());
            assert!(
                !main_browser_argv(&invalid, &assets().chromium_sandbox_executable),
                "invalid main invocation: {extra}"
            );
        }
        assert!(
            chromium_process_type(&["/runtime/chromium --type=renderer --type=zygote".into()])
                .is_err()
        );
        assert!(chromium_process_type(&["x".repeat(65537)]).is_err());
        assert!(chromium_process_type(&vec!["x".to_owned(); 4097]).is_err());
        for required in [
            "--remote-debugging-pipe",
            "--headless",
            "--user-data-dir=/profile",
        ] {
            let mut missing = browser_argv();
            missing.retain(|arg| arg != required);
            assert!(!main_browser_argv(
                &missing,
                &assets().chromium_sandbox_executable
            ));
            let mut duplicated = browser_argv();
            duplicated.push(required.into());
            assert!(!main_browser_argv(
                &duplicated,
                &assets().chromium_sandbox_executable
            ));
        }
        let mut wrong_path = browser_argv();
        wrong_path[0] = "/runtime/unapproved-chromium".into();
        assert!(!main_browser_argv(
            &wrong_path,
            &assets().chromium_sandbox_executable
        ));
    }
    #[test]
    fn named_launch_attestation_requires_mode_read_only_root_and_final_mount_order() {
        let mut wrong_mode = argv();
        let permissions = wrong_mode
            .iter()
            .position(|arg| arg == "--perms")
            .unwrap_or_default();
        wrong_mode[permissions + 1] = "0755".into();
        assert!(launch_arguments(&wrong_mode, &assets()).is_err());
        let mut legacy = argv();
        let copy = legacy
            .iter()
            .position(|arg| arg == "--file")
            .unwrap_or_default();
        legacy[copy] = "--ro-bind-data".into();
        assert!(launch_arguments(&legacy, &assets()).is_err());
        let mut missing = argv();
        let remount = missing
            .iter()
            .position(|arg| arg == "--remount-ro")
            .unwrap_or_default();
        let _ = missing.drain(remount..remount + 2);
        assert!(launch_arguments(&missing, &assets()).is_err());
        let mut late_copy = argv();
        let seccomp = late_copy
            .iter()
            .position(|arg| arg == "--seccomp")
            .unwrap_or_default();
        let _ = late_copy.splice(
            seccomp..seccomp,
            ["--file".into(), "19".into(), "/runtime/late-file".into()],
        );
        assert!(launch_arguments(&late_copy, &assets()).is_err());
        let mut shadow = argv();
        let remount = shadow
            .iter()
            .position(|arg| arg == "--remount-ro")
            .unwrap_or_default();
        let _ = shadow.splice(
            remount..remount,
            [
                "--ro-bind".into(),
                "/unapproved/chromium".into(),
                "/runtime/chromium".into(),
            ],
        );
        assert!(launch_arguments(&shadow, &assets()).is_err());
    }
    fn mount_rows(entries: &[(&str, &str)]) -> String {
        entries
            .iter()
            .enumerate()
            .map(|(index, (destination, flags))| {
                format!(
                    "{} 0 0:1 / {destination} {flags} - tmpfs tmpfs {flags}\n",
                    index + 1
                )
            })
            .collect()
    }
    #[test]
    fn read_only_alias_uses_the_longest_covering_mount_and_rejects_writable_overlays() {
        let executable = Path::new("/runtime/chromium");
        assert!(
            covering_mount_read_only(
                executable,
                &mount_rows(&[("/", "ro"), ("/profile", "rw"), ("/tmp", "rw")])
            )
            .is_ok_and(|ro| ro)
        );
        assert!(
            covering_mount_read_only(executable, &mount_rows(&[("/", "ro"), ("/runtime", "rw")]))
                .is_ok_and(|ro| !ro)
        );
        assert!(
            covering_mount_read_only(
                executable,
                &mount_rows(&[("/", "rw"), ("/runtime/chromium", "ro")])
            )
            .is_ok_and(|ro| ro)
        );
        assert!(
            covering_mount_read_only(
                executable,
                &mount_rows(&[("/", "ro"), ("/runtime/chromium-extra", "rw")])
            )
            .is_ok_and(|ro| ro)
        );
        for flags in [
            [("/runtime", "rw"), ("/runtime", "ro")],
            [("/runtime", "ro"), ("/runtime", "rw")],
        ] {
            assert!(
                covering_mount_read_only(executable, &mount_rows(&flags)).is_ok_and(|ro| !ro),
                "ambiguous stacked writeability must fail closed"
            );
        }
        assert!(covering_mount_read_only(executable, "malformed").is_err());
    }
    #[test]
    fn runtime_projection_exception_does_not_admit_other_executable_ancestors_or_descendants() {
        for destination in [
            "/",
            "/runtime",
            "/runtime/nested/chromium",
            "/runtime/nested/chromium/child",
        ] {
            let mount = ManifestMount {
                source: "/unavailable/source".into(),
                destination: destination.into(),
                files: Vec::new(),
            };
            assert!(
                runtime_mount_destinations(&mount, Path::new("/runtime/nested/chromium")).is_err()
            );
        }
        let mount = ManifestMount {
            source: "/unavailable/source".into(),
            destination: "/usr".into(),
            files: Vec::new(),
        };
        assert!(
            runtime_mount_destinations(&mount, Path::new("/runtime/chromium"))
                .is_ok_and(|destinations| destinations == [PathBuf::from("/usr")])
        );
    }
    fn device_mount_row(destination: &str, device: u64, flags: &str) -> String {
        format!(
            "1 0 {}:{} / {destination} {flags} - tmpfs tmpfs rw",
            nix::sys::stat::major(device),
            nix::sys::stat::minor(device)
        )
    }
    #[test]
    fn bwrap_device_mounts_require_the_exact_six_host_character_device_inodes()
    -> std::io::Result<()> {
        for destination in BWRAP_DEVICE_MOUNTS {
            let host = fs::symlink_metadata(destination)?;
            let row = device_mount_row(destination, host.dev(), "rw,nosuid");
            let fields = row.split_whitespace().collect::<Vec<_>>();
            assert!(
                approved_bwrap_device_mount(std::process::id(), &fields)
                    .is_ok_and(|approved| approved),
                "the fixed device must resolve to the same host inode through the proc root"
            );
        }
        let host = fs::symlink_metadata("/dev/null")?;
        for destination in [
            "/dev",
            "/dev/mem",
            "/dev/sda",
            "/dev/net/tun",
            "/dev/console",
            "/dev/pts/0",
            "/dev/null/child",
            "/dev/null-extra",
        ] {
            let row = device_mount_row(destination, host.dev(), "rw,nosuid");
            let fields = row.split_whitespace().collect::<Vec<_>>();
            assert!(!bwrap_device_mount_matches(&fields, &host, &host));
            assert!(
                approved_bwrap_device_mount(u32::MAX, &fields).is_ok_and(|approved| !approved),
                "unlisted paths must be rejected without consulting a process root"
            );
        }
        Ok(())
    }
    #[test]
    fn bwrap_device_mounts_reject_substituted_devices_and_regular_files() -> std::io::Result<()> {
        let host = fs::symlink_metadata("/dev/null")?;
        let substituted = fs::symlink_metadata("/dev/zero")?;
        let regular = fs::metadata("/proc/self/exe")?;
        let row = device_mount_row("/dev/null", host.dev(), "rw,nosuid");
        let fields = row.split_whitespace().collect::<Vec<_>>();
        assert_ne!(host.rdev(), substituted.rdev());
        assert!(!bwrap_device_mount_matches(&fields, &host, &substituted));
        assert!(!bwrap_device_mount_matches(&fields, &substituted, &host));
        assert!(!bwrap_device_mount_matches(&fields, &host, &regular));
        assert!(!bwrap_device_mount_matches(&fields, &regular, &host));
        assert!(!bwrap_device_mount_matches(&fields, &regular, &regular));
        Ok(())
    }
    #[test]
    fn bwrap_device_mounts_require_nosuid_and_matching_mount_device_identity() -> std::io::Result<()>
    {
        let host = fs::symlink_metadata("/dev/null")?;
        for flags in ["rw", "rw,suid", "rw,nosuid-extra"] {
            let row = device_mount_row("/dev/null", host.dev(), flags);
            assert!(!bwrap_device_mount_matches(
                &row.split_whitespace().collect::<Vec<_>>(),
                &host,
                &host
            ));
        }
        let row = device_mount_row("/dev/null", host.dev(), "rw,nosuid");
        let mut fields = row.split_whitespace().collect::<Vec<_>>();
        let original_device = fields[2];
        fields[2] = "invalid";
        assert!(!bwrap_device_mount_matches(&fields, &host, &host));
        fields[2] = "0:4294967295";
        assert!(!bwrap_device_mount_matches(&fields, &host, &host));
        assert!(!bwrap_device_mount_matches(&fields[..6], &host, &host));
        fields[2] = original_device;
        fields[6] = "missing-separator";
        assert!(!bwrap_device_mount_matches(&fields, &host, &host));
        Ok(())
    }
}
