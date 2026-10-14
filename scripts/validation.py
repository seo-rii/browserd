#!/usr/bin/env python3
"""Run separate browserd validation gates, without treating absent infrastructure as success.

Kernel/soak runners are trusted, deployment-specific executable files, configured through
BROWSERD_KERNEL_RUNNER / BROWSERD_SOAK_RUNNER. They receive no shell-expanded arguments.
The runner must write JSON to BROWSERD_VALIDATION_RECEIPT with the exact run_id, tier,
manifest_sha256, kernel_release and machine from BROWSERD_VALIDATION_* and a probes object. Every required probe
must contain {"status": "passed", "evidence": "path or durable evidence identifier"}.
Use --describe to inspect the probe names and infrastructure contract. A zero exit
without a complete, current receipt fails. The soak runner must actually run >=72h.
External kernel/soak runners return 2 for incomplete deployment prerequisites or
probes, which blocks the gate. Ordinary test commands returning 2 still fail.

Logs may contain service diagnostics: keep them private; publish report.json only.
This program starts test commands, never database services or deployment resources.
Live Chromium Rust/Python functional suites run explicitly in the kernel tier with
BROWSERD_TEST_CHROMIUM derived from the verified artifact; they do not replace the
deployment runner's sandbox and kernel qualification receipt.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.parse import urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_profile_artifact import (
    CATALOG_PATH, MAX_CATALOG_BYTES, MAX_RESOURCE_BYTES, decode_json,
    validate_manifest, validate_native_catalog,
)


TIERS = ("fast", "adapter", "process", "kernel", "soak")
LIVE_BROWSER_SUITES = frozenset({"live_chromium_input", "live_chromium_capture", "live_chromium_viewer", "live_chromium_emulation", "live_chromium_downloads", "live_chromium_workers", "live_chromium_evaluate", "live_chromium_shared_context"})
ADAPTER_SUITES = frozenset({
    ("browser-gateway", "worker_notifications"),
    ("browserd-coordination", "notification_import"),
    ("browserd-coordination", "postgres_event_outbox"),
    ("browserd-coordination", "postgres_operation_events"),
    ("browserd-coordination", "postgres_opt_in"),
    ("browserd-coordination", "postgres_webhook_store"),
    ("browserd-coordination", "redis_event_outbox"),
    ("browserd-coordination", "redis_gateway_actions"),
    ("browserd-coordination", "redis_worker_opt_in"),
    ("browserd-coordination", "safety_authority"),
})
PROCESS_SUITES = frozenset({
    ("browserd-launch-gate", "launch_gate"),
    ("browserd-sandbox", "rpc_contract"),
    ("browserd-worker", "rpc_transport"),
    ("browser-sandboxd", "startup_config"),
})
KERNEL_PROBES = (
    "chromium_identity", "chromium_sandbox", "outer_sandbox", "context_create_dispose",
    "proxy_loopback", "direct_egress_denial", "target_pause_resume", "context_ownership",
    "emulation", "downloads", "pdf_streaming", "screencast_ack", "orphan_targets_zero",
    "start_stop_1000", "worker_sigkill_cleanup", "cross_shard_isolation",
)
SOAK_PROBES = (
    "mixed_workload_72h", "bounded_memory_slope", "bounded_disk_inodes",
    "orphan_processes_zero", "orphan_routes_zero", "action_ordering", "tenant_fairness",
)
BOOKKEEPING_FILES = frozenset({"STAGING.md", "DONE.md", "MISTAKES.md", "RISK_REGISTER.md"})
SOURCE_VARIABLES = (
    "BROWSERD_VALIDATION_SOURCE_REVISION", "BROWSERD_VALIDATION_SOURCE_DIRTY",
    "BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256",
)


class GateError(Exception):
    """An unmet prerequisite or missing validation evidence."""


def source_identity(root: Path) -> dict:
    """Bind evidence to source, excluding only intentionally uncommitted bookkeeping."""
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
        status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root, stderr=subprocess.DEVNULL, text=True)
        dirty = any(line[3:] not in BOOKKEEPING_FILES for line in status.splitlines())
        return {"source_revision": revision, "source_dirty": dirty}
    except (OSError, subprocess.SubprocessError):
        return {"source_revision": None, "source_dirty": True}


def source_content_identity(root: Path) -> str | None:
    """Hash current Git source bytes, including untracked files, without following links.

    Pin each directory and detect file/list changes while reading. Missing tracked
    files and symlink text are part of the snapshot. An unreadable or oversized
    tree cannot provide source evidence.
    """
    def paths() -> list[bytes]:
        listing = subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, stderr=subprocess.DEVNULL)
        return sorted({path for path in listing.split(b"\0") if path and
                       os.fsdecode(path) not in BOOKKEEPING_FILES})

    def stamp(info: os.stat_result) -> tuple:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    try:
        names = paths()
        digest = hashlib.sha256(b"browserd-source-v1\0")
        total = 0
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with ExitStack() as root_stack:
            root_fd = os.open(root, directory_flags)
            root_stack.callback(os.close, root_fd)
            for name in names:
                parts = name.split(b"/")
                if name.startswith(b"/") or any(part in {b"", b".", b".."} for part in parts):
                    return None
                digest.update(len(name).to_bytes(8, "big"))
                digest.update(name)
                with ExitStack() as stack:
                    parent = root_fd
                    try:
                        for part in parts[:-1]:
                            parent = os.open(part, directory_flags, dir_fd=parent)
                            stack.callback(os.close, parent)
                        info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        digest.update(b"missing\0")
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        content = os.fsencode(os.readlink(parts[-1], dir_fd=parent))
                        digest.update(b"symlink\0" + len(content).to_bytes(8, "big") + content)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_size > 64 * 1024 * 1024:
                            return None
                        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        stack.callback(os.close, fd)
                        if stamp(os.fstat(fd)) != stamp(info):
                            return None
                        content_hash = hashlib.sha256()
                        count = 0
                        while chunk := os.read(fd, 1024 * 1024):
                            count += len(chunk)
                            total += len(chunk)
                            if count > 64 * 1024 * 1024 or total > 1024 * 1024 * 1024:
                                return None
                            content_hash.update(chunk)
                        if count != info.st_size or stamp(os.fstat(fd)) != stamp(info):
                            return None
                        digest.update(b"file\0" + stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
                        digest.update(count.to_bytes(8, "big") + content_hash.digest())
                    else:
                        return None
                    if stamp(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != stamp(info):
                        return None
        return digest.hexdigest() if paths() == names else None
    except (OSError, subprocess.SubprocessError):
        return None


@dataclass(frozen=True)
class Command:
    name: str
    argv: tuple[str, ...]
    cwd: Path
    timeout: float = 3600


def inventory(root: Path) -> dict[tuple[str, str], str]:
    result = {}
    for manifest in sorted(root.glob("*/*/Cargo.toml")):
        package = tomllib.loads(manifest.read_text())["package"]["name"]
        for source in sorted((manifest.parent / "tests").glob("*.rs")):
            target = (package, source.stem)
            if target in ADAPTER_SUITES:
                # Mixed memory/real-service suites run here as a whole. The adapter
                # URLs are mandatory, so an early return cannot qualify the suite.
                tier = "adapter"
            elif target == ("browserd-sandbox", "linux_backend") or (package == "browserd-worker" and source.stem in LIVE_BROWSER_SUITES):
                # Includes namespace and pinned-bubblewrap tests. Ignored functions are
                # subprocess helpers invoked by their nonignored parent tests, not gates.
                tier = "kernel"
            elif target in PROCESS_SUITES:
                tier = "process"
            else:
                tier = "fast"
                # Live suites read their browser through shared helpers, so the name marks them.
                if source.stem.startswith("live_") or re.search(r'env::var\("BROWSERD_[A-Z_]*TEST_[A-Z_]*"', source.read_text()):
                    raise GateError(f"classify new infrastructure-dependent suite: {package}/{source.stem}")
            result[target] = tier
    if not result:
        raise GateError("no Cargo integration test suites were found")
    return result


def build_plan(tier: str, root: Path) -> list[Command]:
    commands = []
    if tier == "fast":
        commands.extend([
            Command("runner-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_validation.py"), root),
            Command("packaging-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_package_release.py"), root),
            Command("device-tools-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*device*.py"), root),
            Command("device-host-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_setup_validation_host.py"), root),
            Command("production-probe-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_production_kernel_runner.py"), root),
            Command("kernel-probe-assets-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_prepare_kernel_probe_assets.py"), root),
            Command("kernel-probe-seccomp-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_kernel_probe_seccomp.py"), root),
            Command("kernel-probe-lab-tests", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_kernel_probe_lab.py"), root),
            Command("native-fixture-tests", ("cargo", "test", "--locked", "-p", "browserd-worker",
                    "--test", "live_chromium_emulation",
                    "live_chromium::"), root),
            Command("rust-format", ("cargo", "fmt", "--all", "--", "--check"), root),
            Command("rust-clippy", ("cargo", "clippy", "--locked", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"), root),
            Command("rust-unit", ("cargo", "test", "--locked", "--workspace", "--lib", "--bins"), root),
            Command("rust-doc", ("cargo", "test", "--locked", "--workspace", "--doc"), root),
            Command("python-sdk", (sys.executable, "-m", "unittest", "discover", "-s", "tests"), root / "sdk/python"),
            Command("typescript-install", ("npm", "ci", "--ignore-scripts"), root / "sdk/typescript"),
            Command("typescript-check", ("npm", "run", "typecheck"), root / "sdk/typescript"),
            Command("typescript-test", ("npm", "test"), root / "sdk/typescript"),
            Command("typescript-build", ("npm", "run", "build"), root / "sdk/typescript"),
            Command("viewer-test", ("npm", "test"), root / "viewer-web"),
            Command("viewer-check", ("npm", "run", "check"), root / "viewer-web"),
        ])
    if tier == "kernel":
        commands.append(Command("live-chromium-python", (sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_chromium_*.py"), root))
        commands.append(Command("foreign-netns", ("cargo", "test", "--locked", "-p", "browserd-sandbox",
            "--lib", "netns_listener_tests::privileged_helper_enters_the_exact_foreign_namespace",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("nested-netns", ("cargo", "test", "--locked", "-p", "browserd-sandbox",
            "--lib", "netns_listener_tests::parent_user_namespace_enters_the_exact_nested_bubblewrap_namespace",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("scratch-byte-bound", ("cargo", "test", "--locked", "-p", "browserd-sandbox",
            "--test", "scratch_capability", "private_tmpfs_capability_enforces_a_physical_byte_limit",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("scratch-rpc-handoff", ("cargo", "test", "--locked", "-p", "browserd-sandbox",
            "--test", "scratch_rpc", "three_fd_rpc_preserves_exact_directory_and_rejects_swapped_inode",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("scratch-gate-handoff", ("cargo", "test", "--locked", "-p", "browserd-launch-gate",
            "--test", "scratch_gate", "gate_exports_exact_bounded_mount_before_approval_then_executes",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("file-input-artifacts", ("cargo", "test", "--locked", "-p", "browserd-worker",
            "--lib", "chromium_owner::uploads::live_tests::actual_owner_file_inputs_preserve_names_bytes_and_scope",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("origin-bound-secrets", ("cargo", "test", "--locked", "-p", "browserd-worker",
            "--lib", "chromium_owner::secrets::live_tests::actual_owner_secret_fill_preserves_origin_and_redacts_results",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("storage-checkpoint", ("cargo", "test", "--locked", "-p", "browserd-worker",
            "--lib", "chromium_owner::checkpoints::live_tests::actual_owner_checkpoint_roundtrip_without_network_or_reapplication",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("frame-node-input", ("cargo", "test", "--locked", "-p", "browserd-worker",
            "--lib", "chromium_owner::frames::live_tests::actual_owner_nested_frames_and_oopif_input_are_fenced",
            "--", "--ignored", "--exact"), root))
        commands.append(Command("typed-approvals", ("cargo", "test", "--locked", "-p", "browserd-worker",
            "--lib", "chromium_owner::approvals::live_tests::actual_owner_typed_approvals_bind_child_secret_files_and_blank_context",
            "--", "--ignored", "--exact"), root))
    suites = inventory(root)
    if tier == "adapter" and {target for target, gate in suites.items() if gate == tier} != ADAPTER_SUITES:
        raise GateError("adapter inventory changed; update the explicit required suites")
    packages: dict[str, list[str]] = {}
    for (package, target), gate in suites.items():
        if gate == tier:
            packages.setdefault(package, []).append(target)
    for package, targets in packages.items():
        args = ["cargo", "test", "--locked", "-p", package]
        for target in targets:
            args.extend(["--test", target])
        if package == "browserd-worker" and tier == "kernel":
            # These explicit real-browser tests are ignored by default and must actually execute.
            args.extend(["--", "--ignored"])
        commands.append(Command(package, tuple(args), root, 7200 if tier == "kernel" else 3600))
    return commands


def verify_artifact(root: Path) -> str:
    manifest = root / "compatibility.json"
    if not root.is_absolute() or not manifest.is_file() or manifest.is_symlink():
        raise GateError("BROWSERD_CHROMIUM_ARTIFACT_ROOT must contain a pinned compatibility.json")
    if manifest.stat().st_size > 1024 * 1024:
        raise GateError("compatibility.json exceeds the manifest limit")
    try:
        raw = manifest.read_bytes()
        artifact = decode_json(raw)
        files = validate_manifest(artifact)
        catalog_path = root / CATALOG_PATH
        if (not catalog_path.is_file()
                or any(parent.is_symlink() for parent in (catalog_path, *catalog_path.parents))):
            raise ValueError("native catalog must be a regular file without symlink ancestors")
        if catalog_path.stat().st_size > MAX_CATALOG_BYTES:
            raise ValueError("native catalog exceeds the size bound")
        with catalog_path.open("rb") as stream:
            catalog = validate_native_catalog(artifact, stream.read(MAX_CATALOG_BYTES + 1))
        resources = {catalog["icu_data"], *(entry["pak"] for entry in catalog["locales"])}
        for name, expected_digest in files.items():
            relative = Path(name)
            path = root / relative
            if (path.resolve() != root.resolve() / relative or not path.is_file()
                    or any(parent.is_symlink() for parent in (path, *path.parents))):
                raise ValueError("unsafe artifact file")
            if name in resources and not 0 < path.stat().st_size <= MAX_RESOURCE_BYTES:
                raise ValueError("native resource exceeds runtime size bound")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if digest != expected_digest:
                raise ValueError("digest mismatch")
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise GateError("pinned Chromium artifact manifest/files failed verification") from error
    return hashlib.sha256(raw).hexdigest()


def pinned_test_chromium(root: Path, env: dict[str, str]) -> str:
    """Resolve the executable covered by the already verified compatibility manifest."""
    try:
        manifest = json.loads((root / "compatibility.json").read_text())
        matches = [root / entry["relative_path"] for entry in manifest["files"]
                   if entry["digest"] == manifest["identity"]["binary_digest"]]
        if len(matches) != 1 or not matches[0].is_file() or not os.access(matches[0], os.X_OK):
            raise ValueError("missing or ambiguous pinned executable")
        binary = matches[0].resolve()
        configured = env.get("BROWSERD_TEST_CHROMIUM")
        if configured and Path(configured).resolve() != binary:
            raise ValueError("unrelated Chromium executable")
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise GateError("live-browser tests require the executable identified by the verified Chromium artifact") from error
    return str(binary)


def check_prerequisites(tier: str, env: dict[str, str], root: Path) -> dict[str, str]:
    if tier == "adapter":
        for name, schemes in [
            ("BROWSERD_REDIS_TEST_URL", {"redis", "rediss"}),
            ("BROWSERD_COORDINATION_TEST_DATABASE_URL", {"postgres", "postgresql"}),
        ]:
            value = env.get(name, "")
            if not value:
                raise GateError(f"{name} is required; use an isolated test service with migration/write permissions")
            try:
                parsed = urlsplit(value)
                valid = parsed.scheme in schemes and bool(parsed.hostname)
            except ValueError:
                valid = False
            if not valid:
                raise GateError(f"{name} must be a valid service URL (value omitted)")
    if tier not in {"kernel", "soak"}:
        return {}
    runner_name = f"BROWSERD_{tier.upper()}_RUNNER"
    runner = Path(env.get(runner_name, ""))
    if not runner.is_absolute() or not runner.is_file() or not os.access(runner, os.X_OK):
        raise GateError(f"{runner_name} must name an installed absolute executable implementing the real-browser probe contract; no simulated fallback")
    if env.get("BROWSERD_TRUSTED_VALIDATION") != "1":
        raise GateError("BROWSERD_TRUSTED_VALIDATION=1 is required on an isolated trusted runner")
    if platform.system() != "Linux":
        raise GateError("kernel and soak validation require Linux")
    cgroup = Path(env.get("BROWSERD_VALIDATION_CGROUP_ROOT", ""))
    cgroup_parent = Path("/sys/fs/cgroup")
    if (not cgroup.is_absolute() or cgroup == cgroup_parent
            or not cgroup.resolve().is_relative_to(cgroup_parent)
            or not (cgroup / "cgroup.controllers").is_file()
            or not os.access(cgroup / "cgroup.subtree_control", os.W_OK)
            or os.statvfs(cgroup).f_flag & os.ST_RDONLY):
        raise GateError("BROWSERD_VALIDATION_CGROUP_ROOT must be a writable delegated cgroup v2 subtree; namespace support alone is insufficient")
    if not {"cpu", "memory", "pids"}.issubset((cgroup / "cgroup.controllers").read_text().split()):
        raise GateError("delegated cgroup v2 subtree must expose cpu, memory and pids controllers")
    artifact = Path(env.get("BROWSERD_CHROMIUM_ARTIFACT_ROOT", ""))
    manifest_sha256 = verify_artifact(artifact)
    if tier == "kernel" and (not Path("/usr/bin/bwrap").is_file()
            or any(shutil.which(tool, path=env.get("PATH", os.defpath)) is None for tool in ("unshare", "nsenter", "ip"))):
        raise GateError("kernel suite requires /usr/bin/bwrap, util-linux unshare/nsenter and iproute2 ip")
    result = {"runner": str(runner), "manifest_sha256": manifest_sha256}
    if tier == "kernel":
        result["test_chromium"] = pinned_test_chromium(artifact, env)
    return result


def validate_receipt(receipt: dict, expected: dict, elapsed: float) -> None:
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items()):
        raise GateError("real-runner receipt does not match this run/tier/pinned artifact")
    required = KERNEL_PROBES if expected["tier"] == "kernel" else SOAK_PROBES
    probes = receipt.get("probes")
    for name in required:
        probe = probes.get(name) if isinstance(probes, dict) else None
        if (not isinstance(probe, dict) or probe.get("status") != "passed"
                or not isinstance(probe.get("evidence"), str) or not probe["evidence"].strip()):
            raise GateError(f"real-runner receipt lacks passing evidence for {name}; skipped probes fail the gate")
    if expected["tier"] == "soak" and elapsed < 72 * 60 * 60:
        raise GateError("soak runner must actually execute for at least 72 hours")


def private_json(path: Path, value: dict) -> None:
    with open(path, "w", opener=lambda file, flags: os.open(file, flags, 0o600)) as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def execute(tier: str, commands: list[Command], log_root: Path, env: dict[str, str],
            qualification: dict[str, str] | None = None, blocked: str | None = None) -> tuple[Path, dict]:
    log_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_root.chmod(0o700)
    run_dir = Path(tempfile.mkdtemp(prefix=f"browserd-{tier}-", dir=log_root))
    report = {"schema_version": 1, "run_id": str(uuid.uuid4()), "tier": tier,
              "started_at": datetime.now(timezone.utc).isoformat(), "status": "running", "commands": [],
              "kernel_release": platform.release(), "machine": platform.machine()}
    source_root = Path(__file__).resolve().parents[1]
    report.update(source_identity(source_root))
    report_path = run_dir / "report.json"
    if blocked:
        report.update(status="blocked", reason=blocked)
    child_env = env.copy()
    for variable in SOURCE_VARIABLES:
        child_env.pop(variable, None)
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    receipt_path = run_dir / "receipt.json"
    expected = None
    if qualification:
        report["source_content_sha256"] = source_content_identity(source_root)
        if report["source_revision"] is not None:
            child_env["BROWSERD_VALIDATION_SOURCE_REVISION"] = report["source_revision"]
        child_env["BROWSERD_VALIDATION_SOURCE_DIRTY"] = json.dumps(report["source_dirty"])
        if report["source_content_sha256"] is not None:
            child_env["BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256"] = report["source_content_sha256"]
        expected = {"run_id": report["run_id"], "tier": tier,
                    "manifest_sha256": qualification["manifest_sha256"],
                    "kernel_release": report["kernel_release"], "machine": report["machine"]}
        child_env.update({f"BROWSERD_VALIDATION_{key.upper()}": value for key, value in expected.items()})
        child_env["BROWSERD_VALIDATION_RECEIPT"] = str(receipt_path)
        child_env["BROWSERD_VALIDATION_LOG_DIR"] = str(run_dir)
        report["manifest_sha256"] = qualification["manifest_sha256"]
        if "test_chromium" in qualification:
            child_env["BROWSERD_TEST_CHROMIUM"] = qualification["test_chromium"]
    private_json(report_path, report)
    for index, command in enumerate(commands if not blocked else []):
        log_path = run_dir / f"{index:02d}-{command.name}.log"
        entry = {"name": command.name, "argv": list(command.argv), "cwd": str(command.cwd),
                 "log": str(log_path), "started_at": datetime.now(timezone.utc).isoformat()}
        report["commands"].append(entry)
        started = time.monotonic()
        with open(log_path, "wb", opener=lambda file, flags: os.open(file, flags, 0o600)) as output:
            try:
                process = subprocess.Popen(command.argv, cwd=command.cwd, env=child_env,
                                           stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                                           umask=0o077)
                entry["pid"] = process.pid
                private_json(report_path, report)
                try:
                    code = process.wait(timeout=command.timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    code = 124 if isinstance(error, subprocess.TimeoutExpired) else 130
            except OSError as error:
                output.write(f"command could not start (errno={error.errno})\n".encode())
                code = 127
        entry.update(exit_code=code, duration_seconds=round(time.monotonic() - started, 3))
        private_json(report_path, report)
        if code:
            if (code == 2 and expected is not None and tier in {"kernel", "soak"}
                    and command.name == f"{tier}-real-browser"):
                report["status"] = "blocked"
                report["reason"] = f"{tier} runner reported incomplete deployment prerequisites or probes; inspect its private log"
            else:
                report["status"] = "failed"
            break
    else:
        if not blocked:
            report["status"] = "passed"
    if expected and report["status"] == "passed":
        try:
            if receipt_path.stat().st_size > 1024 * 1024:
                raise GateError("real-runner receipt is too large")
            validate_receipt(json.loads(receipt_path.read_text()), expected,
                             report["commands"][-1]["duration_seconds"])
            receipt_path.chmod(0o600)
            report["probes"] = list(KERNEL_PROBES if tier == "kernel" else SOAK_PROBES)
        except (OSError, ValueError, GateError) as error:
            report["status"] = "failed"
            report["reason"] = str(error) if isinstance(error, GateError) else "real-runner receipt missing or invalid"
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    final_source = source_identity(source_root)
    if qualification:
        final_content = source_content_identity(source_root)
        report["source_changed_during_run"] = (
            final_source["source_revision"] != report["source_revision"] or
            final_content != report["source_content_sha256"])
        if report["source_changed_during_run"]:
            report["source_dirty"] = True
            report["final_source_content_sha256"] = final_content
            if report["status"] == "passed":
                report.update(status="failed", reason="source changed during qualification")
        elif final_content is None and report["status"] == "passed":
            report.update(status="failed", reason="source contents could not be verified for qualification")
    if final_source["source_revision"] != report["source_revision"] or final_source["source_dirty"]:
        report["source_dirty"] = True
    private_json(report_path, report)
    return run_dir, report


def main(argv: list[str] | None = None, env: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tier", choices=TIERS)
    parser.add_argument("--log-dir", type=Path, default=Path.home() / "logs")
    parser.add_argument("--plan", action="store_true", help="show command inventory only; does not validate or pass a gate")
    parser.add_argument("--describe", action="store_true", help="show real-runner probes and prerequisite variables")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    if args.describe:
        print(json.dumps({"tier": args.tier, "kernel_probes": KERNEL_PROBES, "soak_probes": SOAK_PROBES,
                          "prerequisites": ["BROWSERD_REDIS_TEST_URL", "BROWSERD_COORDINATION_TEST_DATABASE_URL",
                            "BROWSERD_KERNEL_RUNNER", "BROWSERD_SOAK_RUNNER", "BROWSERD_TRUSTED_VALIDATION=1",
                            "BROWSERD_VALIDATION_CGROUP_ROOT", "BROWSERD_CHROMIUM_ARTIFACT_ROOT"],
                          "receipt_contract": __doc__}, indent=2))
        return 0
    current_env = dict(os.environ) if env is None else env
    qualification = None
    blocked = None
    try:
        commands = build_plan(args.tier, root)
        if args.plan:
            print(json.dumps({"status": "planned_only", "tier": args.tier,
                              "commands": [{"name": c.name, "argv": c.argv} for c in commands],
                              "external_runner_required": args.tier in {"kernel", "soak"}}, indent=2))
            return 0
        qualification = check_prerequisites(args.tier, current_env, root)
        if qualification:
            commands.append(Command(f"{args.tier}-real-browser", (qualification["runner"],), root,
                                    80 * 60 * 60 if args.tier == "soak" else 2 * 60 * 60))
    except (GateError, OSError) as error:
        blocked = str(error) if isinstance(error, GateError) else f"prerequisite could not be inspected (errno={error.errno})"
        commands = []
    run_dir, report = execute(args.tier, commands, args.log_dir, current_env, qualification, blocked)
    print(f"{args.tier}: {report['status']}; report: {run_dir / 'report.json'}")
    if report.get("reason"):
        print(report["reason"])
    return {"passed": 0, "blocked": 2}.get(report["status"], 1)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    raise SystemExit(main())
