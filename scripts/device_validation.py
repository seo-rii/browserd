#!/usr/bin/env python3
"""Install and exercise a private device candidate, without granting release approval.

The functional command uses the copied Chromium and records actual browser tests.
It never writes a kernel/soak receipt. Host cgroup delegation is a separate action
implemented by deploy/setup-validation-host.py and requires an ordinary root shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_profile_artifact import decode_json
from validation import Command, GateError, execute, pinned_test_chromium, verify_artifact


class DeviceError(ValueError):
    pass


DEFAULT_STATE = Path.home() / ".local/state/browserd-validation"
QUALIFICATION_VARIABLES = (
    "BROWSERD_TRUSTED_VALIDATION", "BROWSERD_KERNEL_RUNNER", "BROWSERD_SOAK_RUNNER",
    "BROWSERD_VALIDATION_CGROUP_ROOT",
    "BROWSERD_KERNEL_PROBE_CONFIG", "BROWSERD_KERNEL_PROBE_CONFIG_SHA256",
)
CONFIG_KEYS = {"schema_version", "uid", "repo", "artifact_root", "manifest_sha256",
               "test_chromium", "artifact_status"}


def safe_path(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise DeviceError("device paths must be absolute and normalized")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise DeviceError("device paths must not contain symlinks")


def private_state(state: Path, create: bool = False) -> None:
    safe_path(state)
    if create:
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (not state.is_dir() or state.stat().st_uid != os.getuid()
            or (state.stat().st_mode & 0o077)):
        raise DeviceError("device state must be an owned directory with mode 0700")


def read_object(path: Path) -> dict:
    safe_path(path)
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise DeviceError("device metadata must be a bounded regular file")
    try:
        return decode_json(path.read_bytes())
    except (OSError, ValueError) as error:
        raise DeviceError("invalid device metadata") from error


def candidate(artifact: Path) -> tuple[str, str]:
    safe_path(artifact)
    provenance = read_object(artifact / "provenance.json")
    if (provenance.get("qualification") != "local_candidate"
            or provenance.get("operator_approval") is not False):
        raise DeviceError("device installation requires explicit unqualified candidate provenance")
    try:
        digest = verify_artifact(artifact)
        binary = pinned_test_chromium(artifact, {})
    except (OSError, GateError) as error:
        raise DeviceError("candidate artifact failed verification") from error
    return digest, binary


def write_private(path: Path, text: str) -> None:
    safe_path(path)
    if path.exists() and (not path.is_file() or path.stat().st_uid != os.getuid()):
        raise DeviceError("refusing to replace unowned device metadata")
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        stream.write(text)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def install(state: Path, repo: Path, artifact: Path) -> dict:
    safe_path(repo)
    if not (repo / "scripts/validation.py").is_file():
        raise DeviceError("repo must contain browserd scripts/validation.py")
    digest, binary = candidate(artifact)
    private_state(state, create=True)
    settings = {"schema_version": 1, "uid": os.getuid(), "repo": str(repo),
                "artifact_root": str(artifact), "manifest_sha256": digest,
                "test_chromium": binary, "artifact_status": "local_candidate"}
    path = state / "device.json"
    if path.exists() and read_object(path) != settings:
        raise DeviceError("refusing to replace another device installation; choose a new state directory")
    env = environment(settings, {})
    shell = "# Local functional candidate; no operator approval or kernel/soak qualification.\n"
    shell += "unset " + " ".join(QUALIFICATION_VARIABLES) + "\n"
    shell += "".join(f"export {name}={shlex.quote(value)}\n" for name, value in sorted(env.items()))
    write_private(state / "candidate.env", shell)
    write_private(path, json.dumps(settings, indent=2) + "\n")
    return settings


def load(state: Path) -> dict:
    private_state(state)
    settings = read_object(state / "device.json")
    if (set(settings) != CONFIG_KEYS or settings["schema_version"] != 1
            or settings["uid"] != os.getuid() or settings["artifact_status"] != "local_candidate"):
        raise DeviceError("device settings do not belong to this installation/user")
    try:
        artifact = Path(settings["artifact_root"])
        repo = Path(settings["repo"])
        safe_path(repo)
        if not (repo / "scripts/validation.py").is_file():
            raise DeviceError("configured browserd checkout is missing")
        digest, binary = candidate(artifact)
        if digest != settings["manifest_sha256"] or binary != settings["test_chromium"]:
            raise DeviceError("installed candidate identity changed")
    except (KeyError, TypeError) as error:
        raise DeviceError("invalid device settings") from error
    return settings


def environment(settings: dict, inherited: dict[str, str]) -> dict[str, str]:
    env = {key: value for key, value in inherited.items() if key not in QUALIFICATION_VARIABLES}
    env.update(BROWSERD_CHROMIUM_ARTIFACT_ROOT=settings["artifact_root"],
               BROWSERD_TEST_CHROMIUM=settings["test_chromium"],
               RUSTUP_TOOLCHAIN="1.94.0", CARGO_BUILD_JOBS="2", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0", PYTHONDONTWRITEBYTECODE="1")
    return env


def query_host(address: Path, uid: int) -> dict:
    """Read the fixed diagnose response from the same user's live holder."""
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(address))
        peer_pid, peer_uid, _peer_gid = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer_uid != uid:
            raise DeviceError("dedicated host socket server uid differs")
        connection.sendall(b'{"action":"diagnose","environment":{}}\n')
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = connection.recv(4096)
            if not chunk or len(raw) + len(chunk) > 65536:
                raise DeviceError("dedicated host socket response is incomplete or oversized")
            raw += chunk
    response = decode_json(raw)
    if type(response.get("pid")) is not int or response["pid"] != peer_pid:
        raise DeviceError("dedicated host response pid differs from socket server credentials")
    return response


def validate_host_runtime(root: Path, workloads: Path, uid: int, pid: int) -> None:
    """Check real kernel paths and holder identity without changing cgroups."""
    required = {"cpu", "memory", "pids"}
    for path in (root, workloads):
        safe_path(path)
        if (not path.is_dir() or path.stat().st_uid != uid
                or os.statvfs(path).f_flag & os.ST_RDONLY):
            raise DeviceError("dedicated cgroup must be owned and writable on cgroupfs")
        for control in ("cgroup.procs", "cgroup.subtree_control"):
            target = path / control
            if not target.is_file() or not os.access(target, os.W_OK):
                raise DeviceError("dedicated cgroup control files must be writable")
        if not required.issubset((path / "cgroup.controllers").read_text().split()):
            raise DeviceError("dedicated cgroup controllers must include cpu, memory and pids")
        if not required.issubset((path / "cgroup.subtree_control").read_text().split()):
            raise DeviceError("dedicated cgroup controllers are not enabled for children")
    proc = Path("/proc") / str(pid)
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines()
                  if ":" in line)
    if (status.get("NoNewPrivs", "").strip() != "1"
            or status.get("Uid", "").split()[:2] != [str(uid), str(uid)]):
        raise DeviceError("dedicated holder must retain its uid and NoNewPrivileges")
    expected = "0::/" + str((root / "holder").relative_to("/sys/fs/cgroup"))
    if (proc / "cgroup").read_text().splitlines() != [expected]:
        raise DeviceError("live holder is outside the expected dedicated cgroup")


def host_delegation(state: Path, settings: dict) -> dict:
    """A delegated host service is independent of the invoking process's cgroup."""
    unavailable = {"available": False, "validated": False, "status": "unavailable"}
    try:
        if platform.system() != "Linux":
            raise DeviceError("dedicated host delegation requires Linux")
        private_state(state)
        plan_path = state / "host-plan.json"
        if not plan_path.exists():
            return {**unavailable, "error": "host bootstrap plan is not installed"}
        info = plan_path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise DeviceError("host bootstrap plan must be private and owned by this user")
        plan = read_object(plan_path)
        identity = hashlib.sha256((settings["repo"] + "\0" + str(state)).encode()).hexdigest()[:12]
        unit = f"browserd-validation-u{os.getuid()}-{identity}.service"
        address = state / "control.sock"
        expected_plan = {"schema_version": 1, "uid": os.getuid(), "repo": settings["repo"],
                         "state_directory": str(state), "unit_name": unit,
                         "unit_path": "/etc/systemd/system/" + unit, "socket_path": str(address)}
        if (type(plan.get("schema_version")) is not int or type(plan.get("uid")) is not int
                or any(plan.get(key) != value for key, value in expected_plan.items())):
            raise DeviceError("host bootstrap plan identity differs from this device installation")
        safe_path(address)
        if not address.exists():
            return {**unavailable, "error": "dedicated host service socket is missing"}
        info = address.stat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise DeviceError("dedicated host socket must be private and owned by this user")
        response = query_host(address, os.getuid())
        root = Path("/sys/fs/cgroup/system.slice") / unit
        workloads = root / "workloads"
        controllers = response.get("controllers")
        if (response.get("status") != "ready" or type(response.get("uid")) is not int
                or response["uid"] != os.getuid() or response.get("unit_name") != unit
                or type(response.get("pid")) is not int or response["pid"] <= 0
                or response.get("delegated_cgroup") != str(root)
                or response.get("validation_cgroup_root") != str(workloads)
                or not isinstance(controllers, list)
                or not all(isinstance(controller, str) for controller in controllers)
                or not {"cpu", "memory", "pids"}.issubset(controllers)):
            raise DeviceError("dedicated host response has invalid identity, cgroup paths or controllers")
        validate_host_runtime(root, workloads, os.getuid(), response["pid"])
        return {"available": True, "validated": True, "status": "available", "uid": os.getuid(),
                "pid": response["pid"], "unit_name": unit, "delegated_cgroup": str(root),
                "validation_cgroup_root": str(workloads), "controllers": controllers,
                "no_new_privileges": True}
    except OSError as error:
        return {**unavailable, "error": f"dedicated host service is unavailable ({type(error).__name__})"}
    except (DeviceError, ValueError, KeyError, TypeError) as error:
        return {**unavailable, "status": "invalid", "error": str(error)}


def doctor(state: Path, settings: dict) -> dict:
    process_status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                          if ":" in line) if platform.system() == "Linux" else {}
    current = Path("/sys/fs/cgroup")
    if platform.system() == "Linux":
        entry = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                      if line.startswith("0::")), "")
        current = current / entry.lstrip("/")
    delegated = current != Path("/sys/fs/cgroup") and os.access(current / "cgroup.subtree_control", os.W_OK)
    dedicated = host_delegation(state, settings)
    report = {"schema_version": 1, "status": "blocked", "artifact_status": "local_candidate",
              "manifest_sha256": settings["manifest_sha256"], "operator_approval": False,
              "kernel_release": platform.release(), "uid": os.getuid(),
              "no_new_privileges": process_status.get("NoNewPrivs", "").strip() == "1",
              "current_cgroup": str(current), "current_cgroup_delegated": delegated,
              "host_delegation": dedicated,
              "tools": {tool: shutil.which(tool) for tool in ("bwrap", "unshare", "nsenter", "ip")},
              "blockers": ["candidate artifact has no production approval",
                           "deployment-specific kernel probe runner is not implemented",
                           "measured 72-hour workload runner is not implemented"]}
    if not delegated and not dedicated["available"]:
        report["blockers"].append("dedicated host delegation is unavailable; host bootstrap requires root or the installed service must be started")
    if any(value is None for value in report["tools"].values()):
        report["blockers"].append("required host tools are missing")
    write_private(state / "doctor.json", json.dumps(report, indent=2) + "\n")
    return report


def functional(settings: dict, log_dir: Path) -> int:
    root = Path(settings["repo"])
    commands = [Command("real-browser-python", (sys.executable, "-m", "unittest", "discover",
                        "-s", "scripts/tests", "-p", "test_chromium_*.py"), root),
                Command("real-browser-rust", ("cargo", "test", "--locked", "-p", "browserd-worker",
                        "--test", "live_chromium_emulation", "--test", "live_chromium_input",
                        "--test", "live_chromium_capture", "--test", "live_chromium_viewer",
                        "--test", "live_chromium_downloads", "--test", "live_chromium_workers",
                        "--test", "live_chromium_evaluate", "--test", "live_chromium_shared_context",
                        "--", "--ignored"), root),
                Command("real-browser-file-inputs", ("cargo", "test", "--locked", "-p", "browserd-worker",
                        "--lib", "chromium_owner::uploads::live_tests::actual_owner_file_inputs_preserve_names_bytes_and_scope",
                        "--", "--ignored", "--exact"), root),
                Command("real-browser-secrets", ("cargo", "test", "--locked", "-p", "browserd-worker",
                        "--lib", "chromium_owner::secrets::live_tests::actual_owner_secret_fill_preserves_origin_and_redacts_results",
                        "--", "--ignored", "--exact"), root),
                Command("real-browser-checkpoint", ("cargo", "test", "--locked", "-p", "browserd-worker",
                        "--lib", "chromium_owner::checkpoints::live_tests::actual_owner_checkpoint_roundtrip_without_network_or_reapplication",
                        "--", "--ignored", "--exact"), root),
                Command("real-browser-frame-input", ("cargo", "test", "--locked", "-p", "browserd-worker",
                        "--lib", "chromium_owner::frames::live_tests::actual_owner_nested_frames_and_oopif_input_are_fenced",
                        "--", "--ignored", "--exact"), root),
                Command("real-browser-typed-approvals", ("cargo", "test", "--locked", "-p", "browserd-worker",
                        "--lib", "chromium_owner::approvals::live_tests::actual_owner_typed_approvals_bind_child_secret_files_and_blank_context",
                        "--", "--ignored", "--exact"), root)]
    run_dir, report = execute("device-functional", commands, log_dir, environment(settings, dict(os.environ)))
    report.update(artifact_status="local_candidate", operator_approval=False,
                  manifest_sha256=settings["manifest_sha256"])
    write_private(run_dir / "report.json", json.dumps(report, indent=2) + "\n")
    print(f"device functional: {report['status']}; report: {run_dir / 'report.json'}")
    return 0 if report["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "doctor", "functional"))
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--log-dir", type=Path, default=Path.home() / "logs")
    args = parser.parse_args()
    try:
        if args.command == "install":
            if not args.artifact_root:
                parser.error("install requires --artifact-root")
            settings = install(args.state_dir, args.repo, args.artifact_root)
            print(f"candidate installed: {args.state_dir / 'device.json'}; manifest: {settings['manifest_sha256']}")
            return 0
        settings = load(args.state_dir)
        if args.command == "doctor":
            report = doctor(args.state_dir, settings)
            print(json.dumps(report, indent=2))
            return 2
        return functional(settings, args.log_dir)
    except (OSError, DeviceError) as error:
        print(f"device setup failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
