#!/usr/bin/env python3
"""Run approved production probes; partial device diagnostics remain separate.

Approval authorizes the exact immutable inputs, not a successful qualification.
The Rust engine owns its temporary validation resources and must positively prove
cleanup. This wrapper never starts services, changes approval, or installs trust.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_kernel_runner import (
    CGROUP_ROOT, PrerequisiteError as DelegationError, check_delegation,
    control_read, process_cgroup,
)
from validation import GateError, KERNEL_PROBES, verify_artifact


DEFAULT_CONFIG = Path("/etc/browserd/kernel-probe-approval.json")
MAX_JSON_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_ASSETS = 1024
MAX_RUNTIME_FILES = 4096
DEADLINE_SECONDS = 7200
REQUIRED_ROLES = frozenset({"chromium_binary", "launch_gate", "bwrap", "seccomp",
                            "sandbox_daemon", "egress_daemon", "runtime_manifest"})
CONFIG_KEYS = {"schema_version", "operator_approval", "isolated_validation", "validation_uid",
               "manifest_sha256", "artifact_root", "probe_executable", "approved_assets", "deployment"}
DEPLOYMENT_KEYS = {
    "sandbox": {"socket_path", "expected_server_uid", "daemon_epoch", "worker_id", "worker_epoch",
                "cgroup_root", "runtime_root", "journal_directory"},
    "egress": {"control_url", "install_socket", "expected_server_uid", "daemon_epoch", "worker_token",
               "supervisor_token", "policy_profile", "policy_digest"},
    "runtime": {"redis_url", "redis_prefix", "safety_pin_path"},
    "worker": {"state_root", "max_session_count"},
    "fixtures": {"bind_address", "origin", "host_direct_address", "private_direct_address"},
    "assets": {"chromium_host_executable", "chromium_sandbox_executable", "launch_gate_host_executable",
               "launch_gate_sandbox_executable", "bwrap_executable", "seccomp_filter",
               "sandbox_daemon_executable", "egress_daemon_executable", "runtime_manifest", "read_only_mounts"},
}
ROLE_FIELDS = {"chromium_binary": "chromium_host_executable", "launch_gate": "launch_gate_host_executable",
               "bwrap": "bwrap_executable", "seccomp": "seccomp_filter",
               "sandbox_daemon": "sandbox_daemon_executable", "egress_daemon": "egress_daemon_executable",
               "runtime_manifest": "runtime_manifest"}


class PrerequisiteError(ValueError):
    """A missing or unapproved input; never a passing probe."""


class ProbeFailure(ValueError):
    """An admitted probe or its publication did not complete correctly."""


def _object(value, keys, label):
    if not isinstance(value, dict) or set(value) != keys:
        raise PrerequisiteError(f"invalid {label} fields")


def _text(value, label, maximum=4096, minimum=1):
    if (not isinstance(value, str) or not minimum <= len(value) <= maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise PrerequisiteError(f"invalid {label}")
    return value


def _digest(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None or value == "0" * 64:
        raise PrerequisiteError(f"invalid {label} digest")
    return value


def _integer(value, label, minimum=0, maximum=(1 << 64) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise PrerequisiteError(f"invalid {label}")


def _absolute(value, label):
    value = _text(value, label)
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts or value == "/":
        raise PrerequisiteError(f"invalid {label} path")
    return path


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise PrerequisiteError("duplicate JSON field")
        result[key] = value
    return result


def _json(raw):
    def nonfinite(_value):
        raise PrerequisiteError("nonfinite JSON value")
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise PrerequisiteError("nonfinite JSON value")
        return result
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PrerequisiteError("invalid bounded JSON") from error
    if not isinstance(value, dict):
        raise PrerequisiteError("JSON must be an object")
    return value


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
            metadata.st_nlink)


def _root_metadata(metadata, directory=False, private=False):
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != 0 or mode & 0o022:
        raise PrerequisiteError("approval inputs and ancestors must be root-owned and unwritable by other users")
    if private and mode not in {0o400, 0o440, 0o600, 0o640}:
        raise PrerequisiteError("approval configuration must have private read permissions")
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise PrerequisiteError("approval ancestor must be a directory")


def _open_parent(path, approved=False, private_root=None):
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = Path("/")
        if approved:
            _root_metadata(os.fstat(descriptor), directory=True)
        for component in path.parts[1:-1]:
            next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            current /= component
            metadata = os.fstat(descriptor)
            if approved:
                _root_metadata(metadata, directory=True)
            if private_root is not None and current.is_relative_to(private_root):
                if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise PrerequisiteError("evidence directories must be private and owned")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@dataclass
class PinnedFile:
    path: Path
    stream: object
    identity: tuple
    sha256: str
    limit: int
    approved: bool
    private_root: Path | None

    def read(self):
        self.stream.seek(0)
        data = self.stream.read(self.limit + 1)
        if len(data) > self.limit or _identity(os.fstat(self.stream.fileno())) != self.identity:
            raise PrerequisiteError("pinned input changed or exceeds its bound")
        return data

    def recheck(self):
        current = _pin(self.path, self.limit, self.approved, self.private_root)
        try:
            if current.identity != self.identity or current.sha256 != self.sha256:
                raise PrerequisiteError("approved input or evidence changed during validation")
        finally:
            current.close()

    def close(self):
        self.stream.close()


def _pin(path, limit, approved=False, private_root=None, private_config=False, executable=False):
    parent = _open_parent(path, approved, private_root)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    stream = os.fdopen(descriptor, "rb")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit or metadata.st_nlink != 1:
            raise PrerequisiteError("input must be a bounded regular file with one link")
        if approved:
            _root_metadata(metadata, private=private_config)
        if executable and (not metadata.st_mode & 0o111 or not os.access(path, os.X_OK)):
            raise PrerequisiteError("approved probe/runtime executable must be executable")
        if private_root is not None and (metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}):
            raise PrerequisiteError("evidence must be a private owned regular file")
        hasher = hashlib.sha256()
        count = 0
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > limit:
                raise PrerequisiteError("input exceeds its byte bound")
            hasher.update(chunk)
        identity = _identity(metadata)
        if _identity(os.fstat(descriptor)) != identity:
            raise PrerequisiteError("input changed while hashing")
        return PinnedFile(path, stream, identity, hasher.hexdigest(), limit, approved, private_root)
    except BaseException:
        stream.close()
        raise


def _origin(value, label, loopback=False):
    value = _text(value, label)
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise PrerequisiteError(f"invalid {label} origin")
    try:
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise PrerequisiteError(f"invalid {label} port") from None
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if loopback and parsed.hostname != "localhost":
            raise PrerequisiteError(f"{label} must be loopback") from None
    else:
        if loopback and not address.is_loopback:
            raise PrerequisiteError(f"{label} must be loopback")
        if not loopback and not address.is_global:
            raise PrerequisiteError(f"{label} must be public")


def _socket_address(value, label, bind=False):
    value = _text(value, label, 128)
    try:
        parsed = urlsplit("//" + value)
        ipaddress.ip_address(parsed.hostname)
        if (parsed.port is None or not (0 if bind else 1) <= parsed.port <= 65535 or parsed.path
                or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):
            raise ValueError
    except (ValueError, TypeError):
        raise PrerequisiteError(f"invalid {label} socket address") from None


def validate_deployment(value):
    _object(value, set(DEPLOYMENT_KEYS), "deployment")
    for section, keys in DEPLOYMENT_KEYS.items():
        optional = {"scanner", "privileged_evaluate"} & set(value[section]) if section == "worker" and isinstance(value[section], dict) else set()
        expected = keys | optional
        _object(value[section], expected, f"deployment {section}")
    for section, fields in {
        "sandbox": ("socket_path", "cgroup_root", "runtime_root", "journal_directory"),
        "egress": ("install_socket",), "runtime": ("safety_pin_path",), "worker": ("state_root",),
        "assets": tuple(field for field in DEPLOYMENT_KEYS["assets"] if field != "read_only_mounts"),
    }.items():
        for field in fields:
            _absolute(value[section][field], field)
    for section in ("sandbox", "egress"):
        _integer(value[section]["expected_server_uid"], "server UID", maximum=(1 << 32) - 1)
        _integer(value[section]["daemon_epoch"], "daemon epoch", minimum=1)
    _integer(value["sandbox"]["worker_epoch"], "worker epoch", minimum=1)
    _text(value["sandbox"]["worker_id"], "worker ID", 128)
    for field in ("worker_token", "supervisor_token"):
        _text(value["egress"][field], "egress authentication", 4096, 32)
    _text(value["egress"]["policy_profile"], "policy profile", 128)
    _digest(value["egress"]["policy_digest"], "policy")
    _origin(value["egress"]["control_url"], "egress control", loopback=True)
    _origin(value["fixtures"]["origin"], "fixture")
    for field in ("bind_address", "host_direct_address", "private_direct_address"):
        _socket_address(value["fixtures"][field], field, bind=field == "bind_address")
    _text(value["runtime"]["redis_url"], "Redis URL")
    _text(value["runtime"]["redis_prefix"], "Redis prefix", 256)
    _integer(value["worker"]["max_session_count"], "session capacity", minimum=2, maximum=64)
    if "privileged_evaluate" in value["worker"] and type(value["worker"]["privileged_evaluate"]) is not bool:
        raise PrerequisiteError("privileged evaluate approval must be an explicit boolean")
    scanner = value["worker"].get("scanner")
    if scanner is not None:
        _object(scanner, {"socket_path", "expected_uid", "max_database_age_millis", "max_future_skew_millis"}, "artifact scanner")
        _absolute(scanner["socket_path"], "scanner socket")
        _integer(scanner["expected_uid"], "scanner UID", maximum=(1 << 32) - 1)
        _integer(scanner["max_database_age_millis"], "scanner database freshness", minimum=1)
        _integer(scanner["max_future_skew_millis"], "scanner future skew")
    mounts = value["assets"]["read_only_mounts"]
    if not isinstance(mounts, list) or not 1 <= len(mounts) <= 64:
        raise PrerequisiteError("invalid runtime mounts")
    seen = set()
    executables = [Path(value["assets"][field]) for field in ("chromium_sandbox_executable", "launch_gate_sandbox_executable")]
    for mount in mounts:
        _object(mount, {"source", "destination"}, "runtime mount")
        pair = tuple(str(_absolute(mount[field], "runtime mount")) for field in ("source", "destination"))
        destination = Path(pair[1])
        chromium_parent = destination == executables[0].parent and destination != Path("/")
        if any((destination.is_relative_to(executable) or executable.is_relative_to(destination))
               and not (chromium_parent and executable == executables[0]) for executable in executables):
            raise PrerequisiteError("runtime mount overlaps a gated executable")
        if pair in seen or any(pair[1] == previous[1] for previous in seen):
            raise PrerequisiteError("duplicate runtime mount")
        seen.add(pair)


@dataclass
class Approval:
    path: Path
    config: dict
    config_sha256: str
    files: list[PinnedFile]
    probe: PinnedFile

    def recheck(self):
        for pinned in self.files:
            pinned.recheck()
        if verify_artifact(Path(self.config["artifact_root"])) != self.config["manifest_sha256"]:
            raise PrerequisiteError("approved artifact changed during validation")
        runtime_path = Path(self.config["deployment"]["assets"]["runtime_manifest"])
        manifest = next(pinned for pinned in self.files if pinned.path == runtime_path)
        temporary_pins = []
        try:
            _runtime_inventory(manifest.read(), self.config["deployment"], temporary_pins)
        finally:
            for pinned in temporary_pins:
                pinned.close()

    def close(self):
        for pinned in self.files:
            pinned.close()


def _runtime_inventory(raw, deployment, pins):
    manifest = _json(raw)
    _object(manifest, {"schema_version", "mounts"}, "runtime manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise PrerequisiteError("unsupported runtime manifest")
    mounts = manifest["mounts"]
    if not isinstance(mounts, list) or not 1 <= len(mounts) <= 64:
        raise PrerequisiteError("invalid runtime manifest mounts")
    actual = set()
    seen_files = set()
    entry_count = [0]
    for mount in mounts:
        _object(mount, {"source", "destination", "files"}, "runtime inventory mount")
        source = _absolute(mount["source"], "runtime inventory")
        destination = _absolute(mount["destination"], "runtime destination")
        pair = (str(source), str(destination))
        if pair in actual:
            raise PrerequisiteError("duplicate runtime inventory mount")
        actual.add(pair)
        if not isinstance(mount["files"], list) or not mount["files"]:
            raise PrerequisiteError("runtime inventory must bind its files")
        declared = set()
        for entry in mount["files"]:
            _object(entry, {"relative_path", "sha256"}, "runtime inventory file")
            relative = _text(entry["relative_path"], "runtime relative path")
            if (Path(relative).is_absolute() or str(Path(relative)) != relative
                    or ".." in Path(relative).parts or relative == "."):
                raise PrerequisiteError("unsafe runtime inventory path")
            path = source / relative
            if path in seen_files or len(seen_files) >= MAX_RUNTIME_FILES:
                raise PrerequisiteError("duplicate or excessive runtime inventory files")
            seen_files.add(path)
            declared.add(relative)
            pinned = _pin(path, MAX_ASSET_BYTES, approved=True)
            pins.append(pinned)
            if pinned.sha256 != _digest(entry["sha256"], "runtime file"):
                raise PrerequisiteError("runtime file digest mismatch")
        actual_files = set()
        directory = _open_parent(source / "entry", approved=True)
        try:
            _runtime_directory_files(directory, Path(), actual_files, entry_count)
        finally:
            os.close(directory)
        if actual_files != declared:
            raise PrerequisiteError("runtime inventory omits or invents mounted files")
    expected = {(mount["source"], mount["destination"]) for mount in deployment["assets"]["read_only_mounts"]}
    if actual != expected:
        raise PrerequisiteError("runtime inventory does not bind the configured mounts")


def _runtime_directory_files(directory, relative, result, entry_count):
    for entry in os.scandir(directory):
        entry_count[0] += 1
        if entry_count[0] > MAX_RUNTIME_FILES * 2:
            raise PrerequisiteError("runtime directory exceeds its entry bound")
        metadata = entry.stat(follow_symlinks=False)
        _root_metadata(metadata)
        name = relative / entry.name
        if stat.S_ISREG(metadata.st_mode):
            result.add(str(name))
            if len(result) > MAX_RUNTIME_FILES:
                raise PrerequisiteError("runtime directory exceeds its inventory bound")
        elif stat.S_ISDIR(metadata.st_mode):
            if len(name.parts) > 32:
                raise PrerequisiteError("runtime directory exceeds its depth bound")
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                _runtime_directory_files(child, name, result, entry_count)
            finally:
                os.close(child)
        else:
            raise PrerequisiteError("runtime inventory cannot contain symlinks or special files")


def load_configuration(env, expected_manifest):
    custom = env.get("BROWSERD_KERNEL_PROBE_CONFIG")
    expected_digest = env.get("BROWSERD_KERNEL_PROBE_CONFIG_SHA256")
    if (custom is None) != (expected_digest is None):
        raise PrerequisiteError("custom approval path and digest must both be supplied")
    path = _absolute(custom, "approval") if custom is not None else DEFAULT_CONFIG
    if expected_digest is not None:
        _digest(expected_digest, "approval")
    pins = []
    try:
        config_pin = _pin(path, MAX_JSON_BYTES, approved=True, private_config=True)
        pins.append(config_pin)
        if expected_digest is not None and config_pin.sha256 != expected_digest:
            raise PrerequisiteError("approval configuration digest mismatch")
        config = _json(config_pin.read())
        _object(config, CONFIG_KEYS, "approval")
        if (type(config["schema_version"]) is not int or config["schema_version"] != 1
                or config["operator_approval"] is not True or config["isolated_validation"] is not True):
            raise PrerequisiteError("explicit isolated operator approval is required")
        _integer(config["validation_uid"], "validation UID", maximum=(1 << 32) - 1)
        if config["validation_uid"] != os.getuid():
            raise PrerequisiteError("approval belongs to another validation UID")
        if _digest(config["manifest_sha256"], "artifact") != expected_manifest:
            raise PrerequisiteError("approval belongs to another run artifact")
        artifact = _absolute(config["artifact_root"], "approved artifact")
        if env.get("BROWSERD_CHROMIUM_ARTIFACT_ROOT") != str(artifact):
            raise PrerequisiteError("approval artifact differs from this run")
        validate_deployment(config["deployment"])
        _object(config["probe_executable"], {"path", "sha256"}, "probe executable")
        probe = _pin(_absolute(config["probe_executable"]["path"], "probe executable"),
                     MAX_ASSET_BYTES, approved=True, executable=True)
        pins.append(probe)
        if probe.sha256 != _digest(config["probe_executable"]["sha256"], "probe executable"):
            raise PrerequisiteError("probe executable digest mismatch")
        assets = config["approved_assets"]
        if not isinstance(assets, list) or not len(REQUIRED_ROLES) <= len(assets) <= MAX_ASSETS:
            raise PrerequisiteError("invalid approved asset inventory")
        roles = {}
        paths = {probe.path}
        runtime_manifest = None
        for asset in assets:
            _object(asset, {"path", "sha256", "role"}, "approved asset")
            role = _text(asset["role"], "approved asset role", 64)
            if role not in REQUIRED_ROLES | {"runtime_file"} or (role != "runtime_file" and role in roles):
                raise PrerequisiteError("unknown or duplicate approved asset role")
            asset_path = _absolute(asset["path"], "approved asset")
            if asset_path in paths:
                raise PrerequisiteError("duplicate approved asset path")
            paths.add(asset_path)
            if role in ROLE_FIELDS and str(asset_path) != config["deployment"]["assets"][ROLE_FIELDS[role]]:
                raise PrerequisiteError("approved asset differs from deployment")
            pinned = _pin(asset_path, MAX_JSON_BYTES if role == "runtime_manifest" else MAX_ASSET_BYTES,
                          approved=True, executable=role in {"chromium_binary", "launch_gate", "bwrap", "sandbox_daemon", "egress_daemon"})
            pins.append(pinned)
            if pinned.sha256 != _digest(asset["sha256"], "approved asset"):
                raise PrerequisiteError("approved asset digest mismatch")
            roles[role] = pinned
            if role == "runtime_manifest":
                runtime_manifest = pinned
        if not REQUIRED_ROLES <= set(roles):
            raise PrerequisiteError("approved mandatory runtime asset is missing")
        _runtime_inventory(runtime_manifest.read(), config["deployment"], pins)
        artifact_manifest = _pin(artifact / "compatibility.json", MAX_JSON_BYTES, approved=True)
        pins.append(artifact_manifest)
        if artifact_manifest.sha256 != expected_manifest or verify_artifact(artifact) != expected_manifest:
            raise PrerequisiteError("approved artifact manifest/files failed verification")
        manifest = _json(artifact_manifest.read())
        matches = []
        for entry in manifest["files"]:
            pinned = _pin(artifact / entry["relative_path"], MAX_ASSET_BYTES, approved=True)
            pins.append(pinned)
            if pinned.sha256 != entry["digest"]:
                raise PrerequisiteError("approved artifact file changed")
            if entry["digest"] == manifest["identity"]["binary_digest"]:
                matches.append(pinned.path)
        if matches != [roles["chromium_binary"].path]:
            raise PrerequisiteError("approved executable is not the pinned artifact binary")
        return Approval(path, config, config_pin.sha256, pins, probe)
    except BaseException:
        for pinned in pins:
            pinned.close()
        raise


def check_production_delegation(root, run_id):
    """Accept the holder, or an exact owned lab descendant with migration authority."""
    try:
        check_delegation(root)
        return None
    except DelegationError:
        pass
    service = root.parent
    lab = root / ("lab-" + run_id)
    current = process_cgroup(os.getpid())
    if (root.name != "workloads" or not root.is_relative_to(CGROUP_ROOT)
            or re.fullmatch(rf"browserd-validation-u{os.getuid()}-[0-9a-f]{{12}}\.service", service.name) is None
            or current != lab / "control"):
        raise PrerequisiteError("production runner lacks its exact delegated holder or current-run lab cgroup")
    for directory in (root, lab, lab / "control", lab / "shards"):
        _absolute(str(directory), "delegated lab cgroup")
        if any(path.is_symlink() for path in (directory, *directory.parents)):
            raise PrerequisiteError("delegated lab cgroup contains a symlink")
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise PrerequisiteError("delegated lab cgroup is not owned by the validation UID")
        for name in ("cgroup.controllers", "cgroup.procs", "cgroup.type"):
            info = (directory / name).lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise PrerequisiteError("delegated lab cgroup control ownership is invalid")
        if control_read(directory / "cgroup.type") != "domain":
            raise PrerequisiteError("delegated lab requires domain cgroups")
        if directory != lab / "control":
            required = {"cpu", "memory", "pids"}
            if (not required <= set(control_read(directory / "cgroup.controllers").split())
                    or not required <= set(control_read(directory / "cgroup.subtree_control").split())):
                raise PrerequisiteError("delegated lab lacks enabled cpu/memory/pids controllers")
        if directory != root and (not os.access(directory, os.W_OK)
                or os.statvfs(directory).f_flag & os.ST_RDONLY):
            raise PrerequisiteError("current-run lab cgroups must be writable")
    if (control_read(lab / "cgroup.procs") or control_read(lab / "shards/cgroup.procs")
            or str(os.getpid()) not in control_read(current / "cgroup.procs").split()):
        raise PrerequisiteError("current-run lab has invalid domain or process membership")
    return lab / "shards"


def _check_approved_delegation(env, binding, approval):
    root = _absolute(env.get("BROWSERD_VALIDATION_CGROUP_ROOT", ""), "delegated cgroup")
    shards = check_production_delegation(root, binding["run_id"])
    if shards is not None and approval.config["deployment"]["sandbox"]["cgroup_root"] != str(shards):
        raise PrerequisiteError("approved sandbox cgroup root differs from this exact current-run lab")


def binding_from_environment(env):
    expected = {key: env.get(f"BROWSERD_VALIDATION_{key.upper()}", "") for key in
                ("run_id", "tier", "manifest_sha256", "kernel_release", "machine")}
    try:
        parsed = uuid.UUID(expected["run_id"])
    except ValueError:
        raise PrerequisiteError("invalid current run UUID") from None
    if (str(parsed) != expected["run_id"] or parsed.int == 0 or expected["tier"] != "kernel"
            or expected["kernel_release"] != platform.release() or expected["machine"] != platform.machine()
            or platform.system() != "Linux" or env.get("BROWSERD_TRUSTED_VALIDATION") != "1"):
        raise PrerequisiteError("metadata must bind the current trusted Linux kernel run")
    _digest(expected["manifest_sha256"], "run artifact")
    revision = env.get("BROWSERD_VALIDATION_SOURCE_REVISION")
    dirty = env.get("BROWSERD_VALIDATION_SOURCE_DIRTY")
    content = env.get("BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256")
    if revision is not None:
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is None or set(revision) == {"0"}:
            raise PrerequisiteError("invalid source revision binding")
        expected["source_revision"] = revision
    if dirty is not None:
        if dirty not in {"true", "false"}:
            raise PrerequisiteError("invalid source dirty binding")
        expected["source_dirty"] = dirty == "true"
    if content is not None:
        expected["source_content_sha256"] = _digest(content, "source content")
    if dirty == "true" and content is None:
        raise PrerequisiteError("dirty runtime evidence requires a source content digest")
    log_dir = _absolute(env.get("BROWSERD_VALIDATION_LOG_DIR", ""), "run log")
    parent = _open_parent(log_dir / "entry", private_root=log_dir)
    os.close(parent)
    receipt = _absolute(env.get("BROWSERD_VALIDATION_RECEIPT", ""), "receipt")
    if receipt != log_dir / "receipt.json" or os.path.lexists(receipt):
        raise PrerequisiteError("receipt must be a fresh path in the private run directory")
    cgroup = _absolute(env.get("BROWSERD_VALIDATION_CGROUP_ROOT", ""), "delegated cgroup")
    check_production_delegation(cgroup, expected["run_id"])
    return expected, log_dir, receipt


def _publish(path, value):
    encoded = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    if len(encoded) > MAX_JSON_BYTES:
        raise ProbeFailure("output JSON exceeds its size bound")
    temporary = path.with_name("." + path.name + "-" + uuid.uuid4().hex)
    parent = _open_parent(path, private_root=path.parent)
    descriptor = None
    published = False
    try:
        descriptor = os.open(temporary.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        published = True
        os.fsync(parent)
    except BaseException:
        if published:
            original = os.stat(temporary.name, dir_fd=parent, follow_symlinks=False)
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                os.unlink(path.name, dir_fd=parent)
                try:
                    os.fsync(parent)
                except OSError:
                    pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary.name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)


def _check_run_directory(path, descriptor):
    current = _open_parent(path / "entry", private_root=path)
    try:
        held_metadata = os.fstat(descriptor)
        current_metadata = os.fstat(current)
        if held_metadata.st_nlink == 0 or (held_metadata.st_dev, held_metadata.st_ino) != (current_metadata.st_dev, current_metadata.st_ino):
            raise ProbeFailure("private run directory was replaced during validation")
    finally:
        os.close(current)


def execute_engine(approval, binding, log_dir):
    request_path = log_dir / "production-request.json"
    response_path = log_dir / "production-response.json"
    engine_log = log_dir / "production-engine.log"
    if any(os.path.lexists(path) for path in (request_path, response_path, engine_log)):
        raise PrerequisiteError("production engine output paths must be fresh")
    request = {"schema_version": 1, "binding": binding, "config_path": str(approval.path),
               "log_dir": str(log_dir), "deadline_seconds": DEADLINE_SECONDS}
    _publish(request_path, request)
    descriptor = os.open(engine_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    started_ns = time.time_ns()
    process = None
    try:
        with os.fdopen(descriptor, "wb") as output:
            process = subprocess.Popen([str(approval.probe.path), "--request", str(request_path), "--response", str(response_path)],
                cwd=log_dir, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, start_new_session=True, umask=0o077)
            try:
                code = process.wait(timeout=DEADLINE_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise ProbeFailure("production engine exceeded its deadline") from error
    finally:
        if process is not None:
            _stop(process)
    return code, response_path, started_ns


def validate_response(response_path, binding, log_dir, started_ns, code):
    pins = []
    try:
        response_pin = _pin(response_path, MAX_JSON_BYTES, private_root=log_dir)
        pins.append(response_pin)
        if response_pin.identity[7] < started_ns:
            raise ProbeFailure("engine response predates this execution")
        response = _json(response_pin.read())
        _object(response, {"schema_version", "binding", "status", "cleanup_complete", "probes"}, "engine response")
        if type(response["schema_version"]) is not int or response["schema_version"] != 1 or not _same_binding(response["binding"], binding):
            raise ProbeFailure("engine response belongs to another run or approved configuration")
        status = response["status"]
        if status not in {"passed", "blocked", "failed"} or type(response["cleanup_complete"]) is not bool:
            raise ProbeFailure("invalid engine completion")
        probes = response["probes"]
        if not isinstance(probes, dict) or set(probes) != set(KERNEL_PROBES):
            raise ProbeFailure("engine must report every production probe exactly once")
        for probe in probes.values():
            if not isinstance(probe, dict) or probe.get("status") not in {"passed", "blocked", "failed"}:
                raise ProbeFailure("invalid production probe status")
            if probe["status"] == "passed":
                _object(probe, {"status", "evidence"}, "probe result")
                _text(probe["evidence"], "probe evidence")
            else:
                _object(probe, {"status", "reason"}, "incomplete probe")
                _text(probe["reason"], "probe reason", 1024)
        if status != "passed":
            if code != (2 if status == "blocked" else 1):
                raise ProbeFailure("engine exit and result disagree")
            return status, {}, pins
        if code != 0 or not response["cleanup_complete"]:
            raise ProbeFailure("passing probes require a successful engine and positive cleanup")
        completed = {}
        seen = {response_path}
        for name in KERNEL_PROBES:
            probe = probes[name]
            _object(probe, {"status", "evidence"}, "probe result")
            if probe["status"] != "passed":
                raise ProbeFailure("missing or skipped production probe")
            evidence_path = _absolute(probe["evidence"], "probe evidence")
            if not evidence_path.is_relative_to(log_dir) or evidence_path in seen:
                raise ProbeFailure("probe evidence must be distinct and inside this run")
            seen.add(evidence_path)
            pinned = _pin(evidence_path, MAX_JSON_BYTES, private_root=log_dir)
            pins.append(pinned)
            if pinned.identity[7] < started_ns:
                raise ProbeFailure("probe evidence predates this execution")
            evidence = _json(pinned.read())
            _object(evidence, {"schema_version", "binding", "probe", "status", "observations"}, "probe evidence")
            if (type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1
                    or not _same_binding(evidence["binding"], binding) or evidence["probe"] != name or evidence["status"] != "passed"
                    or not isinstance(evidence["observations"], dict) or not evidence["observations"]):
                raise ProbeFailure("probe evidence does not prove this completed run")
            completed[name] = {"status": "passed", "evidence": str(evidence_path), "evidence_sha256": pinned.sha256}
        return status, completed, pins
    except BaseException:
        for pinned in pins:
            pinned.close()
        raise


def _same_binding(value, expected):
    return (isinstance(value, dict) and set(value) == set(expected)
            and all(type(value[key]) is type(expected[key]) and value[key] == expected[key] for key in expected))


def main(env=None):
    env = dict(os.environ) if env is None else env
    approval = None
    evidence_pins = []
    run_directory = None
    admitted = False
    try:
        binding, log_dir, receipt = binding_from_environment(env)
        run_directory = _open_parent(log_dir / "entry", private_root=log_dir)
        approval = load_configuration(env, binding["manifest_sha256"])
        _check_approved_delegation(env, binding, approval)
        binding.update(config_sha256=approval.config_sha256, probe_executable_sha256=approval.probe.sha256)
        approval.recheck()
        _check_run_directory(log_dir, run_directory)
        admitted = True
        code, response_path, started_ns = execute_engine(approval, binding, log_dir)
        _check_run_directory(log_dir, run_directory)
        status, probes, evidence_pins = validate_response(response_path, binding, log_dir, started_ns, code)
        if status != "passed":
            print(json.dumps({"status": status, "exit_code": 2 if status == "blocked" else 1}))
            return 2 if status == "blocked" else 1
        approval.recheck()
        for pinned in evidence_pins:
            pinned.recheck()
        _check_approved_delegation(env, binding, approval)
        _check_run_directory(log_dir, run_directory)
        _publish(receipt, {"schema_version": 1, **binding, "cleanup_complete": True, "probes": probes})
        print(json.dumps({"status": "passed", "receipt": str(receipt)}))
        return 0
    except (OSError, ValueError, GateError, KeyboardInterrupt, subprocess.SubprocessError) as error:
        code = 1 if admitted else 2
        reason = str(error) if isinstance(error, (PrerequisiteError, ProbeFailure)) else f"production runner could not complete ({type(error).__name__})"
        print(json.dumps({"status": "failed" if admitted else "blocked", "reason": reason, "exit_code": code}))
        return code
    finally:
        for pinned in evidence_pins:
            pinned.close()
        if approval is not None:
            approval.close()
        if run_directory is not None:
            os.close(run_directory)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    raise SystemExit(main())
