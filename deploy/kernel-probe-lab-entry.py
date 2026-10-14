#!/usr/bin/env python3
"""Container-only native probe setup. Root privilege never reaches probe processes.

Invoked only through kernel-probe-lab.py's three scoped bind mounts. The genuine
Redis, ClamAV, egress, sandbox and production wrapper run as the validation UID
with NoNewPrivileges and all effective/permitted/inheritable capabilities zero.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

_SPEC = importlib.util.spec_from_file_location("kernel_probe_lab", Path(__file__).with_name("kernel-probe-lab.py"))
lab = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lab)

ROOT = Path("/opt/browserd")
OUTPUT = Path("/output")
INITIALIZE_REASON = "isolated kernel measurement"
CGROUP_CONTROL_FILES = ("cgroup.procs", "cgroup.subtree_control", "cgroup.threads", "cgroup.kill", "cgroup.controllers", "cgroup.type")
CHILD_NOFILE_SOFT = 65536
PORTS = {"redis": 16379, "egress": 18083, "fixture": 31338, "loopback": 31339, "private": 31340}


def publish(path, value, uid=None, mode=0o600):
    with open(path, "x", encoding="utf-8", opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW, mode)) as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if uid is not None:
        os.chown(path, uid, uid)


def private(path, uid):
    path.mkdir(mode=0o700)
    os.chown(path, uid, uid)


def drop_privileges(uid):
    library = ctypes.CDLL(None, use_errno=True)
    for capability in range(64):
        if library.prctl(24, capability, 0, 0, 0) != 0:
            if ctypes.get_errno() == 22:
                break
            raise OSError(ctypes.get_errno(), "cannot drop capability bounding set")
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    if library.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot set NoNewPrivileges")
    fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (os.geteuid() != uid or fields["NoNewPrivs"].strip() != "1"
            or any(int(fields[key].strip(), 16) for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"))):
        raise lab.LabError("native process privilege drop did not complete")
    os.umask(0o077)


def prepare_child(uid):
    """Drop privilege and provision bounded asset-pin capacity in this child only."""
    drop_privileges(uid)
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < CHILD_NOFILE_SOFT:
        raise lab.LabError("inherited hard RLIMIT_NOFILE cannot support 65536 pinned asset descriptors")
    resource.setrlimit(resource.RLIMIT_NOFILE, (CHILD_NOFILE_SOFT, hard))
    if resource.getrlimit(resource.RLIMIT_NOFILE) != (CHILD_NOFILE_SOFT, hard):
        raise lab.LabError("child RLIMIT_NOFILE provisioning did not preserve its inherited hard limit")


def verify_stage(plan, stage=Path("/input")):
    if not os.statvfs(stage).f_flag & os.ST_RDONLY:
        raise lab.LabError("stage must be a read-only bind mount")
    if lab.inventory(stage) != plan["files"]:
        raise lab.LabError("stage bytes differ from exact approved inventory")
    lab.validate_filter((stage / plan["roles"]["seccomp"]).read_bytes())
    return stage


def install_assets(plan, stage):
    if any(ROOT.iterdir()) or ROOT.stat().st_uid != 0 or stat.S_IMODE(ROOT.stat().st_mode) != 0o755:
        raise lab.LabError("asset tmpfs must be fresh root-owned mode0755")
    # Executable tmpfs is mandatory: a tmpfs /dev/shm stage is not a runtime.
    filesystem = os.statvfs(ROOT)
    if filesystem.f_flag & (os.ST_RDONLY | getattr(os, "ST_NOEXEC", 8)):
        raise lab.LabError("container asset tmpfs must be writable and executable for root installation")
    for item in plan["files"]:
        source = stage / item["path"]
        destination = ROOT / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, item["mode"])
        try:
            with source.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(descriptor, chunk[offset:])
            os.fchmod(descriptor, item["mode"])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if lab.sha256_file(destination) != (item["sha256"], item["size"]):
            raise lab.LabError("installed root asset failed exact byte verification")
    if lab.inventory(stage) != plan["files"]:
        raise lab.LabError("stage changed during root asset installation")
    if any(item["source"] == lab.CHROMIUM_RESOURCE_SOURCE for item in plan["runtime_mounts"]):
        # The native locale overlay needs an existing mount point in its read-only parent.
        # This directory contains no baseline locale files to hide from runtime attestation.
        (ROOT / lab.CHROMIUM_RESOURCE_SOURCE / "locales").mkdir(mode=0o555)
        (ROOT / lab.CHROMIUM_RESOURCE_SOURCE).chmod(0o555)


def own_cgroup_controls(directory, uid):
    """Own only this fresh lab's real domain controls, including read-only proof files."""
    if directory.is_symlink() or not directory.is_dir() or (directory / "cgroup.type").read_text().strip() != "domain":
        raise lab.LabError("owned lab requires an actual domain cgroup")
    os.chown(directory, uid, uid)
    for name in CGROUP_CONTROL_FILES:
        path = directory / name
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise lab.LabError("required lab cgroup control is absent or aliased")
        os.chown(path, uid, uid)


def setup_cgroups(plan):
    root = lab.absolute(plan["lab_cgroup"])
    uid = plan["validation_uid"]
    if root.is_symlink() or not root.is_dir() or (root / "cgroup.procs").read_text().strip():
        raise lab.LabError("fresh scoped lab cgroup is unavailable or already populated")
    if any(item.is_dir() for item in root.iterdir()):
        raise lab.LabError("lab cgroup already contains an incarnation")
    if not {"cpu", "memory", "pids"} <= set((root / "cgroup.controllers").read_text().split()):
        raise lab.LabError("lab child lacks real delegated controllers")
    (root / "cgroup.subtree_control").write_text("+cpu +memory +pids\n")
    control, shards = root / "control", root / "shards"
    control.mkdir(mode=0o700)
    shards.mkdir(mode=0o700)
    (shards / "cgroup.subtree_control").write_text("+cpu +memory +pids\n")
    for directory in (root, control, shards):
        own_cgroup_controls(directory, uid)
    # Only this new scoped child is exposed. Root migration happens before UID drop.
    (control / "cgroup.procs").write_text("0\n")
    observed = [line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")]
    if observed != [str(control).removeprefix("/sys/fs/cgroup")]:
        raise lab.LabError("container launcher did not enter its exact owned control cgroup")
    return shards


def daemon_environment(plan, tokens, mounts):
    uid, run_id = plan["validation_uid"], plan["run_id"]
    state = OUTPUT / "state"
    base = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
            "HOME": str(state), "TMPDIR": "/tmp", "BROWSERD_REDIS_URL": "redis://127.0.0.1:16379/0",
            "BROWSERD_REDIS_PREFIX": "browserd-kernel-lab-" + run_id}
    common = {"BROWSERD_WORKER_ID": "browserd-kernel-lab", "BROWSERD_WORKER_EPOCH": "1",
        "BROWSERD_EGRESS_CONTROL_URL": "http://127.0.0.1:18083", "BROWSERD_EGRESS_INSTALL_SOCKET": str(state / "egress.sock"),
        "BROWSERD_EGRESS_DAEMON_EPOCH": "1", "BROWSERD_EGRESS_EXPECTED_SERVER_UID": str(uid),
        "BROWSERD_EGRESS_WORKER_TOKEN": tokens["worker"], "BROWSERD_EGRESS_SUPERVISOR_TOKEN": tokens["supervisor"],
        "BROWSERD_EGRESS_REQUEST_TIMEOUT_MILLIS": "5000", "BROWSERD_EGRESS_MAX_RESPONSE_BYTES": "65536"}
    egress = dict(base, BROWSER_EGRESS_CONTROL_BIND="127.0.0.1:18083", BROWSER_EGRESS_INSTALL_SOCKET=str(state / "egress.sock"),
        BROWSER_EGRESS_DAEMON_EPOCH_STATE=str(state / "egress" / "epoch"), BROWSER_EGRESS_EXPECTED_PEER_UID=str(uid),
        BROWSER_EGRESS_WORKER_ID="browserd-kernel-lab", BROWSER_EGRESS_WORKER_EPOCH="1",
        BROWSER_EGRESS_WORKER_TOKEN=tokens["worker"], BROWSER_EGRESS_SUPERVISOR_TOKEN=tokens["supervisor"],
        # Terminal plans remain as anti-replay tombstones; reserve the full 1,000
        # lifecycle launches plus functional/qualification/helper generations.
        BROWSER_EGRESS_MAX_CONTROL_CONNECTIONS="128", BROWSER_EGRESS_MAX_LEASE_MILLIS="30000", BROWSER_EGRESS_MAX_PLANS="2048",
        BROWSER_EGRESS_MAX_CONNECTIONS_PER_ROUTE="64", BROWSER_EGRESS_MAX_CONNECTION_STARTS_PER_MINUTE="1200",
        BROWSER_EGRESS_MAX_DNS_PER_MINUTE="600", BROWSER_EGRESS_MAX_BYTES_PER_MINUTE="67108864",
        BROWSER_EGRESS_MAX_TOTAL_BYTES="1073741824", BROWSER_EGRESS_MAX_RESPONSE_BYTES="33554432",
        BROWSER_EGRESS_IDLE_TIMEOUT_MILLIS="30000")
    binary_digest = next(item["sha256"] for item in plan["files"] if item["path"] == plan["chromium_binary"])
    sandbox = dict(base, **common, BROWSERD_SANDBOX_SOCKET=str(state / "sandbox.sock"),
        BROWSERD_SANDBOX_JOURNAL_DIR=str(state / "sandbox-journal"), BROWSERD_SANDBOXD_EPOCH_STATE=str(state / "sandbox" / "epoch"),
        BROWSERD_SANDBOX_CGROUP_ROOT=str(Path(plan["lab_cgroup"]) / "shards"), BROWSERD_SANDBOX_RUNTIME_ROOT=str(state / "sandboxes"),
        BROWSERD_SANDBOX_EXPECTED_PEER_UID=str(uid), BROWSERD_SUPERVISOR_LEASE_MILLIS="30000",
        BROWSERD_DIRECTORY_LEASE_MILLIS="60000", BROWSERD_SANDBOX_CLEANUP_TIMEOUT_MILLIS="10000",
        BROWSERD_SANDBOX_RPC_TIMEOUT_MILLIS="5000", BROWSERD_SANDBOX_LEASE_SWEEP_MILLIS="1000",
        BROWSERD_SANDBOX_RPC_MAX_FRAME_BYTES="1048576", BROWSERD_SANDBOX_RPC_MAX_CONNECTIONS="128",
        BROWSERD_CHROMIUM_BINARY_SHA256=binary_digest, BROWSERD_CHROMIUM_ARTIFACT_ROOT=str(ROOT / plan["artifact_root"]),
        BROWSERD_CHROMIUM_HOST_EXECUTABLE=str(ROOT / plan["chromium_binary"]), BROWSERD_CHROMIUM_SANDBOX_EXECUTABLE=str(lab.CHROMIUM_SANDBOX_EXECUTABLE),
        BROWSERD_LAUNCH_GATE_HOST_EXECUTABLE=str(ROOT / plan["roles"]["launch_gate"]), BROWSERD_LAUNCH_GATE_SANDBOX_EXECUTABLE="/browserd/launch-gate",
        BROWSERD_BWRAP_EXECUTABLE="/usr/bin/bwrap", BROWSERD_SANDBOX_READ_ONLY_MOUNTS_JSON=json.dumps(mounts, separators=(",", ":")),
        BROWSERD_SANDBOX_SECCOMP_FD="5", BROWSERD_SANDBOX_MEMORY_MAX_BYTES="2147483648",
        BROWSERD_SANDBOX_MEMORY_HIGH_BYTES="1610612736", BROWSERD_SANDBOX_PIDS_MAX="512",
        BROWSERD_SANDBOX_CPU_QUOTA="200000", BROWSERD_SANDBOX_CPU_PERIOD="100000",
        BROWSERD_SANDBOX_TERMINATION_GRACE_MILLIS="3000", BROWSERD_SANDBOX_PROCESS_POLL_MILLIS="50",
        BROWSERD_SANDBOX_RECOVERY_TIMEOUT_MILLIS="30000", BROWSERD_SANDBOX_RECOVERY_CONCURRENCY="8")
    return base, egress, sandbox


def approval_configuration(plan, tokens):
    paths = {role: ROOT / name for role, name in plan["roles"].items()}
    paths["chromium_binary"] = ROOT / plan["chromium_binary"]
    paths["bwrap"] = Path("/usr/bin/bwrap")
    paths["runtime_manifest"] = ROOT / "runtime-manifest.json"
    mounts = [{"source": str(ROOT / item["source"]), "destination": item["destination"]} for item in plan["runtime_mounts"]]
    runtime = {"schema_version": 1, "mounts": []}
    for mount, relative_mount in zip(mounts, plan["runtime_mounts"]):
        root = PurePosixPath(relative_mount["source"])
        files = [{"relative_path": str(PurePosixPath(item["path"]).relative_to(root)), "sha256": item["sha256"]}
                 for item in plan["files"] if PurePosixPath(item["path"]).is_relative_to(root)]
        runtime["mounts"].append(dict(mount, files=files))
    publish(paths["runtime_manifest"], runtime, mode=0o444)
    approved = [{"role": role, "path": str(paths[role]), "sha256": lab.sha256_file(paths[role])[0]}
                for role in ("chromium_binary", "launch_gate", "bwrap", "seccomp", "sandbox_daemon", "egress_daemon", "runtime_manifest")]
    # Also pin the executable Python wrapper/source and native initialization operation.
    for name in sorted([*plan["roles"].values(), *(item["path"] for item in plan["files"] if item["path"].startswith("scripts/"))]):
        path = ROOT / name
        if str(path) not in {item["path"] for item in approved} and path != paths["probe"]:
            approved.append({"role": "runtime_file", "path": str(path), "sha256": lab.sha256_file(path)[0]})
    state = OUTPUT / "state"
    policy_digest = hashlib.sha256(json.dumps({"profile": "public-web", "shared_context": False,
        "source_content_sha256": plan["source_binding"]["source_content_sha256"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    config = {"schema_version": 1, "operator_approval": True, "isolated_validation": True,
        "validation_uid": plan["validation_uid"], "manifest_sha256": plan["manifest_sha256"],
        "artifact_root": str(ROOT / plan["artifact_root"]),
        "probe_executable": {"path": str(paths["probe"]), "sha256": lab.sha256_file(paths["probe"])[0]},
        "approved_assets": approved, "deployment": {
        "sandbox": {"socket_path": str(state / "sandbox.sock"), "expected_server_uid": plan["validation_uid"], "daemon_epoch": 1,
            "worker_id": "browserd-kernel-lab", "worker_epoch": 1, "cgroup_root": str(Path(plan["lab_cgroup"]) / "shards"),
            "runtime_root": str(state / "sandboxes"), "journal_directory": str(state / "sandbox-journal")},
        "egress": {"control_url": "http://127.0.0.1:18083", "install_socket": str(state / "egress.sock"),
            "expected_server_uid": plan["validation_uid"], "daemon_epoch": 1, "worker_token": tokens["worker"],
            "supervisor_token": tokens["supervisor"], "policy_profile": "public-web", "policy_digest": policy_digest},
        "runtime": {"redis_url": "redis://127.0.0.1:16379/0", "redis_prefix": "browserd-kernel-lab-" + plan["run_id"],
            "safety_pin_path": str(state / "safety" / "pin.json")},
        "worker": {"state_root": str(state / "worker"), "max_session_count": 8, "privileged_evaluate": True,
            "scanner": {"socket_path": str(state / "clamd.sock"), "expected_uid": plan["validation_uid"],
                        "max_database_age_millis": 86400000, "max_future_skew_millis": 60000}},
        "fixtures": {"bind_address": "0.0.0.0:31338", "origin": f"http://{plan['public_ip']}:31338",
            "host_direct_address": "127.0.0.1:31339", "private_direct_address": f"{plan['private_ip']}:31340"},
        "assets": {"chromium_host_executable": str(paths["chromium_binary"]), "chromium_sandbox_executable": str(lab.CHROMIUM_SANDBOX_EXECUTABLE),
            "launch_gate_host_executable": str(paths["launch_gate"]), "launch_gate_sandbox_executable": "/browserd/launch-gate",
            "bwrap_executable": str(paths["bwrap"]), "seccomp_filter": str(paths["seccomp"]),
            "sandbox_daemon_executable": str(paths["sandbox_daemon"]), "egress_daemon_executable": str(paths["egress_daemon"]),
            "runtime_manifest": str(paths["runtime_manifest"]), "read_only_mounts": mounts}}}
    config_path = ROOT / "approval.json"
    publish(config_path, config, mode=0o640)
    os.chown(config_path, 0, plan["validation_uid"])
    return config, config_path, mounts


class Processes:
    def __init__(self, uid):
        self.uid, self.items, self.streams = uid, [], []

    def start(self, label, argv, env, *, filter_path=None):
        log = OUTPUT / (label + ".log")
        stream = log.open("xb")
        os.chmod(log, 0o600)
        os.chown(log, self.uid, self.uid)
        self.streams.append(stream)
        if filter_path is not None:
            # The existing production wrapper uses the same explicit inherited FD.
            # Each dynamic path is a positional shell argument, never shell source.
            argv = ["/bin/sh", "-c", 'exec 5< "$1"; shift; exec "$@"',
                    "browserd-approved-seccomp", str(filter_path), *argv]
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
            env=env, start_new_session=True, preexec_fn=lambda: prepare_child(self.uid), umask=0o077)
        self.items.append((label, process))
        return process

    def stop(self):
        complete = True
        for _label, process in reversed(self.items):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=20)
                except (OSError, subprocess.TimeoutExpired):
                    complete = False
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
        for stream in self.streams:
            stream.close()
        return complete


def wait_socket(path, process, deadline=60):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if process.poll() is not None:
            raise lab.LabError("required native service exited before readiness")
        try:
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(0.5)
                connection.connect(str(path))
            return
        except OSError:
            time.sleep(0.1)
    raise lab.LabError("native service readiness exceeded its deadline")


def wait_tcp(port, process):
    end = time.monotonic() + 60
    while time.monotonic() < end:
        if process.poll() is not None:
            raise lab.LabError("required native service exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise lab.LabError("native TCP readiness exceeded its deadline")


def canary(address):
    host, port = address.rsplit(":", 1)
    with socket.socket() as listener:
        listener.bind((host, int(port)))
        listener.listen(16)
        while True:
            connection, _peer = listener.accept()
            with connection:
                connection.settimeout(0.5)
                try:
                    connection.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass


def socket_peer(connection, uid, pid):
    actual_pid, actual_uid, _gid = struct.unpack("=3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if actual_uid != uid or actual_pid != pid:
        raise lab.LabError("service preflight Unix peer differs from the exact started service")


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        block = connection.recv(size - len(result))
        if not block:
            raise lab.LabError("native service closed before its complete response")
        result.extend(block)
    return bytes(result)


def epoch_exchange(path, request, uid, pid, decoder):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        socket_peer(connection, uid, pid)
        encoded = json.dumps(request, separators=(",", ":")).encode()
        connection.sendall(struct.pack(">I", len(encoded)) + encoded)
        length = struct.unpack(">I", receive_exact(connection, 4))[0]
        if not 0 < length <= 65536:
            raise lab.LabError("native service response exceeded its bound")
        return decoder(receive_exact(connection, length))


def validate_epoch_response(response, nonce, expected_epoch, *, sandbox):
    expected = ({"status": "success", "value": {"result": "daemon_epoch_probe",
        "value": {"daemon_epoch": expected_epoch, "request_nonce": nonce}}} if sandbox else
        {"protocol_version": 1, "nonce": nonce, "current_daemon_epoch": expected_epoch})
    # Type-preserving canonical encoding also rejects bool standing in for an epoch.
    if json.dumps(response, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise lab.LabError("native service epoch response is stale, uncorrelated or malformed")


def scanner_reply(connection, sequence):
    response = bytearray()
    while len(response) <= 8192:
        value = receive_exact(connection, 1)
        if value == b"\0":
            prefix = str(sequence).encode() + b": "
            if not response.startswith(prefix):
                raise lab.LabError("ClamAV reply sequence mismatch")
            return bytes(response[len(prefix):])
        response.extend(value)
    raise lab.LabError("ClamAV response exceeded its bound")


def validate_scanner_version(raw, now):
    try:
        match = re.fullmatch(r"ClamAV ([!-~]{1,64})/([1-9][0-9]*)/(.+)", raw.decode("ascii"))
        if match is None:
            raise ValueError("invalid scanner version")
        date = datetime.strptime(match[3], "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        if "/" in match[1] or date.strftime("%a %b %e %H:%M:%S %Y") != match[3] or not 0 < int(match[2]) < 2**64:
            raise ValueError("noncanonical scanner version")
        age = now - date.timestamp()
        if age < -60 or age > 86400:
            raise ValueError("scanner database is stale or future dated")
    except (UnicodeError, ValueError, OverflowError) as error:
        raise lab.LabError("genuine scanner did not report fresh canonical UTC version metadata") from error
    return hashlib.sha256(raw).hexdigest()


def scan_preflight(path, uid, pid):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(30)
        connection.connect(str(path))
        socket_peer(connection, uid, pid)
        connection.sendall(b"zIDSESSION\0zVERSION\0")
        before = scanner_reply(connection, 1)
        version = validate_scanner_version(before, time.time())
        canary_bytes = b"browserd-isolated-service-preflight\n"
        connection.sendall(b"zINSTREAM\0" + struct.pack(">I", len(canary_bytes)) + canary_bytes + b"\0\0\0\0")
        if scanner_reply(connection, 2) != b"stream: OK":
            raise lab.LabError("genuine scanner did not positively scan the exact service canary clean")
        connection.sendall(b"zVERSION\0")
        after = scanner_reply(connection, 3)
        if after != before:
            raise lab.LabError("scanner metadata changed during the actual clean scan")
        validate_scanner_version(after, time.time())
        connection.sendall(b"zEND\0")
        if connection.recv(1):
            raise lab.LabError("scanner session retained unexpected trailing data")
        return {"peer_pid": pid, "version_metadata_sha256": version, "scanned_bytes": len(canary_bytes),
                "scanned_sha256": hashlib.sha256(canary_bytes).hexdigest(), "verdict": "clean"}


def service_preflight(path):
    """Read-only admission and real service messages, never a qualification receipt."""
    if path != OUTPUT / "state/service-preflight-request.json" or os.geteuid() == 0:
        raise lab.LabError("service preflight must run unprivileged on its exact private input")
    request = lab.read_json(path)
    if (set(request) != {"schema_version", "run_id", "expected_pids"} or type(request["schema_version"]) is not int
            or request["schema_version"] != 1 or request["run_id"] != os.environ.get("BROWSERD_VALIDATION_RUN_ID")
            or set(request["expected_pids"]) != {"sandbox", "egress", "scanner"}
            or any(type(pid) is not int or pid <= 0 for pid in request["expected_pids"].values())):
        raise lab.LabError("service preflight input lacks exact current-run process bindings")
    sys.path.insert(0, str(ROOT / "scripts"))
    import production_kernel_runner as production
    binding, logs, _receipt = production.binding_from_environment(os.environ)
    approval = production.load_configuration(os.environ, binding["manifest_sha256"])
    try:
        production._check_approved_delegation(os.environ, binding, approval)
        binding.update(config_sha256=approval.config_sha256, probe_executable_sha256=approval.probe.sha256)
        config = approval.config["deployment"]
        uid, pids = os.geteuid(), request["expected_pids"]
        for label, executable in (("sandbox", config["assets"]["sandbox_daemon_executable"]),
                                  ("egress", config["assets"]["egress_daemon_executable"])):
            actual, _size = lab.sha256_file(Path(f"/proc/{pids[label]}/exe").resolve())
            if actual != lab.sha256_file(Path(executable))[0]:
                raise lab.LabError("native preflight daemon executable differs from its approved bytes")
        nonce = str(uuid.uuid4())
        sandbox_response = epoch_exchange(config["sandbox"]["socket_path"],
            {"operation": "probe_daemon_epoch", "sandboxd_epoch": config["sandbox"]["daemon_epoch"],
             "worker_id": config["sandbox"]["worker_id"], "worker_epoch": config["sandbox"]["worker_epoch"],
             "request_nonce": nonce}, uid, pids["sandbox"], production._json)
        validate_epoch_response(sandbox_response, nonce, config["sandbox"]["daemon_epoch"], sandbox=True)
        nonce = str(uuid.uuid4())
        egress_response = epoch_exchange(config["egress"]["install_socket"], {"protocol_version": 1, "nonce": nonce},
            uid, pids["egress"], production._json)
        validate_epoch_response(egress_response, nonce, config["egress"]["daemon_epoch"], sandbox=False)
        connection = http.client.HTTPConnection("127.0.0.1", 18083, timeout=5)
        try:
            connection.request("GET", "/readyz")
            response = connection.getresponse()
            if response.status != 204 or response.read(1):
                raise lab.LabError("genuine egress has not freshly observed initialized safety authority")
        finally:
            connection.close()
        with socket.create_connection(("127.0.0.1", 16379), timeout=5) as redis:
            redis.sendall(b"*1\r\n$4\r\nPING\r\n")
            if receive_exact(redis, 7) != b"+PONG\r\n":
                raise lab.LabError("isolated Redis did not answer PING")
        scan = scan_preflight(config["worker"]["scanner"]["socket_path"], uid, pids["scanner"])
        approval.recheck()
        publish(logs / "service-preflight.json", {"schema_version": 1, "run_id": binding["run_id"],
            "status": "services_ready", "diagnostic": True, "qualification": False,
            "sandbox_epoch": config["sandbox"]["daemon_epoch"], "egress_epoch": config["egress"]["daemon_epoch"],
            "redis_ping": True, "egress_safety_ready": True, "scanner": scan})
        publish(logs / "preflight-request.json", {"schema_version": 1, "binding": binding,
            "config_path": str(approval.path), "log_dir": str(logs), "deadline_seconds": 7200})
        return 0
    finally:
        approval.close()


def validate_diagnostic_response(response, binding, code):
    expected_keys = {"schema_version", "binding", "status", "diagnostic", "qualification", "cleanup_complete", "observations", "omitted_probes"}
    names = {"chromium_identity", "chromium_sandbox", "outer_sandbox", "context_create_dispose", "proxy_loopback",
        "direct_egress_denial", "target_pause_resume", "context_ownership", "emulation", "downloads", "pdf_streaming",
        "screencast_ack", "orphan_targets_zero", "worker_sigkill_cleanup", "cross_shard_isolation"}
    if (not isinstance(response, dict) or set(response) != expected_keys
            or type(response["schema_version"]) is not int or response["schema_version"] != 1
            or json.dumps(response["binding"], sort_keys=True) != json.dumps(binding, sort_keys=True)
            or response["diagnostic"] is not True or response["qualification"] is not False
            or type(response["cleanup_complete"]) is not bool or response["omitted_probes"] != ["start_stop_1000"]
            or not isinstance(response["observations"], dict) or set(response["observations"]) != names):
        raise lab.LabError("native diagnostic response does not bind exactly this isolated preflight")
    status = response["status"]
    if status not in {"preflight_completed", "blocked", "failed"} or code != {"preflight_completed": 0, "blocked": 2, "failed": 1}[status]:
        raise lab.LabError("native diagnostic response and exit status disagree")
    for observed in response["observations"].values():
        if not isinstance(observed, dict) or observed.get("status") not in {"passed", "failed", "blocked"}:
            raise lab.LabError("native diagnostic observation is incomplete")
        if set(observed) != ({"status", "evidence"} if observed["status"] == "passed" else {"status", "reason"}):
            raise lab.LabError("native diagnostic observation has unexpected fields")
    if status == "preflight_completed" and (not response["cleanup_complete"] or any(
            observation["status"] != "passed" for observation in response["observations"].values())):
        raise lab.LabError("native diagnostic completion lacks all15 observations and positive cleanup")
    return status


def diagnostic_result(path):
    if path != OUTPUT / "state/diagnostic-result-request.json" or os.geteuid() == 0:
        raise lab.LabError("diagnostic validation must use its exact unprivileged private input")
    meta = lab.read_json(path)
    if (set(meta) != {"schema_version", "run_id", "exit_code", "started_ns"} or type(meta["schema_version"]) is not int or meta["schema_version"] != 1
            or meta["run_id"] != os.environ.get("BROWSERD_VALIDATION_RUN_ID")
            or type(meta["exit_code"]) is not int or meta["exit_code"] not in {0, 1, 2}
            or type(meta["started_ns"]) is not int or meta["started_ns"] <= 0):
        raise lab.LabError("diagnostic validation metadata is invalid")
    sys.path.insert(0, str(ROOT / "scripts"))
    import production_kernel_runner as production
    expected, logs, receipt = production.binding_from_environment(os.environ)
    approval = production.load_configuration(os.environ, expected["manifest_sha256"])
    pins = []
    try:
        production._check_approved_delegation(os.environ, expected, approval)
        expected.update(config_sha256=approval.config_sha256, probe_executable_sha256=approval.probe.sha256)
        if receipt.exists() or (logs / "production-response.json").exists():
            raise lab.LabError("a diagnostic must never contain a qualification receipt or production response")
        response_path = logs / "preflight-response.json"
        pinned = production._pin(response_path, production.MAX_JSON_BYTES, private_root=logs)
        pins.append(pinned)
        if pinned.identity[7] < meta["started_ns"]:
            raise lab.LabError("native diagnostic response predates this execution")
        response = production._json(pinned.read())
        validate_diagnostic_response(response, expected, meta["exit_code"])
        seen = {response_path}
        for name, observation in response["observations"].items():
            if observation["status"] != "passed":
                production._text(observation["reason"], "diagnostic reason", 1024)
                continue
            evidence = production._absolute(observation["evidence"], "diagnostic evidence")
            if not evidence.is_relative_to(logs) or evidence in seen:
                raise lab.LabError("diagnostic evidence escapes or repeats this exact run")
            seen.add(evidence)
            item = production._pin(evidence, production.MAX_JSON_BYTES, private_root=logs)
            pins.append(item)
            if item.identity[7] < meta["started_ns"]:
                raise lab.LabError("native diagnostic observation predates this execution")
            data = production._json(item.read())
            if (set(data) != {"schema_version", "binding", "probe", "status", "observations"}
                    or type(data["schema_version"]) is not int or data["schema_version"] != 1
                    or not production._same_binding(data["binding"], expected) or data["probe"] != name
                    or data["status"] != "passed" or not isinstance(data["observations"], dict) or not data["observations"]):
                raise lab.LabError("native diagnostic evidence does not prove its actual current-run observation")
        approval.recheck()
        for item in pins:
            item.recheck()
        return meta["exit_code"]
    finally:
        for item in pins:
            item.close()
        approval.close()


def scanner_database(plan, uid):
    """Keep genuine signatures off the host output disk; verify optional staged bytes."""
    directory = Path("/tmp/private-clamav")
    private(directory, uid)
    for item in plan["files"]:
        if not item["path"].startswith("clamav/"):
            continue
        name = item["path"].removeprefix("clamav/")
        if name not in {"main.cvd", "main.cld", "daily.cvd", "daily.cld", "bytecode.cvd", "bytecode.cld"}:
            raise lab.LabError("optional signature stage contains an unexpected file")
        destination = directory / name
        shutil.copyfile(ROOT / item["path"], destination, follow_symlinks=False)
        destination.chmod(0o600)
        os.chown(destination, uid, uid)
        if lab.sha256_file(destination) != (item["sha256"], item["size"]):
            raise lab.LabError("optional genuine scanner database byte verification failed")
    return directory


def run(plan, *, preflight=False):
    lab.validate_plan(plan)
    uid = plan["validation_uid"]
    if os.geteuid() != 0 or not Path("/.dockerenv").exists():
        raise lab.LabError("entry must run as root inside a fresh Docker container")
    if OUTPUT.is_symlink() or OUTPUT.stat().st_uid != uid or stat.S_IMODE(OUTPUT.stat().st_mode) != 0o700:
        raise lab.LabError("output is not the fresh private validation directory")
    if {path.name for path in OUTPUT.iterdir()} != {"lab-plan.json"}:
        raise lab.LabError("output contains prior run state")
    for command in ("ip", "bwrap", "redis-server", "clamd", "freshclam"):
        if shutil.which(command) is None:
            raise lab.LabError("prepared image lacks a required real command: " + command)
    stage = verify_stage(plan)
    install_assets(plan, stage)
    shards = setup_cgroups(plan)
    for address in (plan["public_ip"], plan["private_ip"]):
        subprocess.run(["ip", "address", "add", address + "/32", "dev", "lo"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, stdout=subprocess.DEVNULL)
    state, evidence = OUTPUT / "state", OUTPUT / "evidence"
    private(state, uid)
    private(evidence, uid)
    for name in ("redis", "egress", "sandbox", "sandbox-journal", "sandboxes", "worker", "safety"):
        private(state / name, uid)
    clamav = scanner_database(plan, uid)
    tokens = {"worker": secrets.token_hex(32), "supervisor": secrets.token_hex(32)}
    config, config_path, mounts = approval_configuration(plan, tokens)
    base, egress_env, sandbox_env = daemon_environment(plan, tokens, mounts)
    if preflight:
        sandbox_env["BROWSERD_SANDBOX_PRIVATE_CHILD_STDERR_FILE"] = str(state / "native-preflight-child.stderr")
    processes = Processes(uid)
    outcome, reason, probe_code, diagnostic_code, cleanup = "blocked", None, None, None, False
    try:
        freshclam_config = state / "freshclam.conf"
        freshclam_config.write_text(f"DatabaseDirectory {clamav}\nDatabaseMirror database.clamav.net\nChecks 1\n")
        os.chmod(freshclam_config, 0o600)
        os.chown(freshclam_config, uid, uid)
        freshclam = processes.start("freshclam", [shutil.which("freshclam"), "--config-file=" + str(freshclam_config), "--stdout"], base)
        if freshclam.wait(timeout=1200) != 0:
            raise lab.LabError("genuine freshclam database update failed")
        if not any((clamav / name).is_file() for name in ("daily.cvd", "daily.cld")):
            raise lab.LabError("freshclam produced no genuine current daily database")
        clamd_config = state / "clamd.conf"
        clamd_config.write_text(f"DatabaseDirectory {clamav}\nLocalSocket {state / 'clamd.sock'}\nLocalSocketMode 0600\nForeground yes\nMaxThreads 2\nStreamMaxLength 32M\n")
        os.chmod(clamd_config, 0o600)
        os.chown(clamd_config, uid, uid)
        scanner = processes.start("clamd", [shutil.which("clamd"), "--config-file=" + str(clamd_config)], base)
        wait_socket(state / "clamd.sock", scanner, deadline=180)
        redis = processes.start("redis", [shutil.which("redis-server"), "--bind", "127.0.0.1", "--port", "16379",
            "--dir", str(state / "redis"), "--appendonly", "yes", "--save", ""], base)
        wait_tcp(PORTS["redis"], redis)
        initializer = processes.start("safety-initialize", [str(ROOT / plan["roles"]["safety_initializer"]),
            "--redis-url", base["BROWSERD_REDIS_URL"], "--redis-prefix", base["BROWSERD_REDIS_PREFIX"],
            "--reason", INITIALIZE_REASON], base)
        if initializer.wait(timeout=30) != 0:
            raise lab.LabError("native durable safety Initialize failed")
        egress = processes.start("egress", [str(ROOT / plan["roles"]["egress_daemon"])], egress_env)
        wait_tcp(PORTS["egress"], egress)
        wait_socket(state / "egress.sock", egress)
        sandbox = processes.start("sandbox", [str(ROOT / plan["roles"]["sandbox_daemon"])], sandbox_env,
            filter_path=ROOT / plan["roles"]["seccomp"])
        wait_socket(state / "sandbox.sock", sandbox)
        wrapper_env = dict(base, BROWSERD_TRUSTED_VALIDATION="1", BROWSERD_VALIDATION_RUN_ID=plan["run_id"],
            BROWSERD_VALIDATION_TIER="kernel", BROWSERD_VALIDATION_MANIFEST_SHA256=plan["manifest_sha256"],
            BROWSERD_VALIDATION_KERNEL_RELEASE=platform.release(), BROWSERD_VALIDATION_MACHINE=platform.machine(),
            BROWSERD_VALIDATION_CGROUP_ROOT=plan["delegated_workloads"], BROWSERD_VALIDATION_LOG_DIR=str(evidence),
            BROWSERD_VALIDATION_RECEIPT=str(evidence / "receipt.json"),
            BROWSERD_CHROMIUM_ARTIFACT_ROOT=config["artifact_root"], BROWSERD_KERNEL_PROBE_CONFIG=str(config_path),
            BROWSERD_KERNEL_PROBE_CONFIG_SHA256=lab.sha256_file(config_path)[0],
            BROWSERD_VALIDATION_SOURCE_REVISION=plan["source_binding"]["source_revision"],
            BROWSERD_VALIDATION_SOURCE_DIRTY=str(plan["source_binding"]["source_dirty"]).lower(),
            BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256=plan["source_binding"]["source_content_sha256"])
        service_request = state / "service-preflight-request.json"
        publish(service_request, {"schema_version": 1, "run_id": plan["run_id"],
            "expected_pids": {"sandbox": sandbox.pid, "egress": egress.pid, "scanner": scanner.pid}}, uid)
        checker = processes.start("service-preflight", [sys.executable, str(ROOT / "helpers/kernel-probe-lab-entry.py"),
            "--internal-service-preflight", str(service_request)], wrapper_env)
        if checker.wait(timeout=90) != 0:
            raise lab.LabError("genuine service preflight or approved input admission failed")
        for label, address in (("loopback", "127.0.0.1:31339"), ("private", f"{plan['private_ip']}:31340")):
            child = processes.start(label + "-canary", [sys.executable, str(ROOT / "helpers/kernel-probe-lab-entry.py"),
                "--internal-canary", address], base)
            if label == "loopback":
                wait_tcp(PORTS[label], child)
            else:
                end = time.monotonic() + 10
                while True:
                    if child.poll() is not None:
                        raise lab.LabError("owned private canary exited")
                    try:
                        with socket.create_connection((plan["private_ip"], PORTS[label]), timeout=0.5):
                            break
                    except OSError:
                        if time.monotonic() >= end:
                            raise lab.LabError("owned private canary was not reachable")
                        time.sleep(0.1)
        if preflight:
            outcome = "failed"
            started_ns = time.time_ns()
            diagnostic_env = dict(base)
            repetition_key = "BROWSERD_KERNEL_PREFLIGHT_PROXY_REPETITIONS"
            if repetition_key in os.environ:
                diagnostic_env[repetition_key] = os.environ[repetition_key]
            diagnostic = processes.start("browser-preflight", [str(ROOT / plan["roles"]["probe"]),
                "--preflight-request", str(evidence / "preflight-request.json"),
                "--response", str(evidence / "preflight-response.json")], diagnostic_env)
            diagnostic_code = diagnostic.wait(timeout=1500)
            if diagnostic_code not in {0, 1, 2}:
                raise lab.LabError("native browser diagnostic exited abnormally")
            validation_request = state / "diagnostic-result-request.json"
            publish(validation_request, {"schema_version": 1, "run_id": plan["run_id"],
                "exit_code": diagnostic_code, "started_ns": started_ns}, uid)
            verified = processes.start("browser-preflight-verify", [sys.executable,
                str(ROOT / "helpers/kernel-probe-lab-entry.py"), "--internal-diagnostic-result", str(validation_request)], wrapper_env)
            if verified.wait(timeout=30) != diagnostic_code:
                raise lab.LabError("native browser diagnostic evidence was not independently admitted")
            outcome = {0: "preflight_completed", 1: "failed", 2: "blocked"}[diagnostic_code]
            if diagnostic_code:
                reason = "native browser diagnostic did not complete all15 observations"
        else:
            probe = processes.start("production-runner", [sys.executable, str(ROOT / "scripts/production_kernel_runner.py")], wrapper_env)
            end = time.monotonic() + 7300
            while probe.poll() is None:
                if any(service.poll() is not None for service in (redis, scanner, egress, sandbox)):
                    raise lab.LabError("a genuine required service exited during kernel measurement")
                if time.monotonic() >= end:
                    raise lab.LabError("kernel measurement exceeded its outer deadline")
                time.sleep(1)
            probe_code = probe.returncode
            if probe_code == 0 and not (evidence / "receipt.json").is_file():
                raise lab.LabError("production wrapper exited zero without its real receipt")
            if probe_code not in {0, 1, 2}:
                raise lab.LabError("production wrapper exited abnormally")
            outcome = "finished"
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, lab.LabError) else "isolated native lab failed: " + type(error).__name__
    finally:
        cleanup = processes.stop()
        remaining = [item for item in shards.iterdir() if item.is_dir()]
        if remaining or (shards / "cgroup.procs").read_text().strip():
            cleanup = False
        if not cleanup:
            outcome, reason = "failed", "owned services or shard cgroups did not positively clean up"
        status = {"schema_version": 1, "run_id": plan["run_id"], "environment": "isolated_native_container",
                  "status": outcome, "mode": "preflight" if preflight else "measurement",
                  "full_production_probes_executed": probe_code is not None, "probe_exit_code": probe_code,
                  "diagnostic_executed": diagnostic_code is not None, "diagnostic_exit_code": diagnostic_code, "services_reaped": cleanup,
                  "lab_cgroup": plan["lab_cgroup"], "host_cgroup_removal_pending": True,
                  "exit_code": 0 if outcome == "preflight_completed" and cleanup else
                               probe_code if outcome == "finished" and cleanup else 1 if outcome == "failed" else 2}
        if reason:
            status["reason"] = reason
        publish(OUTPUT / "lab-status.json", status, uid)
    return status["exit_code"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--internal-canary")
    parser.add_argument("--internal-service-preflight", type=Path)
    parser.add_argument("--internal-diagnostic-result", type=Path)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args(argv)
    if args.internal_canary:
        canary(args.internal_canary)
        return 0
    if args.internal_diagnostic_result:
        return diagnostic_result(args.internal_diagnostic_result)
    if args.internal_service_preflight:
        return service_preflight(args.internal_service_preflight)
    if args.plan != OUTPUT / "lab-plan.json":
        parser.error("--plan must be /output/lab-plan.json")
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        return run(lab.read_json(args.plan), preflight=args.preflight)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error) if isinstance(error, lab.LabError) else type(error).__name__, "exit_code": 2}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
