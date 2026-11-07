#!/usr/bin/env python3
"""Measure partial device kernel capabilities without claiming qualification.

Only Chromium identity is a qualification probe implemented here. Cgroup and
namespace smoke checks are prerequisites, not production sandbox/egress evidence.
The runner never writes BROWSERD_VALIDATION_RECEIPT and never returns success.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import platform
import re
import resource
import select
import signal
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_profile_artifact import decode_json
from validation import GateError, KERNEL_PROBES, pinned_test_chromium, verify_artifact


CGROUP_ROOT = Path("/sys/fs/cgroup")
NAMESPACE_NAMES = ("user", "pid", "mnt", "net")
SMOKE_DESTINATION = "192.0.2.1:9"
IDENTITY_DIGEST_FIELDS = (
    "binary_digest", "browser_protocol_schema_digest", "js_protocol_schema_digest",
    "launch_profile_digest", "extension_bundle_digest", "font_bundle_digest",
    "certificate_runtime_bundle_digest",
)
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_FRAME_BYTES = 32768
LIMITS = {"cpu.max": "10000 100000", "memory.max": str(128 * 1024 * 1024),
          "memory.high": str(64 * 1024 * 1024), "pids.max": "16"}


class PrerequisiteError(ValueError):
    pass


class ProbeFailure(ValueError):
    def __init__(self, message: str, evidence: dict | None = None):
        super().__init__(message)
        self.evidence = evidence or {}


@dataclass(frozen=True)
class Binding:
    expected: dict
    log_dir: Path
    receipt: Path
    artifact: Path
    cgroup: Path
    environment: dict


def safe_path(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise PrerequisiteError("device paths must be absolute and contain no symlinks or traversal")


def control_read(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = os.read(descriptor, 4097)
        if len(data) > 4096:
            raise ProbeFailure("cgroup control exceeds its size bound")
        return data.decode().strip()
    finally:
        os.close(descriptor)


def control_write(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        data = value.encode()
        if os.write(descriptor, data) != len(data):
            raise ProbeFailure("short cgroup control write")
    finally:
        os.close(descriptor)


def process_cgroup(pid: int) -> Path:
    lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    unified = [line[3:] for line in lines if line.startswith("0::")]
    if len(unified) != 1 or not unified[0].startswith("/") or ".." in Path(unified[0]).parts:
        raise PrerequisiteError("process has no unambiguous cgroup v2 membership")
    return CGROUP_ROOT / unified[0].lstrip("/")


def self_cgroup() -> Path:
    return process_cgroup(os.getpid())


def check_delegation(root: Path) -> None:
    safe_path(root)
    current = self_cgroup()
    service = root.parent
    if (root.name != "workloads" or not root.is_relative_to(CGROUP_ROOT)
            or re.fullmatch(rf"browserd-validation-u{os.getuid()}-[0-9a-f]{{12}}\.service", service.name) is None
            or current.parent != service or current.name != "runs"):
        raise PrerequisiteError("partial runner must execute inside its dedicated validation service runs cgroup")
    if (not root.is_dir() or not os.access(root, os.W_OK)
            or os.statvfs(root).f_flag & os.ST_RDONLY
            or not {"cpu", "memory", "pids"} <= set(control_read(root / "cgroup.controllers").split())
            or not {"cpu", "memory", "pids"} <= set(control_read(root / "cgroup.subtree_control").split())):
        raise PrerequisiteError("dedicated workloads cgroup must delegate enabled cpu, memory and pids controllers")


def binding_from_environment(env: dict[str, str]) -> Binding:
    keys = ("run_id", "tier", "manifest_sha256", "kernel_release", "machine")
    expected = {key: env.get(f"BROWSERD_VALIDATION_{key.upper()}", "") for key in keys}
    try:
        parsed_run = uuid.UUID(expected["run_id"])
    except ValueError as error:
        raise PrerequisiteError("kernel runner requires a valid current run UUID") from error
    if (str(parsed_run) != expected["run_id"] or expected["tier"] != "kernel"
            or re.fullmatch(r"[0-9a-f]{64}", expected["manifest_sha256"]) is None
            or expected["manifest_sha256"] == "0" * 64
            or expected["kernel_release"] != platform.release() or expected["machine"] != platform.machine()
            or platform.system() != "Linux" or env.get("BROWSERD_TRUSTED_VALIDATION") != "1"):
        raise PrerequisiteError("kernel runner metadata must match the current Linux run and exact artifact")
    paths = {key: Path(env.get(key, "")) for key in (
        "BROWSERD_VALIDATION_LOG_DIR", "BROWSERD_VALIDATION_RECEIPT",
        "BROWSERD_CHROMIUM_ARTIFACT_ROOT", "BROWSERD_VALIDATION_CGROUP_ROOT")}
    for path in paths.values():
        safe_path(path)
    log_dir, receipt = paths["BROWSERD_VALIDATION_LOG_DIR"], paths["BROWSERD_VALIDATION_RECEIPT"]
    if (not log_dir.is_dir() or log_dir.stat().st_uid != os.getuid() or log_dir.stat().st_mode & 0o077
            or receipt.parent != log_dir or receipt.name != "receipt.json"
            or receipt.exists() or (log_dir / "partial-evidence.json").exists()):
        raise PrerequisiteError("runner requires an owned private run directory with no previous receipt or partial evidence")
    cgroup = paths["BROWSERD_VALIDATION_CGROUP_ROOT"]
    check_delegation(cgroup)
    return Binding(expected, log_dir, receipt, paths["BROWSERD_CHROMIUM_ARTIFACT_ROOT"], cgroup, dict(env))


def read_ready(process: subprocess.Popen, *, frame_limit=MAX_FRAME_BYTES, timeout=10) -> dict:
    deadline = time.monotonic() + timeout
    pending = bytearray()
    while b"\n" not in pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], max(0, remaining))[0]:
            raise ProbeFailure("owned probe process readiness timed out")
        block = os.read(process.stdout.fileno(), min(4096, frame_limit + 1 - len(pending)))
        if not block:
            raise ProbeFailure("owned probe exited before readiness")
        pending.extend(block)
        if len(pending) > frame_limit:
            raise ProbeFailure("owned probe readiness exceeds its size bound")
    result = decode_json(bytes(pending).split(b"\n", 1)[0])
    return result


def cgroup_mkdir(path: Path) -> None:
    path.mkdir(mode=0o700)


def cgroup_remove(path: Path) -> None:
    path.rmdir()


def spawn_attached(group: Path, diagnostics) -> subprocess.Popen:
    descriptor = os.open(group / "cgroup.procs", os.O_WRONLY | os.O_NOFOLLOW)
    def attach_before_exec():
        data = str(os.getpid()).encode()
        if os.write(descriptor, data) != len(data):
            raise OSError("short owned-process cgroup attach")
        os.close(descriptor)
    code = ("import json,os,time; allocation=bytearray(4*1024*1024); "
            "print(json.dumps({'pid':os.getpid(),'ready':True}),flush=True); time.sleep(30)")
    try:
        return subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=diagnostics, start_new_session=True,
                                preexec_fn=attach_before_exec, pass_fds=(descriptor,), umask=0o077)
    finally:
        os.close(descriptor)


def wait_empty(group: Path) -> dict:
    deadline = time.monotonic() + 5
    while True:
        events = dict(line.split(None, 1) for line in control_read(group / "cgroup.events").splitlines())
        if events.get("populated") == "0":
            if control_read(group / "cgroup.procs") or control_read(group / "pids.current") != "0":
                raise ProbeFailure("owned cgroup claims empty but retains processes")
            return events
        if time.monotonic() >= deadline:
            raise ProbeFailure("owned cgroup remains populated after kill")
        time.sleep(0.05)


def cgroup_smoke(root: Path, logs: Path) -> dict:
    group = root / f"kernel-smoke-{uuid.uuid4().hex}"
    evidence = {"status": "running", "cgroup": str(group), "limits": {}, "cleanup": {"removed": False}}
    created = False
    process = None
    failure = None
    try:
        cgroup_mkdir(group)
        created = True
        for name, requested in LIMITS.items():
            control_write(group / name, requested)
            observed = control_read(group / name)
            if observed != requested:
                raise ProbeFailure("owned cgroup resource control readback differs")
            evidence["limits"][name] = observed
        with (logs / "cgroup-child.stderr").open("xb") as diagnostics:
            os.chmod(diagnostics.name, 0o600)
            process = spawn_attached(group, diagnostics)
            evidence["process"] = {"pid": process.pid, "exit_code": None}
            ready = read_ready(process)
            if ready != {"pid": process.pid, "ready": True} or process_cgroup(process.pid) != group:
                raise ProbeFailure("owned process was not attached to the exact child cgroup before its code")
            evidence["observed"] = {"membership": str(group), "pids_current": int(control_read(group / "pids.current")),
                                    "memory_current": int(control_read(group / "memory.current"))}
            if evidence["observed"]["pids_current"] != 1 or evidence["observed"]["memory_current"] <= 0:
                raise ProbeFailure("owned cgroup counters do not account for its process")
    except BaseException as error:
        failure = error
    finally:
        if created:
            cleanup_error = None
            try:
                control_write(group / "cgroup.kill", "1")
                evidence["cleanup"]["cgroup_kill_written"] = True
            except BaseException as error:
                cleanup_error = error
            try:
                if process is not None:
                    if cleanup_error is not None:
                        process.kill()
                    evidence["process"]["exit_code"] = process.wait(timeout=5)
            except BaseException as error:
                cleanup_error = cleanup_error or error
                try:
                    process.kill()
                    evidence["process"]["exit_code"] = process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    evidence["cleanup"]["process_wait_failed"] = True
            try:
                evidence["cleanup"]["events"] = wait_empty(group)
                cgroup_remove(group)
                evidence["cleanup"]["removed"] = True
            except BaseException as error:
                cleanup_error = cleanup_error or error
            finally:
                if process is not None and process.stdout is not None:
                    process.stdout.close()
            if cleanup_error is not None:
                evidence["cleanup"]["error"] = f"owned cgroup cleanup failed ({type(cleanup_error).__name__})"
                failure = failure or cleanup_error
    if failure is not None:
        evidence["status"] = "failed"
        message = str(failure) if isinstance(failure, ProbeFailure) else f"owned cgroup probe failed ({type(failure).__name__})"
        raise ProbeFailure(message, evidence) from failure
    if evidence.get("process", {}).get("exit_code") != -signal.SIGKILL:
        evidence["status"] = "failed"
        raise ProbeFailure("cgroup.kill did not terminate the owned process with SIGKILL", evidence)
    evidence["status"] = "passed"
    return evidence


NAMESPACE_CODE = """import errno,json,os,socket,time
from pathlib import Path
namespaces={name:os.stat('/proc/self/ns/'+name).st_ino for name in ('user','pid','mnt','net')}
network={'destination':'192.0.2.1:9','connected':False}
connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connection.settimeout(0.25)
try:
 connection.connect(('192.0.2.1',9)); network['connected']=True; network['errno']=None
except OSError as error:
 network['errno']=error.errno
finally:
 connection.close()
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
print(json.dumps({'namespaces':namespaces,'network':network,'no_new_privileges':status.get('NoNewPrivs','').strip()=='1'}),flush=True)
"""


def validate_namespace_observation(parent: dict, observed: dict) -> None:
    child = observed.get("namespaces")
    network = observed.get("network")
    if (not isinstance(child, dict) or set(child) != set(NAMESPACE_NAMES)
            or any(type(child[name]) is not int or child[name] <= 0 or child[name] == parent[name] for name in NAMESPACE_NAMES)
            or observed.get("no_new_privileges") is not True or not isinstance(network, dict)
            or network.get("destination") != SMOKE_DESTINATION or network.get("connected") is not False
            or network.get("errno") not in {errno.ENETUNREACH, errno.EHOSTUNREACH}):
        raise ProbeFailure("isolated namespace smoke did not observe distinct namespaces and offline route refusal")


def stop_group(process: subprocess.Popen) -> int:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        code = process.wait(timeout=5)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return code


def namespace_smoke(logs: Path) -> dict:
    parent = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in NAMESPACE_NAMES}
    arguments = ["/usr/bin/bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-net",
                 "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                 "--", sys.executable, "-c", NAMESPACE_CODE]
    evidence = {"status": "running", "parent_namespaces": parent,
                "scope": "bwrap capability smoke only; production outer_sandbox/direct_egress_denial remain blocked"}
    def bounds():
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_EVIDENCE_BYTES, MAX_EVIDENCE_BYTES))
    process = None
    try:
        with (logs / "namespace.stderr").open("xb") as diagnostics:
            os.chmod(diagnostics.name, 0o600)
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=diagnostics,
                                       start_new_session=True, preexec_fn=bounds, umask=0o077)
            evidence["process"] = {"pid": process.pid, "exit_code": None}
            observed = read_ready(process)
            code = process.wait(timeout=5)
            evidence["process"]["exit_code"] = code
            if code != 0:
                raise ProbeFailure("bwrap namespace smoke exited nonzero")
            validate_namespace_observation(parent, observed)
            evidence["observed"] = observed
    except BaseException as error:
        evidence["status"] = "failed"
        if process is not None:
            try:
                evidence["process"]["exit_code"] = stop_group(process)
            except (OSError, subprocess.TimeoutExpired):
                evidence["cleanup_failed"] = True
        message = str(error) if isinstance(error, ProbeFailure) else f"namespace smoke failed ({type(error).__name__})"
        raise ProbeFailure(message, evidence) from error
    finally:
        if process is not None and process.stdout is not None:
            process.stdout.close()
    evidence["status"] = "passed"
    return evidence


def read_manifest(root: Path) -> dict:
    path = root / "compatibility.json"
    if path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ProbeFailure("Chromium manifest exceeds its size bound")
    return decode_json(path.read_bytes())


def normalized_product_version(product: str) -> str:
    if not isinstance(product, str) or len(product) > 1024 or any(ord(char) < 32 for char in product):
        raise ProbeFailure("invalid actual Chromium product observation")
    brand, separator, version = product.partition("/")
    if not separator or brand not in {"Chrome", "Chromium", "HeadlessChrome"} or not version or "/" in version:
        raise ProbeFailure("actual Chromium product does not match the production owner contract")
    return version


def read_browser_version(binary: Path, logs: Path) -> dict:
    result = {"process": {}}
    with tempfile.TemporaryDirectory(prefix="identity-private-", dir=logs) as temporary:
        work = Path(temporary)
        profile = work / "profile"
        profile.mkdir(mode=0o700)
        fixture = Path(__file__).with_name("chromium_pipe_fixture.py")
        process = subprocess.Popen([sys.executable, str(fixture), str(binary), str(profile), str(work / "targets.jsonl")],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True, umask=0o077)
        result["process"]["pid"] = process.pid
        try:
            process.stdin.write(b'{"id":1,"method":"Browser.getVersion"}\0')
            process.stdin.flush()
            deadline = time.monotonic() + 15
            pending = bytearray()
            version = None
            while version is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], max(0, remaining))[0]:
                    raise ProbeFailure("sandbox-enabled Chromium identity observation timed out")
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    raise ProbeFailure("sandbox-enabled Chromium exited during identity observation")
                pending.extend(data)
                if len(pending) > MAX_EVIDENCE_BYTES:
                    raise ProbeFailure("Chromium identity observation exceeds its size bound")
                while (end := pending.find(0)) >= 0:
                    frame = decode_json(bytes(pending[:end]))
                    del pending[:end + 1]
                    if frame.get("id") == 1:
                        if "error" in frame or not isinstance(frame.get("result"), dict):
                            raise ProbeFailure("Chromium rejected Browser.getVersion")
                        version = frame["result"]
                        break
            result["version"] = version
        except BaseException as error:
            message = str(error) if isinstance(error, ProbeFailure) else f"Chromium identity observation failed ({type(error).__name__})"
            raise ProbeFailure(message, result) from error
        finally:
            result["process"]["exit_code"] = stop_group(process)
            process.stdin.close()
            process.stdout.close()
    return result


def verify_chromium_identity(binding: Binding) -> dict:
    try:
        current = verify_artifact(binding.artifact)
        if current != binding.expected["manifest_sha256"]:
            raise ProbeFailure("Chromium manifest differs from this kernel run")
        manifest = read_manifest(binding.artifact)
        identity = manifest["identity"]
        if (any(not isinstance(identity.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", identity[key]) is None
                or identity[key] == "0" * 64 for key in IDENTITY_DIGEST_FIELDS)
                or any(not isinstance(identity.get(key), str) or not identity[key] for key in ("product_version", "chromium_revision"))):
            raise ProbeFailure("Chromium identity fields are incomplete")
        binary = Path(pinned_test_chromium(binding.artifact, binding.environment))
        observation = read_browser_version(binary, binding.log_dir)
        if (normalized_product_version(observation["version"].get("product")) != identity["product_version"]
                or observation["version"].get("revision") != identity["chromium_revision"]):
            raise ProbeFailure("actual Browser.getVersion differs from the pinned artifact identity", observation)
        if verify_artifact(binding.artifact) != current:
            raise ProbeFailure("Chromium artifact changed during identity observation", observation)
    except ProbeFailure:
        raise
    except (OSError, ValueError, KeyError, TypeError, GateError) as error:
        raise ProbeFailure("pinned Chromium identity verification failed") from error
    return {"status": "passed", "artifact_identity": identity, "binary": str(binary), **observation,
            "scope": "actual Browser.getVersion and verified file bytes; sandbox qualification remains blocked"}


def write_evidence(path: Path, evidence: dict) -> None:
    encoded = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ProbeFailure("partial device evidence exceeds its size bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def main(env: dict[str, str] | None = None) -> int:
    env = dict(os.environ) if env is None else env
    try:
        binding = binding_from_environment(env)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}))
        return 2
    path = binding.log_dir / "partial-evidence.json"
    evidence = {"schema_version": 1, **binding.expected, "status": "blocked",
                "qualification": "partial_device_capabilities", "artifact_status": "local_candidate",
                "operator_approval": False, "production_qualified": False,
                "started_at": datetime.now(timezone.utc).isoformat(), "runner_pid": os.getpid(),
                "validation_cgroup_root": str(binding.cgroup), "capability_smoke": {},
                "probes": {name: {"status": "blocked", "reason": "real production path probe is not implemented"} for name in KERNEL_PROBES}}
    code = 2
    stage = "chromium_identity"
    try:
        identity = verify_chromium_identity(binding)
        evidence["chromium_identity"] = identity
        evidence["probes"]["chromium_identity"] = {"status": "passed", "evidence": str(path)}
        stage = "cgroup"
        evidence["capability_smoke"][stage] = cgroup_smoke(binding.cgroup, binding.log_dir)
        stage = "namespace"
        evidence["capability_smoke"][stage] = namespace_smoke(binding.log_dir)
        evidence["reason"] = "device capability smoke completed; production kernel probes and operator approval remain absent"
    except PrerequisiteError as error:
        evidence["reason"] = str(error)
    except (ProbeFailure, OSError, ValueError, KeyboardInterrupt) as error:
        evidence.update(status="failed", reason=str(error) if isinstance(error, ProbeFailure) else f"actual device check failed ({type(error).__name__})")
        code = 1
        detail = error.evidence if isinstance(error, ProbeFailure) else {}
        if stage == "chromium_identity":
            evidence["chromium_identity"] = dict(detail, status="failed")
            evidence["probes"][stage] = {"status": "failed", "evidence": str(path)}
        else:
            evidence["capability_smoke"][stage] = dict(detail, status="failed")
    evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
    evidence["exit_code"] = code
    try:
        write_evidence(path, evidence)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "reason": f"could not write private partial evidence ({type(error).__name__})"}))
        return 1
    print(json.dumps({"status": evidence["status"], "partial_evidence": str(path), "exit_code": code}))
    return code


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda _signum, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    raise SystemExit(main())
