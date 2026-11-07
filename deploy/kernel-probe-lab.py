#!/usr/bin/env python3
"""Prepare a pinned, isolated native kernel-probe container; never attest PASS.

The stage is copied into container-only executable tmpfs. The only writable host
mounts are a fresh private output directory and one fresh delegated cgroup child.
This script emits a reviewable Docker argv; --run is an explicit execution step.
A genuine native safety initializer and a supplied restrictive cBPF filter are
required. No production qualification flag or substitute service is generated.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import uuid

MAX_FILES = 4096
MAX_FILE_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 8 * 1024**3
CHROMIUM_SANDBOX_EXECUTABLE = Path("/browserd-chromium/chromium")
CHROMIUM_RESOURCE_SOURCE = "runtime/chromium-resources"
ROLES = {
    "probe": "bin/browserd-kernel-probe",
    "launch_gate": "bin/browserd-launch-gate",
    "sandbox_daemon": "bin/browser-sandboxd",
    "egress_daemon": "bin/browser-egressd",
    "safety_initializer": "bin/browserd-safety-initialize",
    "seccomp": "seccomp/filter.bpf",
}
PLAN_KEYS = {"schema_version", "operator_approval", "isolated_validation", "run_id", "validation_uid",
             "image", "delegated_workloads", "lab_cgroup", "public_ip", "private_ip", "artifact_root",
             "chromium_binary", "manifest_sha256", "roles", "runtime_mounts", "files", "source_binding"}


class LabError(ValueError):
    pass


def absolute(value):
    path = Path(value)
    if (not path.is_absolute() or str(path) != str(value) or path == Path("/")
            or any(part in {".", ".."} for part in path.parts)
            or any(c in str(value) for c in "\n\r\x00,")):
        raise LabError("unsafe absolute lab path")
    return path


def relative(value):
    if (not isinstance(value, str) or not value or "\\" in value
            or any(ord(c) < 32 for c in value) or any(p in {"", ".", ".."} for p in value.split("/"))
            or PurePosixPath(value).is_absolute()):
        raise LabError("unsafe staged relative path")
    return value


def digest(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None or value == "0" * 64:
        raise LabError("missing or invalid SHA256")
    return value


def canonical_uuid(value):
    try:
        parsed = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise LabError("invalid lab UUID") from error
    if not parsed.int or str(parsed) != value:
        raise LabError("lab UUID must be canonical and nonnil")
    return value


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise LabError("lab JSON is not a bounded regular file")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LabError("duplicate lab JSON field")
            result[key] = value
        return result
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(LabError("nonfinite lab JSON")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise LabError("invalid lab JSON") from error


def sha256_file(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_FILE_BYTES:
        raise LabError("staged input must be a nonempty bounded single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        identity = lambda m: (m.st_dev, m.st_ino, m.st_mode, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
        if identity(before) != identity(opened):
            raise LabError("staged input changed while opening")
        hasher = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            hasher.update(block)
        if identity(opened) != identity(os.fstat(descriptor)) or identity(opened) != identity(path.lstat()):
            raise LabError("staged input changed while hashing")
        return hasher.hexdigest(), opened.st_size
    finally:
        os.close(descriptor)


def inventory(stage):
    """Reject aliases, extra special files and writable assets before admission."""
    stage = absolute(stage)
    for ancestor in stage.parents:
        if ancestor.is_symlink():
            raise LabError("stage ancestor is symlinked")
    if stage.is_symlink() or not stage.is_dir():
        raise LabError("stage must be an actual directory")
    result, pending, total, entries = [], [stage], 0, 0
    while pending:
        directory = pending.pop()
        for item in sorted(directory.iterdir()):
            entries += 1
            if entries > MAX_FILES * 2:
                raise LabError("stage entry bound exceeded")
            metadata = item.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                if len(item.relative_to(stage).parts) > 32:
                    raise LabError("stage depth bound exceeded")
                pending.append(item)
            elif stat.S_ISREG(metadata.st_mode):
                sha, size = sha256_file(item)
                total += size
                if len(result) >= MAX_FILES or total > MAX_TOTAL_BYTES:
                    raise LabError("stage file/byte bound exceeded")
                path = relative(item.relative_to(stage).as_posix())
                result.append({"path": path, "sha256": sha, "size": size,
                               "mode": 0o555 if metadata.st_mode & 0o111 else 0o444})
            else:
                raise LabError("stage contains a symlink or special file")
    return sorted(result, key=lambda item: item["path"])


def validate_filter(raw):
    if not raw or len(raw) % 8 or len(raw) > 4096 * 8:
        raise LabError("supplied seccomp must be bounded raw cBPF")
    instructions = [struct.unpack("=HBBI", raw[offset:offset + 8]) for offset in range(0, len(raw), 8)]
    # An all-ALLOW placeholder is not an approved restrictive outer filter.
    if not any(code == 0x06 and (operand & 0xFFFF0000) in {0, 0x80000000, 0x00030000, 0x00050000}
               for code, _jt, _jf, operand in instructions):
        raise LabError("seccomp input contains no rejecting action")


def validate_ips(public_ip, private_ip):
    try:
        public, private = ipaddress.IPv4Address(public_ip), ipaddress.IPv4Address(private_ip)
    except ipaddress.AddressValueError as error:
        raise LabError("lab canaries require literal IPv4 addresses") from error
    reserved = [ipaddress.IPv4Network(net) for net in
                ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                 "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
                 "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]
    if not public.is_global or any(public in net for net in reserved):
        raise LabError("public canary must satisfy production public-IP policy")
    if not any(private in ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise LabError("private canary must use RFC1918 address space")
    return str(public), str(private)


def validate_plan(plan):
    if (not isinstance(plan, dict) or set(plan) != PLAN_KEYS or type(plan["schema_version"]) is not int or plan["schema_version"] != 1
            or plan["operator_approval"] is not True or plan["isolated_validation"] is not True):
        raise LabError("explicit isolated measurement authorization is required")
    canonical_uuid(plan["run_id"])
    if type(plan["validation_uid"]) is not int or not 1 <= plan["validation_uid"] < 2**31:
        raise LabError("validation UID must be nonroot")
    if not isinstance(plan["image"], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", plan["image"]) is None:
        raise LabError("Docker image must be pinned by local SHA256 ID")
    root, child = absolute(plan["delegated_workloads"]), absolute(plan["lab_cgroup"])
    if (root.name != "workloads" or not root.is_relative_to(Path("/sys/fs/cgroup"))
            or re.fullmatch(rf"browserd-validation-u{plan['validation_uid']}-[0-9a-f]{{12}}\.service", root.parent.name) is None
            or child.parent != root or child.name != "lab-" + plan["run_id"]):
        raise LabError("lab cgroup must be one exact fresh child of the existing validation delegation")
    validate_ips(plan["public_ip"], plan["private_ip"])
    digest(plan["manifest_sha256"])
    relative(plan["artifact_root"])
    relative(plan["chromium_binary"])
    if not PurePosixPath(plan["chromium_binary"]).is_relative_to(plan["artifact_root"]):
        raise LabError("Chromium binary escapes artifact tree")
    if plan["roles"] != ROLES:
        raise LabError("missing exact native lab executable/filter roles")
    files = plan["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise LabError("missing bounded stage inventory")
    known, total = {}, 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "mode", "size"}:
            raise LabError("invalid stage file record")
        name = relative(item["path"])
        if name in known or item["mode"] not in {0o444, 0o555} or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE_BYTES:
            raise LabError("duplicate or invalid stage file")
        digest(item["sha256"])
        total += item["size"]
        known[name] = item
    if total > MAX_TOTAL_BYTES:
        raise LabError("stage byte bound exceeded")
    for role, name in ROLES.items():
        if name not in known or (role != "seccomp" and known[name]["mode"] != 0o555):
            raise LabError("missing actual executable or approved filter: " + role)
    manifest = plan["artifact_root"] + "/compatibility.json"
    if manifest not in known or known[manifest]["sha256"] != plan["manifest_sha256"] or plan["chromium_binary"] not in known:
        raise LabError("artifact manifest/binary are not pinned")
    mounts, destinations = plan["runtime_mounts"], set()
    if not isinstance(mounts, list) or not mounts or len(mounts) > 64:
        raise LabError("runtime mounts are required")
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) != {"source", "destination"}:
            raise LabError("invalid runtime mount")
        source, destination = relative(mount["source"]), absolute(mount["destination"])
        chromium_resources = (str(source) == CHROMIUM_RESOURCE_SOURCE
                              and destination == CHROMIUM_SANDBOX_EXECUTABLE.parent)
        if (destination in destinations or any(destination.is_relative_to(parent) for parent in ("/proc", "/dev", "/tmp", "/profile", "/sys", "/output"))
                or any(destination.is_relative_to(alias) or alias.is_relative_to(destination)
                       for alias in (CHROMIUM_SANDBOX_EXECUTABLE, Path("/browserd/launch-gate"))
                       if not (chromium_resources and alias == CHROMIUM_SANDBOX_EXECUTABLE))):
            raise LabError("unsafe or overlapping runtime mount destination")
        if chromium_resources:
            alias = known.get(CHROMIUM_RESOURCE_SOURCE + "/chromium")
            if alias is None or alias["sha256"] != known[plan["chromium_binary"]]["sha256"] or alias["mode"] != 0o555:
                raise LabError("Chromium resource directory must contain the exact approved executable alias")
        destinations.add(destination)
        if not any(PurePosixPath(name).is_relative_to(source) and name != source for name in known):
            raise LabError("runtime mount has no complete staged files")
    binding = plan["source_binding"]
    if not isinstance(binding, dict) or set(binding) != {"source_revision", "source_dirty", "source_content_sha256"}:
        raise LabError("exact current source binding is required")
    if not isinstance(binding["source_revision"], str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", binding["source_revision"]) is None or set(binding["source_revision"]) == {"0"}:
        raise LabError("invalid source revision")
    if type(binding["source_dirty"]) is not bool:
        raise LabError("source dirty binding must be boolean")
    digest(binding["source_content_sha256"])
    return plan


def prepare_plan(*, stage, output, workloads, image, uid, public_ip, private_ip,
                 artifact_root, chromium_binary, mounts, source_binding, approved=False, run_id=None):
    if not approved:
        raise LabError("pass --approve-isolated-measurement for the explicitly authorized isolated run")
    stage, output, workloads = absolute(stage), absolute(output), absolute(workloads)
    if (stage == output or stage.is_relative_to(output) or output.is_relative_to(stage)
            or stage.is_symlink() or output.is_symlink()):
        raise LabError("stage and output must be separate actual paths")
    if stage.stat().st_uid != os.getuid() or stat.S_IMODE(stage.stat().st_mode) != 0o700:
        raise LabError("stage must be caller-owned mode0700")
    if not output.is_dir() or any(output.iterdir()) or output.stat().st_uid != uid or stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise LabError("output must be fresh, empty, validation-UID-owned mode0700")
    files = inventory(stage)
    public_ip, private_ip = validate_ips(public_ip, private_ip)
    manifest_path = stage / relative(artifact_root) / "compatibility.json"
    manifest_sha, _ = sha256_file(manifest_path)
    validate_filter((stage / ROLES["seccomp"]).read_bytes())
    run_id = canonical_uuid(run_id or str(uuid.uuid4()))
    plan = validate_plan({"schema_version": 1, "operator_approval": True, "isolated_validation": True,
        "run_id": run_id, "validation_uid": uid, "image": image,
        "delegated_workloads": str(workloads), "lab_cgroup": str(workloads / ("lab-" + run_id)),
        "public_ip": public_ip, "private_ip": private_ip, "artifact_root": artifact_root,
        "chromium_binary": chromium_binary, "manifest_sha256": manifest_sha, "roles": dict(ROLES),
        "runtime_mounts": mounts, "files": files, "source_binding": source_binding})
    if Path(plan["lab_cgroup"]).exists():
        raise LabError("lab cgroup must be fresh; do not reuse incarnation state")
    # Package only these implementation helpers into the private read-only stage.
    helper_directory = stage / "helpers"
    helper_directory.mkdir(mode=0o755, exist_ok=True)
    if helper_directory.is_symlink():
        raise LabError("helper stage directory is symlinked")
    for name in ("kernel-probe-lab.py", "kernel-probe-lab-entry.py"):
        destination = helper_directory / name
        if destination.exists() or destination.is_symlink():
            raise LabError("stage helpers must be fresh")
        shutil.copyfile(Path(__file__).with_name(name), destination, follow_symlinks=False)
        destination.chmod(0o555)
    script_directory = stage / "scripts"
    script_directory.mkdir(mode=0o755, exist_ok=True)
    if script_directory.is_symlink():
        raise LabError("script stage directory is symlinked")
    for name in ("production_kernel_runner.py", "device_kernel_runner.py", "device_validation.py",
                 "validation.py", "native_profile_artifact.py"):
        destination = script_directory / name
        if destination.exists() or destination.is_symlink():
            raise LabError("stage scripts must be fresh")
        shutil.copyfile(Path(__file__).resolve().parents[1] / "scripts" / name, destination, follow_symlinks=False)
        destination.chmod(0o444)
    plan["files"] = inventory(stage)
    return validate_plan(plan)


def docker_argv(plan, stage, output, *, preflight=False):
    validate_plan(plan)
    stage, output = absolute(stage), absolute(output)
    command = ["docker", "run", "--pull=never", "--name", "browserd-kernel-lab-" + plan["run_id"],
            "--read-only", "--cgroupns=host", "--security-opt", "no-new-privileges=true",
            "--security-opt", "apparmor=unconfined", "--security-opt", "seccomp=unconfined",
            "--security-opt", "systempaths=unconfined",
            "--cap-add", "NET_ADMIN", "--pids-limit", "4096", "--shm-size", "256m",
            "--mount", f"type=bind,source={stage},target=/input,readonly",
            "--mount", f"type=bind,source={output},target=/output",
            "--mount", f"type=bind,source={plan['lab_cgroup']},target={plan['lab_cgroup']}",
            "--tmpfs", "/opt/browserd:rw,exec,nosuid,nodev,size=8g,mode=0755",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777",
            "--entrypoint", "/usr/bin/python3", plan["image"], "/input/helpers/kernel-probe-lab-entry.py",
            "--plan", "/output/lab-plan.json"]
    if preflight:
        command.append("--preflight")
    return command


def create_lab_child(plan):
    """The sole host mutation: create the exact fresh child in an existing delegation."""
    root, child = Path(plan["delegated_workloads"]), Path(plan["lab_cgroup"])
    for name in ("cgroup.controllers", "cgroup.subtree_control"):
        if not {"cpu", "memory", "pids"} <= set((root / name).read_text().split()):
            raise LabError("existing workloads do not delegate all three required controllers")
    if any(parent.is_symlink() for parent in root.parents) or root.is_symlink():
        raise LabError("delegation contains symlinks")
    child.mkdir(mode=0o700)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--delegated-workloads", required=True)
    parser.add_argument("--image", required=True, help="local sha256 image ID; image must contain python3/ip/bwrap/redis/ClamAV")
    parser.add_argument("--uid", type=int, default=1003)
    parser.add_argument("--public-ip", default="93.184.216.34")
    parser.add_argument("--private-ip", default="10.254.0.1")
    parser.add_argument("--artifact-root", default="chromium")
    parser.add_argument("--chromium-binary", required=True)
    parser.add_argument("--runtime-mount", action="append", required=True, help="staged-relative-source=absolute-sandbox-destination")
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-content-sha256", required=True)
    parser.add_argument("--source-dirty", choices=("true", "false"), required=True)
    parser.add_argument("--approve-isolated-measurement", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--preflight", action="store_true", help="verify genuine services and 15 native diagnostic probes, excluding start_stop_1000; no qualification receipt")
    args = parser.parse_args(argv)
    try:
        mounts = []
        for value in args.runtime_mount:
            source, separator, destination = value.partition("=")
            if not separator:
                raise LabError("runtime mount must use source=destination")
            mounts.append({"source": source, "destination": destination})
        plan = prepare_plan(stage=args.stage, output=args.output, workloads=args.delegated_workloads,
            image=args.image, uid=args.uid, public_ip=args.public_ip, private_ip=args.private_ip,
            artifact_root=args.artifact_root, chromium_binary=args.chromium_binary, mounts=mounts,
            source_binding={"source_revision": args.source_revision, "source_dirty": args.source_dirty == "true",
                            "source_content_sha256": args.source_content_sha256}, approved=args.approve_isolated_measurement)
        plan_path = Path(args.output) / "lab-plan.json"
        with open(plan_path, "x", encoding="utf-8", opener=lambda path, flags: os.open(path, flags | os.O_NOFOLLOW, 0o600)) as stream:
            json.dump(plan, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        command = docker_argv(plan, args.stage, args.output, preflight=args.preflight)
        print(json.dumps({"status": "prepared", "run_id": plan["run_id"], "plan": str(plan_path), "docker_argv": command, "mode": "preflight" if args.preflight else "measurement"}))
        if not args.run:
            return 0
        create_lab_child(plan)
        return subprocess.call(command)
    except (OSError, LabError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error), "exit_code": 2}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
