#!/usr/bin/env python3
"""Create one dedicated cgroup delegation; never qualify a runner or artifact.

Rendering needs no privilege. Applying must run from an ordinary root-capable
host shell, outside an environment which prevents elevation. The service keeps
NoNewPrivileges=yes and executes only the fixed validation entrypoint as the
requested non-root user. A socket starts verification inside the delegation:
moving a process from an unrelated, undelegated service would not be permitted.
"""

import argparse
import hashlib
import json
import os
import pathlib
import pwd
import re
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import time


class SetupError(ValueError):
    pass


ALLOWED_ENVIRONMENT = frozenset({
    "BROWSERD_CHROMIUM_ARTIFACT_ROOT", "BROWSERD_KERNEL_RUNNER",
    "BROWSERD_SOAK_RUNNER", "BROWSERD_TRUSTED_VALIDATION",
    "RUSTUP_TOOLCHAIN", "CARGO_BUILD_JOBS", "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL",
    "BROWSERD_KERNEL_PROBE_CONFIG", "BROWSERD_KERNEL_PROBE_CONFIG_SHA256",
})
MAX_REQUEST_BYTES = 65536


def absolute_path(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SetupError("paths must contain no control characters")
    path = pathlib.Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SetupError("paths must be absolute and contain no '..' components")
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise SetupError("symlink path components are not allowed")
    return path


def unit_quote(value, *, command=False):
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if command:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def make_plan(user, repo, state_dir):
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise SetupError("unknown user") from exc
    if account.pw_uid == 0:
        raise SetupError("the delegated service must use a non-root user")
    repository = absolute_path(repo)
    state = absolute_path(state_dir)
    home = absolute_path(account.pw_dir)
    if state == home or not state.is_relative_to(home):
        raise SetupError("state directory must be below the non-root user's home")
    if len(os.fsencode(str(state / "control.sock"))) >= 108:
        raise SetupError("state directory produces an overlong Unix socket path")
    for relative in ("deploy/setup-validation-host.py", "scripts/validation.py"):
        entrypoint = repository / relative
        absolute_path(str(entrypoint))
        if not entrypoint.is_file():
            raise SetupError("repository is missing " + relative)
    identity = hashlib.sha256((str(repository) + "\0" + str(state)).encode()).hexdigest()[:12]
    unit_name = f"browserd-validation-u{account.pw_uid}-{identity}.service"
    command = ["/usr/bin/python3", str(repository / "deploy/setup-validation-host.py"),
               "--user", account.pw_name, "--repo", str(repository), "--state-dir", str(state), "--hold"]
    content = (
        "# Managed only by browserd deploy/setup-validation-host.py\n"
        "[Unit]\nDescription=browserd dedicated validation delegation\n\n"
        "[Service]\nType=simple\n"
        f"User={account.pw_uid}\nGroup={account.pw_gid}\n"
        "ExecStart=" + " ".join(unit_quote(arg, command=True) for arg in command) + "\n"
        "Delegate=cpu memory pids\nNoNewPrivileges=yes\nUMask=0077\n"
        "KillMode=control-group\nTimeoutStopSec=30\nRestart=no\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    common = ["/usr/bin/python3", str(repository / "deploy/setup-validation-host.py"),
              "--user", account.pw_name, "--repo", str(repository), "--state-dir", str(state)]
    return {
        "schema_version": 1, "user": account.pw_name, "uid": account.pw_uid,
        "gid": account.pw_gid, "home": str(home), "repo": str(repository),
        "state_directory": str(state), "unit_name": unit_name,
        "unit_path": "/etc/systemd/system/" + unit_name, "unit_content": content,
        "socket_path": str(state / "control.sock"),
        "host_command": shlex.join(["sudo", *common, "--apply"]),
        "run_commands": {action: shlex.join([*common, "--run", action])
                         for action in ("diagnose", "kernel", "soak")},
        "qualification": "unqualified; no runner or trusted-validation flag is installed",
    }


def install_unit(path, content):
    """Create an exact unit once; refuse every conflicting existing file."""
    path = pathlib.Path(path)
    encoded = content.encode()
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        if path.is_symlink():
            raise SetupError("existing unit is a symlink")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as existing:
            if not stat.S_ISREG(os.fstat(existing.fileno()).st_mode):
                raise SetupError("existing unit is not a regular file")
            if existing.read(len(encoded) + 1) != encoded:
                raise SetupError("existing unit differs; it will not be overwritten")
        return False
    with os.fdopen(descriptor, "wb") as output:
        os.fchmod(output.fileno(), 0o644)
        output.write(encoded)
    return True


def private_state(state):
    state = absolute_path(str(state))
    os.umask(0o077)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = state.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise SetupError("state directory must be owned by the service user")
    if info.st_mode & 0o077:
        raise SetupError("state directory must have private 0700 permissions")
    return state


def apply(plan):
    if os.geteuid() != 0:
        raise SetupError("--apply requires root from a host shell; it does not attempt elevation")

    def drop_privileges():
        os.setgroups([])
        os.setgid(plan["gid"])
        os.setuid(plan["uid"])

    # State preparation runs after dropping privileges, so user-owned paths are
    # never writable targets for a privileged Python process.
    subprocess.run([
        "/usr/bin/python3", str(pathlib.Path(plan["repo"]) / "deploy/setup-validation-host.py"),
        "--state-dir", plan["state_directory"], "--prepare-state",
    ], preexec_fn=drop_privileges, check=True)
    created = install_unit(plan["unit_path"], plan["unit_content"])
    if created:
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
    subprocess.run(["/usr/bin/systemctl", "enable", "--now", plan["unit_name"]], check=True)
    return {"status": "installed", "unit_name": plan["unit_name"], "created": created,
            "diagnose_command": plan["run_commands"]["diagnose"]}


def cgroup_path(contents):
    lines = contents.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise SetupError("a unified cgroup v2 hierarchy is required")
    relative = pathlib.PurePosixPath(lines[0][3:])
    if relative == pathlib.PurePosixPath("/") or ".." in relative.parts:
        raise SetupError("refusing the cgroup root or an ambiguous cgroup path")
    return pathlib.Path("/sys/fs/cgroup") / str(relative).lstrip("/")


def initialize_delegation(plan):
    root = cgroup_path(pathlib.Path("/proc/self/cgroup").read_text())
    if root.name != plan["unit_name"] or root.stat().st_uid != os.geteuid():
        raise SetupError("holder must start in its dedicated, user-owned systemd delegation")
    controllers = set((root / "cgroup.controllers").read_text().split())
    if not {"cpu", "memory", "pids"}.issubset(controllers):
        raise SetupError("dedicated delegation must provide cpu, memory and pids")
    holder, runs, workloads = (root / name for name in ("holder", "runs", "workloads"))
    for child in (holder, runs, workloads):
        child.mkdir(exist_ok=True)
    # Empty the delegated root before enabling controllers (cgroup v2's
    # no-internal-process rule). Runs are separate from the empty workload root.
    (holder / "cgroup.procs").write_text(str(os.getpid()))
    (root / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    (workloads / "cgroup.subtree_control").write_text("+cpu +memory +pids")
    return root, runs, workloads


def validate_request(request):
    if not isinstance(request, dict) or set(request) - {"action", "environment"}:
        raise SetupError("request accepts only action and environment")
    action = request.get("action")
    if action not in ("diagnose", "kernel", "soak"):
        raise SetupError("only diagnose, kernel and soak are supported")
    environment = request.get("environment", {})
    if not isinstance(environment, dict) or set(environment) - ALLOWED_ENVIRONMENT:
        raise SetupError("unsupported validation environment")
    for value in environment.values():
        if not isinstance(value, str) or "\0" in value or len(value) > 16384:
            raise SetupError("invalid validation environment value")
    config_path = environment.get("BROWSERD_KERNEL_PROBE_CONFIG")
    config_digest = environment.get("BROWSERD_KERNEL_PROBE_CONFIG_SHA256")
    if (config_path is None) != (config_digest is None):
        raise SetupError("custom probe approval path and digest must both be supplied")
    if config_path is not None:
        absolute_path(config_path)
        if re.fullmatch(r"[0-9a-f]{64}", config_digest) is None or config_digest == "0" * 64:
            raise SetupError("invalid probe approval configuration digest")
    return action, environment


def validation_command(repo, action):
    if action not in ("kernel", "soak"):
        raise SetupError("only the kernel and soak validation tiers can be executed")
    return ["/usr/bin/python3", str(pathlib.Path(repo) / "scripts/validation.py"), action]


def write_json(path, value):
    temporary = path.with_name(path.name + ".tmp-" + str(os.getpid()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")
    os.replace(temporary, path)


def hold(plan):
    if os.geteuid() != plan["uid"] or os.geteuid() == 0:
        raise SetupError("holder must run as its configured non-root user")
    state = private_state(plan["state_directory"])
    root, runs, workloads = initialize_delegation(plan)
    address = state / "control.sock"
    if address.exists():
        info = address.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
            raise SetupError("refusing to replace an unexpected control socket path")
        address.unlink()
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop)
    service = socket.socket(socket.AF_UNIX)
    service.bind(str(address))
    os.chmod(address, 0o600)
    service.listen(4)
    service.settimeout(1)
    active = None
    last_job = None
    details = {"uid": os.geteuid(), "pid": os.getpid(), "unit_name": plan["unit_name"],
               "delegated_cgroup": str(root), "validation_cgroup_root": str(workloads),
               "qualification": "unqualified"}
    write_json(state / "host.json", details)
    try:
        while not stopping:
            if active is not None and active.poll() is not None:
                write_json(pathlib.Path(last_job["status_file"]), {"pid": active.pid, "exit_code": active.returncode})
                last_job["exit_code"] = active.returncode
                active = None
            try:
                connection, _ = service.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(5)
                try:
                    _pid, peer_uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if peer_uid != os.geteuid():
                        raise SetupError("control socket accepts only the service user")
                    raw = b""
                    while not raw.endswith(b"\n"):
                        chunk = connection.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(raw)))
                        if not chunk:
                            raise SetupError("incomplete request")
                        raw += chunk
                        if len(raw) > MAX_REQUEST_BYTES:
                            raise SetupError("request exceeds size limit")
                    action, supplied = validate_request(json.loads(raw))
                    if action == "diagnose":
                        response = {"status": "ready", **details, "last_job": last_job,
                                    "controllers": (workloads / "cgroup.controllers").read_text().split()}
                    else:
                        if active is not None:
                            raise SetupError("a validation job is already running")
                        logs = private_state(pathlib.Path(plan["home"]) / "logs")
                        stem = logs / ("browserd-host-" + action + "-" + str(time.time_ns()))
                        log = stem.with_suffix(".log")
                        status_file = stem.with_suffix(".status.json")
                        environment = {"HOME": plan["home"], "USER": plan["user"],
                                       "LOGNAME": plan["user"],
                                       "PATH": str(pathlib.Path(plan["home"]) / ".cargo/bin") + ":/usr/local/bin:/usr/bin:/bin",
                                       "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", **supplied,
                                       "BROWSERD_VALIDATION_CGROUP_ROOT": str(workloads)}

                        def enter_runs():
                            (runs / "cgroup.procs").write_text(str(os.getpid()))

                        descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(descriptor, "wb") as output:
                            active = subprocess.Popen(validation_command(plan["repo"], action),
                                cwd=plan["repo"], env=environment, stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=enter_runs)
                        last_job = {"status": "started", "action": action, "pid": active.pid,
                                    "log": str(log), "status_file": str(status_file),
                                    "validation_cgroup_root": str(workloads)}
                        response = last_job.copy()
                except (SetupError, ValueError, OSError, subprocess.SubprocessError) as exc:
                    response = {"status": "error", "error": str(exc)}
                connection.sendall(json.dumps(response).encode() + b"\n")
    finally:
        if active is not None:
            active.terminate()
            try:
                active.wait(timeout=25)
            except subprocess.TimeoutExpired:
                active.kill()
                active.wait()
            write_json(pathlib.Path(last_job["status_file"]), {"pid": active.pid, "exit_code": active.returncode})
        service.close()
        address.unlink(missing_ok=True)


def request_run(state_dir, action):
    state = private_state(state_dir)
    environment = {name: os.environ[name] for name in ALLOWED_ENVIRONMENT if name in os.environ}
    request = {"action": action, "environment": environment}
    validate_request(request)
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(str(state / "control.sock"))
        client.sendall(json.dumps(request).encode() + b"\n")
        response = b""
        while not response.endswith(b"\n"):
            chunk = client.recv(4096)
            if not chunk or len(response) + len(chunk) > MAX_REQUEST_BYTES:
                raise SetupError("invalid control response")
            response += chunk
    result = json.loads(response)
    if result.get("status") == "error":
        raise SetupError(result.get("error", "control request failed"))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user")
    parser.add_argument("--repo")
    parser.add_argument("--state-dir", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--render", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--run", choices=("diagnose", "kernel", "soak"))
    mode.add_argument("--hold", action="store_true", help=argparse.SUPPRESS)
    mode.add_argument("--prepare-state", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.prepare_state:
            if os.geteuid() == 0:
                raise SetupError("state preparation must run after dropping root privileges")
            private_state(args.state_dir)
            return 0
        if args.run:
            result = request_run(args.state_dir, args.run)
        else:
            if not args.user or not args.repo:
                raise SetupError("--user and --repo are required when rendering or applying")
            plan = make_plan(args.user, args.repo, args.state_dir)
            if args.hold:
                hold(plan)
                return 0
            result = apply(plan) if args.apply else plan
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (SetupError, OSError, subprocess.SubprocessError) as exc:
        print("browserd host setup: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
