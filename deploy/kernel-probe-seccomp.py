#!/usr/bin/env python3
"""Generate the versioned seccomp input for isolated browserd kernel probes.

This is an x86_64 cBPF denylist layered beneath Chromium's own sandbox, not a
qualified release policy or a complete syscall allowlist. Architecture changes
and the x32 ABI kill the process. The named privileged, inspection, keyring and
alternate asynchronous I/O syscalls return EPERM. Namespace setup syscalls stay
available so Chromium can install its native user/namespace/seccomp sandbox.

Every syscall number, audit architecture, BPF opcode and seccomp action comes
from the installed Linux headers through a compiled C helper. Unsupported hosts
or missing headers fail; there is no permissive fallback. This script never
installs a filter in its own process or starts deployment services.
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
import stat
import struct
import subprocess
import sys
import tempfile


POLICY_NAME = "browserd-kernel-probe-x86_64-v1"
POLICY_VERSION = 1
MAX_POLICY_INSTRUCTIONS = 128
MAX_HEADER_BYTES = 4 * 1024 * 1024
DENIED_SYSCALLS = (
    "bpf", "ptrace", "process_vm_readv", "process_vm_writev",
    "perf_event_open", "keyctl", "add_key", "request_key",
    "kexec_load", "kexec_file_load", "init_module", "finit_module",
    "delete_module", "reboot", "swapon", "swapoff", "open_by_handle_at",
    "userfaultfd", "io_uring_setup", "io_uring_enter", "io_uring_register",
)
PRESERVED_SANDBOX_SYSCALLS = (
    "unshare", "clone", "clone3", "setns", "chroot", "mount", "mount_setattr",
)
HEADER_EXPRESSIONS = {
    name: name for name in (
        "AUDIT_ARCH_X86_64", "__X32_SYSCALL_BIT", "BPF_LD", "BPF_W",
        "BPF_ABS", "BPF_JMP", "BPF_JEQ", "BPF_JSET", "BPF_K", "BPF_RET",
        "BPF_MAXINSNS", "SECCOMP_RET_KILL_PROCESS", "SECCOMP_RET_ERRNO",
        "SECCOMP_RET_ALLOW", "SECCOMP_RET_DATA", "SECCOMP_SET_MODE_FILTER",
        "PR_SET_NO_NEW_PRIVS", "PR_GET_NO_NEW_PRIVS", "EPERM",
    )
}
HEADER_EXPRESSIONS.update({
    "seccomp_data_nr_offset": "offsetof(struct seccomp_data, nr)",
    "seccomp_data_arch_offset": "offsetof(struct seccomp_data, arch)",
    "sock_filter_size": "sizeof(struct sock_filter)",
})
HEADER_EXPRESSIONS.update({
    "__NR_" + name: "__NR_" + name
    for name in (*DENIED_SYSCALLS, *PRESERVED_SANDBOX_SYSCALLS, "getppid", "getpid", "seccomp")
})


class PolicyError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def require_supported_host():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or sys.byteorder != "little":
        raise PolicyError("the isolated probe policy supports only native Linux x86_64")


def load_linux_constants():
    """Evaluate UAPI expressions with native headers; never guess syscall IDs."""
    require_supported_host()
    compiler = shutil.which("cc")
    if compiler is None:
        raise PolicyError("a native C compiler and installed Linux UAPI headers are required")
    source = (
        "#include <stddef.h>\n#include <stdio.h>\n#include <errno.h>\n"
        "#include <asm/unistd.h>\n#include <linux/audit.h>\n"
        "#include <linux/filter.h>\n#include <linux/seccomp.h>\n#include <linux/prctl.h>\n"
        "#if !defined(__x86_64__) || defined(__ILP32__)\n"
        '#error "native x86_64 compiler required"\n#endif\n'
        "int main(void) {\n"
        + "".join(f'printf("{name}=%llu\\n", (unsigned long long)({expression}));\n'
                  for name, expression in HEADER_EXPRESSIONS.items())
        + "return 0;\n}\n"
    ).encode()
    environment = dict(os.environ)
    # Header/compiler injection would make the reported Linux constants untrue.
    for name in (
        "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
        "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES", "COMPILER_PATH",
        "GCC_EXEC_PREFIX", "LD_PRELOAD", "LD_LIBRARY_PATH",
    ):
        environment.pop(name, None)
    # Test fixtures sometimes use a noexec TMPDIR. The native helper must run.
    with tempfile.TemporaryDirectory(prefix="browserd-seccomp-headers-", dir="/tmp") as temporary:
        directory = Path(temporary)
        source_path, helper, dependencies = (directory / name for name in ("constants.c", "constants", "headers.d"))
        source_path.write_bytes(source)
        source_path.chmod(0o600)
        built = subprocess.run(
            [compiler, "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-MD", "-MF",
             str(dependencies), str(source_path), "-o", str(helper)],
            capture_output=True, env=environment, timeout=30, check=False,
        )
        if built.returncode != 0:
            raise PolicyError("native Linux header evaluation failed: " + built.stderr.decode(errors="replace")[-2000:])
        evaluated = subprocess.run([str(helper)], capture_output=True, env=environment, timeout=5, check=False)
        if evaluated.returncode != 0:
            raise PolicyError("native Linux header evaluator failed")
        try:
            values = dict((name, int(value)) for name, value in
                          (line.split("=", 1) for line in evaluated.stdout.decode("ascii").splitlines()))
        except (ValueError, UnicodeError) as error:
            raise PolicyError("invalid Linux header evaluator output") from error
        if set(values) != set(HEADER_EXPRESSIONS):
            raise PolicyError("incomplete Linux header constants")
        dependency_text = dependencies.read_text().replace("\\\n", " ")
        header_paths = {Path(value).resolve() for value in shlex.split(dependency_text.split(":", 1)[1])
                        if value.endswith(".h")}
        if not 1 <= len(header_paths) <= 256:
            raise PolicyError("unbounded or empty installed header inventory")
        headers = []
        for path in sorted(header_paths):
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_HEADER_BYTES:
                raise PolicyError("invalid installed header input")
            headers.append({"path": str(path), "sha256": digest(path.read_bytes())})
    return values, {"evaluator_source_sha256": digest(source), "installed_headers": headers}


def compile_filter(constants, denied_syscalls):
    """Compile a bounded denylist; tests add getppid to prove kernel enforcement."""
    if constants["sock_filter_size"] != struct.calcsize("<HBBI"):
        raise PolicyError("unsupported native sock_filter layout")
    names = tuple(denied_syscalls)
    if not names or len(names) > 48 or len(set(names)) != len(names):
        raise PolicyError("denylist must be nonempty, unique and bounded")
    try:
        numbers = [constants["__NR_" + name] for name in names]
    except KeyError as error:
        raise PolicyError("denylist syscall missing from installed headers") from error
    if len(set(numbers)) != len(numbers) or any(not 0 <= number < constants["__X32_SYSCALL_BIT"] for number in numbers):
        raise PolicyError("invalid native syscall IDs")
    load = constants["BPF_LD"] | constants["BPF_W"] | constants["BPF_ABS"]
    equal = constants["BPF_JMP"] | constants["BPF_JEQ"] | constants["BPF_K"]
    bits = constants["BPF_JMP"] | constants["BPF_JSET"] | constants["BPF_K"]
    returned = constants["BPF_RET"] | constants["BPF_K"]
    denied = constants["SECCOMP_RET_ERRNO"] | (constants["EPERM"] & constants["SECCOMP_RET_DATA"])
    instructions = [
        (load, 0, 0, constants["seccomp_data_arch_offset"]),
        (equal, 1, 0, constants["AUDIT_ARCH_X86_64"]),
        (returned, 0, 0, constants["SECCOMP_RET_KILL_PROCESS"]),
        (load, 0, 0, constants["seccomp_data_nr_offset"]),
        (bits, 0, 1, constants["__X32_SYSCALL_BIT"]),
        (returned, 0, 0, constants["SECCOMP_RET_KILL_PROCESS"]),
    ]
    for number in numbers:
        instructions.extend(((equal, 0, 1, number), (returned, 0, 0, denied)))
    instructions.append((returned, 0, 0, constants["SECCOMP_RET_ALLOW"]))
    if len(instructions) > min(MAX_POLICY_INSTRUCTIONS, constants["BPF_MAXINSNS"]):
        raise PolicyError("seccomp instruction limit exceeded")
    return b"".join(struct.pack("<HBBI", *instruction) for instruction in instructions)


def build_policy(constants, provenance):
    require_supported_host()
    raw = compile_filter(constants, DENIED_SYSCALLS)
    metadata = {
        "schema_version": 1, "policy_name": POLICY_NAME, "policy_version": POLICY_VERSION,
        "architecture": "x86_64", "audit_architecture": constants["AUDIT_ARCH_X86_64"],
        "format": "linux-classic-bpf-sock_filter-little-endian",
        "sha256": digest(raw), "size": len(raw), "instruction_count": len(raw) // 8,
        "isolated_validation": True, "operator_approval": False, "production_qualified": False,
        "default_action": "allow", "denied_action": "errno", "denied_errno": constants["EPERM"],
        "architecture_mismatch_action": "kill_process", "x32_action": "kill_process",
        "denied_syscalls": [{"name": name, "number": constants["__NR_" + name]} for name in DENIED_SYSCALLS],
        "preserved_chromium_sandbox_syscalls": [
            {"name": name, "number": constants["__NR_" + name]} for name in PRESERVED_SANDBOX_SYSCALLS
        ],
        "limitations": [
            "A bounded isolated validation denylist, not a complete syscall allowlist.",
            "Chromium must additionally install its native sandbox inside the isolated namespaces.",
            "Raw socket, network, filesystem and resource isolation require the actual outer sandbox.",
            "io_uring entry points are denied to avoid bypassing synchronous syscall inspection.",
            "Generation does not prove runtime filter installation or release qualification.",
        ],
        "linux_header_constants": constants, "linux_header_provenance": provenance,
    }
    return raw, metadata


def write_new_output(directory, raw, metadata):
    """Publish private files into a new directory without traversing symlinks."""
    path = Path(directory)
    if not path.is_absolute() or str(path) != os.fspath(directory) or path == Path("/"):
        raise PolicyError("output directory must be a canonical absolute path")
    if any(part in {"", ".", ".."} for part in os.fspath(directory).split("/")[1:]):
        raise PolicyError("unsafe output directory")
    handles = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    created = False
    output_fd = None
    identity = None
    try:
        for part in path.parts[1:-1]:
            handles.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handles[-1]))
        os.mkdir(path.name, mode=0o700, dir_fd=handles[-1])
        created = True
        output_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handles[-1])
        os.fchmod(output_fd, 0o700)
        own = os.fstat(output_fd)
        identity = own.st_dev, own.st_ino
        for name, data in (("policy.bpf", raw), ("policy.json", encode_json(metadata))):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=output_fd)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(output_fd)
        current = os.stat(path.name, dir_fd=handles[-1], follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            raise PolicyError("output directory changed during publication")
        os.fsync(handles[-1])
    except BaseException:
        if created and output_fd is not None:
            for name in ("policy.bpf", "policy.json"):
                try:
                    os.unlink(name, dir_fd=output_fd)
                except FileNotFoundError:
                    pass
            current = os.stat(path.name, dir_fd=handles[-1], follow_symlinks=False)
            if (current.st_dev, current.st_ino) == identity:
                os.rmdir(path.name, dir_fd=handles[-1])
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)
        for descriptor in reversed(handles):
            os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, help="new absolute private output directory")
    arguments = parser.parse_args()
    try:
        constants, provenance = load_linux_constants()
        raw, metadata = build_policy(constants, provenance)
        write_new_output(arguments.output_dir, raw, metadata)
    except (OSError, PolicyError, subprocess.SubprocessError) as error:
        print(f"seccomp policy generation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "generated", "policy_path": str(Path(arguments.output_dir) / "policy.bpf"),
                      "metadata_path": str(Path(arguments.output_dir) / "policy.json"),
                      "sha256": metadata["sha256"], "production_qualified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
