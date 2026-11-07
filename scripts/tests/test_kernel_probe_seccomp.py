"""Offline policy checks and real seccomp enforcement in disposable children."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "deploy/kernel-probe-seccomp.py"
spec = importlib.util.spec_from_file_location("kernel_probe_seccomp", SCRIPT)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def interpret(raw, constants, *, arch, number):
    """Independent bounded interpreter for the exact four emitted cBPF opcodes."""
    instructions = list(struct.iter_unpack("<HBBI", raw))
    accumulator = 0
    position = 0
    load = constants["BPF_LD"] | constants["BPF_W"] | constants["BPF_ABS"]
    equal = constants["BPF_JMP"] | constants["BPF_JEQ"] | constants["BPF_K"]
    bits = constants["BPF_JMP"] | constants["BPF_JSET"] | constants["BPF_K"]
    returned = constants["BPF_RET"] | constants["BPF_K"]
    for _ in range(len(instructions) + 1):
        code, yes, no, value = instructions[position]
        if code == load:
            if value == constants["seccomp_data_arch_offset"]:
                accumulator = arch
            elif value == constants["seccomp_data_nr_offset"]:
                accumulator = number & 0xFFFFFFFF
            else:
                raise AssertionError("unexpected seccomp data offset")
            position += 1
        elif code == equal:
            position += 1 + (yes if accumulator == value else no)
        elif code == bits:
            position += 1 + (yes if accumulator & value else no)
        elif code == returned:
            return value
        else:
            raise AssertionError("unexpected opcode")
        if not 0 <= position < len(instructions):
            raise AssertionError("out-of-bounds filter jump")
    raise AssertionError("filter does not terminate")


# Loading occurs only in this fresh child, never in the unittest runner. The
# ordinary getppid call is measured before loading so an ambient denial cannot
# be mistaken for evidence that our generated specialization worked.
ENFORCEMENT_CHILD = r'''
import ctypes, json, os, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]
settings = json.loads(sys.stdin.buffer.readline())
raw = bytes.fromhex(settings["raw"])
c = settings["constants"]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
baseline_ppid = libc.syscall(c["__NR_getppid"])
assert baseline_ppid == os.getppid() and baseline_ppid > 0
baseline_pid = libc.syscall(c["__NR_getpid"])
assert baseline_pid == os.getpid()
assert libc.prctl(c["PR_SET_NO_NEW_PRIVS"], 1, 0, 0, 0) == 0, ctypes.get_errno()
assert libc.prctl(c["PR_GET_NO_NEW_PRIVS"], 0, 0, 0, 0) == 1
filters = (Filter * (len(raw) // ctypes.sizeof(Filter))).from_buffer_copy(raw)
program = Program(len(filters), filters)
assert libc.syscall(c["__NR_seccomp"], c["SECCOMP_SET_MODE_FILTER"], 0,
                    ctypes.byref(program)) == 0, ctypes.get_errno()
if settings["mode"] == "x32":
    libc.syscall(c["__X32_SYSCALL_BIT"] | c["__NR_getpid"])
    raise AssertionError("x32 syscall survived the filter")
if settings["mode"] == "arch":
    libc.syscall(c["__NR_getpid"])
    raise AssertionError("mismatching architecture survived the filter")
ctypes.set_errno(0)
ppid = libc.syscall(c["__NR_getppid"])
if settings["mode"] == "deny_getppid":
    assert ppid == -1 and ctypes.get_errno() == c["EPERM"], (ppid, ctypes.get_errno())
else:
    assert ppid == baseline_ppid, (ppid, ctypes.get_errno())
assert libc.syscall(c["__NR_getpid"]) == baseline_pid
os.write(1, json.dumps({"baseline_ppid": baseline_ppid, "allowed_pid": baseline_pid,
                        "getppid": ppid, "nnp": 1, "installed": True}).encode() + b"\n")
'''


class SeccompPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.constants, cls.provenance = policy.load_linux_constants()
        cls.raw, cls.metadata = policy.build_policy(cls.constants, cls.provenance)

    def evaluate(self, name, **overrides):
        values = {"arch": self.constants["AUDIT_ARCH_X86_64"], "number": self.constants["__NR_" + name]}
        values.update(overrides)
        return interpret(self.raw, self.constants, **values)

    def run_child(self, raw, mode):
        payload = json.dumps({"raw": raw.hex(), "constants": self.constants, "mode": mode}) + "\n"
        return subprocess.run([sys.executable, "-I", "-c", ENFORCEMENT_CHILD], input=payload,
                              text=True, capture_output=True, timeout=10, check=False)

    def test_policy_digest_inventory_and_instruction_bound(self):
        self.assertEqual(self.metadata["sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(self.metadata["size"], len(self.raw))
        self.assertEqual(len(self.raw) % 8, 0)
        self.assertLessEqual(self.metadata["instruction_count"], policy.MAX_POLICY_INSTRUCTIONS)
        self.assertEqual(self.metadata["policy_name"], "browserd-kernel-probe-x86_64-v1")
        self.assertEqual(self.metadata["policy_version"], 1)
        self.assertEqual(self.metadata["denied_syscalls"],
                         [{"name": name, "number": self.constants["__NR_" + name]}
                          for name in policy.DENIED_SYSCALLS])
        self.assertTrue(self.metadata["isolated_validation"])
        self.assertFalse(self.metadata["production_qualified"])
        self.assertFalse(self.metadata["operator_approval"])

    def test_every_default_denylist_syscall_returns_eperm(self):
        expected = self.constants["SECCOMP_RET_ERRNO"] | self.constants["EPERM"]
        for name in policy.DENIED_SYSCALLS:
            with self.subTest(syscall=name):
                self.assertEqual(self.evaluate(name), expected)

    def test_native_chromium_sandbox_operations_remain_available(self):
        for name in (*policy.PRESERVED_SANDBOX_SYSCALLS, "getpid", "getppid"):
            with self.subTest(syscall=name):
                self.assertEqual(self.evaluate(name), self.constants["SECCOMP_RET_ALLOW"])

    def test_architecture_mismatch_is_killed_before_allow_or_deny_rules(self):
        for name in ("getpid", "bpf"):
            self.assertEqual(self.evaluate(name, arch=self.constants["AUDIT_ARCH_X86_64"] ^ 1),
                             self.constants["SECCOMP_RET_KILL_PROCESS"])

    def test_x32_abi_is_killed_even_for_otherwise_allowed_syscalls(self):
        for name in ("getpid", "getppid", "bpf"):
            number = self.constants["__NR_" + name] | self.constants["__X32_SYSCALL_BIT"]
            self.assertEqual(self.evaluate(name, number=number), self.constants["SECCOMP_RET_KILL_PROCESS"])

    def test_headers_and_evaluator_are_recorded_without_guessed_syscall_mapping(self):
        headers = self.provenance["installed_headers"]
        self.assertTrue(any(entry["path"].endswith("/asm/unistd_64.h") for entry in headers))
        self.assertTrue(any(entry["path"].endswith("/linux/seccomp.h") for entry in headers))
        for entry in headers:
            self.assertEqual(entry["sha256"], hashlib.sha256(Path(entry["path"]).read_bytes()).hexdigest())
        self.assertEqual(len(self.provenance["evaluator_source_sha256"]), 64)

    def test_unsupported_architecture_or_os_never_builds_a_fallback(self):
        for system, machine in (("Linux", "aarch64"), ("Linux", "i686"), ("Darwin", "x86_64")):
            with self.subTest(system=system, machine=machine), \
                 patch.object(policy.platform, "system", return_value=system), \
                 patch.object(policy.platform, "machine", return_value=machine), \
                 self.assertRaises(policy.PolicyError):
                policy.build_policy(self.constants, self.provenance)

    def test_missing_compiler_is_an_error(self):
        with patch.object(policy.shutil, "which", return_value=None), self.assertRaisesRegex(policy.PolicyError, "compiler"):
            policy.load_linux_constants()

    def test_empty_duplicate_unknown_and_unbounded_denylists_are_rejected(self):
        for names in ((), ("bpf", "bpf"), ("does_not_exist",), tuple(f"fake{i}" for i in range(49))):
            with self.subTest(names=names), self.assertRaises(policy.PolicyError):
                policy.compile_filter(self.constants, names)

    def test_wrong_sock_filter_layout_is_rejected(self):
        invalid = dict(self.constants, sock_filter_size=16)
        with self.assertRaisesRegex(policy.PolicyError, "layout"):
            policy.compile_filter(invalid, policy.DENIED_SYSCALLS)

    def test_private_output_is_exact_and_existing_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new-policy"
            policy.write_new_output(output, self.raw, self.metadata)
            self.assertEqual((output / "policy.bpf").read_bytes(), self.raw)
            self.assertEqual(json.loads((output / "policy.json").read_bytes()), self.metadata)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for name in ("policy.bpf", "policy.json"):
                self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                policy.write_new_output(output, b"replacement", {})
            self.assertEqual((output / "policy.bpf").read_bytes(), self.raw)

    def test_relative_dot_and_symlink_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for output in ("relative", str(root) + "/../unsafe", str(root) + "/./unsafe"):
                with self.subTest(output=output), self.assertRaises(policy.PolicyError):
                    policy.write_new_output(output, self.raw, self.metadata)
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                policy.write_new_output(link / "unsafe", self.raw, self.metadata)
            self.assertFalse((root / "unsafe").exists())

    def test_real_child_installs_default_filter_under_nnp_and_keeps_baseline_working(self):
        child = self.run_child(self.raw, "baseline")
        self.assertEqual(child.returncode, 0, child.stderr)
        evidence = json.loads(child.stdout)
        self.assertTrue(evidence["installed"])
        self.assertEqual(evidence["nnp"], 1)
        self.assertEqual(evidence["getppid"], evidence["baseline_ppid"])
        self.assertGreater(evidence["allowed_pid"], 0)

    def test_real_child_test_specialization_denies_previously_usable_getppid(self):
        specialized = policy.compile_filter(self.constants, (*policy.DENIED_SYSCALLS, "getppid"))
        child = self.run_child(specialized, "deny_getppid")
        self.assertEqual(child.returncode, 0, child.stderr)
        evidence = json.loads(child.stdout)
        self.assertEqual(evidence["getppid"], -1)
        self.assertGreater(evidence["baseline_ppid"], 0)
        self.assertGreater(evidence["allowed_pid"], 0)

    def test_real_child_x32_syscall_is_killed(self):
        child = self.run_child(self.raw, "x32")
        self.assertEqual(child.returncode, -signal.SIGSYS, child.stderr)

    def test_real_child_rejects_filter_with_mismatched_audit_architecture(self):
        mismatched = dict(self.constants, AUDIT_ARCH_X86_64=self.constants["AUDIT_ARCH_X86_64"] ^ 1)
        raw = policy.compile_filter(mismatched, policy.DENIED_SYSCALLS)
        child = self.run_child(raw, "arch")
        self.assertEqual(child.returncode, -signal.SIGSYS, child.stderr)


if __name__ == "__main__":
    unittest.main()
