"""Offline tests for owned capability probes and truthful partial qualification."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / "device_kernel_runner.py"
spec = importlib.util.spec_from_file_location("device_kernel_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


class PartialRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir(mode=0o700)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        self.receipt = self.logs / "receipt.json"
        self.cgroup = Path(f"/sys/fs/cgroup/system.slice/browserd-validation-u{os.getuid()}-8ee989ac7aba.service/workloads")
        self.expected = {"run_id": str(uuid.uuid4()), "tier": "kernel", "manifest_sha256": "a" * 64,
                         "kernel_release": platform.release(), "machine": platform.machine()}
        self.env = {f"BROWSERD_VALIDATION_{key.upper()}": value for key, value in self.expected.items()}
        self.env.update(BROWSERD_VALIDATION_LOG_DIR=str(self.logs), BROWSERD_VALIDATION_RECEIPT=str(self.receipt),
                        BROWSERD_VALIDATION_CGROUP_ROOT=str(self.cgroup), BROWSERD_CHROMIUM_ARTIFACT_ROOT=str(self.artifact),
                        BROWSERD_TRUSTED_VALIDATION="1")
        self.binding = runner.Binding(self.expected, self.logs, self.receipt, self.artifact, self.cgroup, self.env)

    def test_actual_partial_success_never_writes_passing_receipt_or_returns_zero(self):
        with patch.object(runner, "binding_from_environment", return_value=self.binding), \
             patch.object(runner, "verify_chromium_identity", return_value={"status": "passed", "version": {"product": "actual"}}), \
             patch.object(runner, "cgroup_smoke", return_value={"status": "passed", "process": {"pid": 234, "exit_code": -9}}), \
             patch.object(runner, "namespace_smoke", return_value={"status": "passed", "process": {"pid": 235, "exit_code": 0}}):
            self.assertEqual(runner.main(self.env), 2)
        self.assertFalse(self.receipt.exists())
        evidence = json.loads((self.logs / "partial-evidence.json").read_text())
        for key, value in self.expected.items():
            self.assertEqual(evidence[key], value)
        self.assertEqual(evidence["status"], "blocked")
        self.assertEqual(evidence["qualification"], "partial_device_capabilities")
        self.assertFalse(evidence["operator_approval"])
        self.assertFalse(evidence["production_qualified"])
        self.assertEqual(set(evidence["probes"]), set(runner.KERNEL_PROBES))
        self.assertEqual(evidence["probes"]["chromium_identity"]["status"], "passed")
        self.assertTrue(all(probe["status"] == "blocked" for name, probe in evidence["probes"].items() if name != "chromium_identity"))
        self.assertEqual((self.logs / "partial-evidence.json").stat().st_mode & 0o777, 0o600)

    def test_failed_actual_probe_keeps_cleanup_evidence_and_nonzero_status(self):
        failure = runner.ProbeFailure("wrong cgroup membership", {"process": {"pid": 234, "exit_code": -9},
                                                                  "cleanup": {"removed": True}})
        with patch.object(runner, "binding_from_environment", return_value=self.binding), \
             patch.object(runner, "verify_chromium_identity", return_value={"status": "passed"}), \
             patch.object(runner, "cgroup_smoke", side_effect=failure), \
             patch.object(runner, "namespace_smoke") as namespace:
            self.assertEqual(runner.main(self.env), 1)
        namespace.assert_not_called()
        evidence = json.loads((self.logs / "partial-evidence.json").read_text())
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(evidence["capability_smoke"]["cgroup"]["cleanup"], {"removed": True})
        self.assertFalse(self.receipt.exists())

    def test_invalid_metadata_blocks_before_any_probes_or_artifact_reads(self):
        for key, value in [("BROWSERD_VALIDATION_RUN_ID", "../invalid"),
                           ("BROWSERD_VALIDATION_TIER", "soak"),
                           ("BROWSERD_VALIDATION_MANIFEST_SHA256", "0" * 64),
                           ("BROWSERD_VALIDATION_KERNEL_RELEASE", "another-kernel"),
                           ("BROWSERD_VALIDATION_MACHINE", "another-machine")]:
            with self.subTest(key=key):
                env = dict(self.env, **{key: value})
                with patch.object(runner, "verify_chromium_identity") as identity:
                    self.assertEqual(runner.main(env), 2)
                identity.assert_not_called()
        self.assertFalse((self.logs / "partial-evidence.json").exists())
        self.assertFalse(self.receipt.exists())

    def test_existing_receipt_is_never_replaced(self):
        self.receipt.write_bytes(b"keep existing evidence")
        self.assertEqual(runner.main(self.env), 2)
        self.assertEqual(self.receipt.read_bytes(), b"keep existing evidence")

    def test_unprivate_or_symlink_evidence_directory_is_rejected(self):
        self.logs.chmod(0o755)
        self.assertEqual(runner.main(self.env), 2)
        self.logs.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.logs)
        self.assertEqual(runner.main(dict(self.env, BROWSERD_VALIDATION_LOG_DIR=str(alias))), 2)
        self.assertFalse((self.logs / "partial-evidence.json").exists())

    def test_delegation_requires_same_dedicated_service_and_enabled_controllers(self):
        with patch.object(runner, "self_cgroup", return_value=Path("/sys/fs/cgroup/unrelated.service/runs")):
            with self.assertRaises(runner.PrerequisiteError):
                runner.check_delegation(self.cgroup)
        expected = self.cgroup.parent / "runs"
        with patch.object(runner, "self_cgroup", return_value=expected), \
             patch.object(runner, "control_read", side_effect=lambda path: "cpu memory pids"), \
             patch.object(runner.os, "access", return_value=True), \
             patch.object(runner.Path, "is_dir", return_value=True), \
             patch.object(runner.Path, "is_symlink", return_value=False), \
             patch.object(runner.os, "statvfs", return_value=Mock(f_flag=0)):
            runner.check_delegation(self.cgroup)
        with patch.object(runner, "self_cgroup", return_value=expected), \
             patch.object(runner, "control_read", return_value="cpu memory"), \
             patch.object(runner.os, "access", return_value=True), \
             patch.object(runner.Path, "is_dir", return_value=True), \
             patch.object(runner.Path, "is_symlink", return_value=False), \
             patch.object(runner.os, "statvfs", return_value=Mock(f_flag=0)):
            with self.assertRaises(runner.PrerequisiteError):
                runner.check_delegation(self.cgroup)

    def cgroup_patches(self, membership_ok=True):
        self.writes, self.created, self.removed = [], [], []
        process = Mock(pid=234, returncode=None)
        process.wait.side_effect = lambda timeout=None: -9
        def write(path, value):
            self.writes.append((path, value))
        def read(path):
            killed = any(item.name == "cgroup.kill" for item, _ in self.writes)
            if path.name == "cgroup.events":
                return f"populated {0 if killed else 1}\nfrozen 0\n"
            if path.name == "pids.current":
                return "0" if killed else "1"
            if path.name == "memory.current":
                return "12345678"
            if path.name == "cgroup.procs":
                return "" if killed else "234\n"
            return next(value for item, value in reversed(self.writes) if item == path)
        def create(path):
            self.created.append(path)
        return process, [patch.object(runner, "control_write", side_effect=write),
                         patch.object(runner, "control_read", side_effect=read),
                         patch.object(runner, "cgroup_mkdir", side_effect=create),
                         patch.object(runner, "cgroup_remove", side_effect=lambda path: self.removed.append(path)),
                         patch.object(runner, "spawn_attached", return_value=process),
                         patch.object(runner, "read_ready", return_value={"pid": 234, "ready": True}),
                         patch.object(runner, "process_cgroup", side_effect=lambda pid: self.created[0] if membership_ok else self.cgroup)]

    def test_cgroup_smoke_kills_and_removes_exact_owned_child_only(self):
        process, patches = self.cgroup_patches()
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            evidence = runner.cgroup_smoke(self.cgroup, self.logs)
        owned = self.created[0]
        self.assertEqual(owned.parent, self.cgroup)
        self.assertEqual(self.removed, [owned])
        self.assertEqual([path for path, value in self.writes if path.name == "cgroup.kill"], [owned / "cgroup.kill"])
        self.assertTrue(all(path.parent == owned for path, value in self.writes))
        self.assertEqual(evidence["process"], {"pid": 234, "exit_code": -9})
        self.assertTrue(evidence["cleanup"]["removed"])
        self.assertEqual(set(evidence["limits"]), {"cpu.max", "memory.max", "memory.high", "pids.max"})

    def test_owned_process_attachment_is_a_preexec_step_bound_to_opened_control(self):
        sequence = []
        child = Mock(pid=234)
        def spawn(arguments, **options):
            self.assertEqual(options["pass_fds"], (89,))
            self.assertTrue(options["start_new_session"])
            options["preexec_fn"]()
            sequence.append("exec owned code")
            return child
        def write(descriptor, data):
            sequence.append((descriptor, data))
            return len(data)
        with patch.object(runner.os, "open", return_value=89) as opened, \
             patch.object(runner.os, "getpid", return_value=234), \
             patch.object(runner.os, "write", side_effect=write), \
             patch.object(runner.os, "close"), \
             patch.object(runner.subprocess, "Popen", side_effect=spawn):
            self.assertIs(runner.spawn_attached(self.cgroup / "owned", None), child)
        self.assertEqual(opened.call_args.args[0], self.cgroup / "owned/cgroup.procs")
        self.assertEqual(sequence, [(89, b"234"), "exec owned code"])

    def test_wrong_membership_failure_still_kills_owned_cgroup_and_removes_it(self):
        process, patches = self.cgroup_patches(membership_ok=False)
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            with self.assertRaises(runner.ProbeFailure) as failure:
                runner.cgroup_smoke(self.cgroup, self.logs)
        self.assertEqual(self.removed, self.created)
        self.assertTrue(failure.exception.evidence["cleanup"]["removed"])
        self.assertEqual(failure.exception.evidence["process"]["exit_code"], -9)

    def test_cleanup_kill_failure_still_reaps_child_and_removes_empty_owned_group(self):
        process, patches = self.cgroup_patches()
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            def failed_kill(path, value):
                self.writes.append((path, value))
                if path.name == "cgroup.kill":
                    raise OSError("failed actual cgroup kill")
            with patch.object(runner, "control_write", side_effect=failed_kill):
                with self.assertRaises(runner.ProbeFailure) as failure:
                    runner.cgroup_smoke(self.cgroup, self.logs)
        process.kill.assert_called_once()
        self.assertEqual(self.removed, self.created)
        self.assertTrue(failure.exception.evidence["cleanup"]["removed"])
        self.assertIn("error", failure.exception.evidence["cleanup"])

    def test_product_version_matches_production_owner_brand_and_version_contract(self):
        for brand in ["Chrome", "Chromium", "HeadlessChrome"]:
            self.assertEqual(runner.normalized_product_version(brand + "/153.0.8010.12"), "153.0.8010.12")
        for product in ["153.0.8010.12", "AnotherBrowser/153.0", "HeadlessChrome/", "Chrome/153.0/extra"]:
            with self.subTest(product=product), self.assertRaises(runner.ProbeFailure):
                runner.normalized_product_version(product)

    def test_namespace_result_requires_changed_namespaces_and_route_refusal(self):
        parent = {name: value for value, name in enumerate(runner.NAMESPACE_NAMES, start=1)}
        child = {name: value + 100 for name, value in parent.items()}
        observed = {"namespaces": child, "no_new_privileges": True,
                    "network": {"connected": False, "errno": runner.errno.ENETUNREACH,
                                "destination": runner.SMOKE_DESTINATION}}
        runner.validate_namespace_observation(parent, observed)
        observed["namespaces"]["net"] = parent["net"]
        with self.assertRaises(runner.ProbeFailure):
            runner.validate_namespace_observation(parent, observed)
        observed["namespaces"]["net"] += 100
        observed["network"]["errno"] = runner.errno.ETIMEDOUT
        with self.assertRaises(runner.ProbeFailure):
            runner.validate_namespace_observation(parent, observed)

    def test_identity_mismatch_fails_without_promoting_version_to_qualification(self):
        manifest = {"identity": {"product_version": "153", "chromium_revision": "expected",
                                  "binary_digest": hashlib.sha256(b"binary").hexdigest()},
                    "files": [{"relative_path": "binary", "digest": hashlib.sha256(b"binary").hexdigest()}]}
        for key in runner.IDENTITY_DIGEST_FIELDS:
            manifest["identity"].setdefault(key, "b" * 64)
        (self.artifact / "compatibility.json").write_text(json.dumps(manifest))
        (self.artifact / "binary").write_bytes(b"binary")
        with patch.object(runner, "verify_artifact", return_value=self.expected["manifest_sha256"]), \
             patch.object(runner, "pinned_test_chromium", return_value=str(self.artifact / "binary")), \
             patch.object(runner, "read_browser_version", return_value={"version": {"product": "HeadlessChrome/153", "revision": "wrong"},
                                                                        "process": {"pid": 333, "exit_code": -15}}), \
             patch.object(runner, "read_manifest", return_value=manifest):
            with self.assertRaises(runner.ProbeFailure):
                runner.verify_chromium_identity(self.binding)
        observed = {"version": {"product": "HeadlessChrome/153", "revision": "expected"},
                    "process": {"pid": 333, "exit_code": -15}}
        with patch.object(runner, "verify_artifact", return_value=self.expected["manifest_sha256"]) as verify, \
             patch.object(runner, "pinned_test_chromium", return_value=str(self.artifact / "binary")), \
             patch.object(runner, "read_browser_version", return_value=observed), \
             patch.object(runner, "read_manifest", return_value=manifest):
            evidence = runner.verify_chromium_identity(self.binding)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(evidence["version"]["product"], "HeadlessChrome/153")


if __name__ == "__main__":
    unittest.main()
