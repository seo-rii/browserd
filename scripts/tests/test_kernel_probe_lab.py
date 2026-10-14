"""Offline isolation/admission tests; never launch a daemon or approve production."""
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import resource
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


lab = module("kernel_probe_lab", ROOT / "deploy/kernel-probe-lab.py")
entry = module("kernel_probe_lab_entry", ROOT / "deploy/kernel-probe-lab-entry.py")


class LabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.stage, self.output = self.directory / "stage", self.directory / "output"
        self.stage.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        for name in lab.ROLES.values():
            path = self.stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"offline executable fixture")
            path.chmod(0o555)
        self.filter = struct.pack("=HBBI", 0x06, 0, 0, 0x00050001)
        (self.stage / lab.ROLES["seccomp"]).chmod(0o600)
        (self.stage / lab.ROLES["seccomp"]).write_bytes(self.filter)
        (self.stage / "chromium").mkdir()
        (self.stage / "chromium/compatibility.json").write_bytes(b'{"offline_fixture":true}')
        (self.stage / "chromium/chromium").write_bytes(b"offline browser fixture")
        (self.stage / "chromium/chromium").chmod(0o555)
        (self.stage / "runtime/lib").mkdir(parents=True)
        (self.stage / "runtime/lib/library.so").write_bytes(b"offline library fixture")
        self.run_id = str(uuid.uuid4())
        self.workloads = "/sys/fs/cgroup/system.slice/browserd-validation-u1003-123456789abc.service/workloads"
        self.plan = {"schema_version": 1, "operator_approval": True, "isolated_validation": True,
            "validation_uid": 1003, "run_id": self.run_id, "image": "sha256:" + "a" * 64,
            "delegated_workloads": self.workloads, "lab_cgroup": self.workloads + "/lab-" + self.run_id,
            "public_ip": "93.184.216.34", "private_ip": "10.254.0.1", "artifact_root": "chromium",
            "chromium_binary": "chromium/chromium", "roles": dict(lab.ROLES),
            "manifest_sha256": hashlib.sha256((self.stage / "chromium/compatibility.json").read_bytes()).hexdigest(),
            "runtime_mounts": [{"source": "runtime/lib", "destination": "/usr/lib/x86_64-linux-gnu"}],
            "files": lab.inventory(self.stage),
            "source_binding": {"source_revision": "c" * 40, "source_dirty": True, "source_content_sha256": "b" * 64}}

    def test_publish_writes_private_synced_json_and_rejects_existing_paths(self):
        path = self.output / "offline-published.json"
        value = {"diagnostic": True, "qualification": False}
        with patch.object(entry.os, "fsync", wraps=os.fsync) as fsync:
            entry.publish(path, value, os.getuid())
        self.assertEqual(json.loads(path.read_text()), value)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.stat().st_uid, os.getuid())
        fsync.assert_called_once()
        before = path.read_bytes()
        with self.assertRaises(FileExistsError):
            entry.publish(path, {"overwrite": True})
        self.assertEqual(path.read_bytes(), before)
        alias = self.output / "offline-alias.json"
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            entry.publish(alias, {"overwrite": True})
        self.assertEqual(path.read_bytes(), before)

    @unittest.skipIf(os.getuid() == 0, "plan preparation requires a nonroot validation UID")
    def test_actual_cli_prepare_writes_private_plan_without_runtime_mutations(self):
        uid = os.getuid()
        workloads = f"/sys/fs/cgroup/system.slice/browserd-validation-u{uid}-123456789abc.service/workloads"
        arguments = ["--stage", str(self.stage), "--output", str(self.output),
            "--delegated-workloads", workloads, "--image", self.plan["image"], "--uid", str(uid),
            "--chromium-binary", "chromium/chromium", "--runtime-mount", "runtime/lib=/usr/lib/x86_64-linux-gnu",
            "--source-revision", "c" * 40, "--source-content-sha256", "b" * 64, "--source-dirty", "true",
            "--approve-isolated-measurement", "--preflight"]
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch.object(lab.os, "fsync", wraps=os.fsync) as fsync, \
             patch.object(lab, "create_lab_child", side_effect=AssertionError("offline CLI created a cgroup")), \
             patch.object(lab.subprocess, "call", side_effect=AssertionError("offline CLI launched Docker")):
            self.assertEqual(lab.main(arguments), 0)
        prepared = json.loads(stdout.getvalue())
        self.assertEqual(prepared["status"], "prepared")
        self.assertEqual(prepared["mode"], "preflight")
        self.assertEqual(prepared["docker_argv"][-1], "--preflight")
        path = self.output / "lab-plan.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.stat().st_uid, uid)
        plan = lab.read_json(path)
        self.assertEqual(plan["run_id"], prepared["run_id"])
        self.assertEqual(plan["files"], lab.inventory(self.stage))
        self.assertEqual(plan["source_binding"], self.plan["source_binding"])
        self.assertFalse(Path(plan["lab_cgroup"]).exists())
        self.assertNotIn("production_qualified", plan)
        fsync.assert_called_once()

    def test_pinned_plan_is_only_measurement_authorization(self):
        self.assertIs(lab.validate_plan(self.plan), self.plan)
        self.assertNotIn("production_qualified", json.dumps(self.plan))
        self.assertNotIn("probes", self.plan)

    def test_docker_mounts_are_only_stage_output_and_exact_fresh_cgroup(self):
        command = lab.docker_argv(self.plan, self.stage, self.output)
        mounts = [command[i + 1] for i, value in enumerate(command) if value == "--mount"]
        self.assertEqual(len(mounts), 3)
        self.assertIn(f"source={self.stage},target=/input,readonly", mounts[0])
        self.assertIn(f"source={self.output},target=/output", mounts[1])
        self.assertEqual(mounts[2], f"type=bind,source={self.plan['lab_cgroup']},target={self.plan['lab_cgroup']}")
        self.assertNotIn("--privileged", command)
        self.assertNotIn("--network=host", command)
        self.assertNotIn("--pid=host", command)
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges=true", command)
        self.assertIn("systempaths=unconfined", command)
        self.assertIn("NET_ADMIN", command)
        self.assertIn("--pull=never", command)
        self.assertEqual(command[-4:-1], [self.plan["image"], "/input/helpers/kernel-probe-lab-entry.py", "--plan"])
        self.assertEqual(command[-1], "/output/lab-plan.json")

    def test_public_canary_rejects_private_documentation_and_multicast(self):
        for public in ("127.0.0.1", "10.0.0.1", "192.0.2.1", "198.18.0.1", "100.64.0.1", "224.0.0.1", "::1"):
            with self.subTest(public=public), self.assertRaises(lab.LabError):
                lab.validate_ips(public, "10.254.0.1")
        for private in ("93.184.216.34", "127.0.0.1", "192.0.2.1"):
            with self.subTest(private=private), self.assertRaises(lab.LabError):
                lab.validate_ips("93.184.216.34", private)

    def test_rejects_root_uid_unpinned_image_or_absent_explicit_approval(self):
        for field, value in (("validation_uid", 0), ("validation_uid", True), ("image", "debian:latest"),
                             ("operator_approval", False), ("isolated_validation", False)):
            candidate = copy.deepcopy(self.plan)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(lab.LabError):
                lab.validate_plan(candidate)

    def test_cgroup_cannot_escape_its_own_fresh_delegation(self):
        for group in (self.workloads, self.workloads + "/lab-old", self.plan["lab_cgroup"] + "/nested", "/sys/fs/cgroup/foreign/lab-" + self.run_id):
            candidate = copy.deepcopy(self.plan)
            candidate["lab_cgroup"] = group
            with self.subTest(group=group), self.assertRaises(lab.LabError):
                lab.validate_plan(candidate)
        candidate = copy.deepcopy(self.plan)
        candidate["delegated_workloads"] = self.workloads.replace("u1003", "u1004")
        with self.assertRaises(lab.LabError):
            lab.validate_plan(candidate)

    def test_runtime_mounts_cannot_cover_browser_aliases_or_authority_paths(self):
        for destination in ("/browserd", "/browserd/launch-gate", "/browserd-chromium", "/browserd-chromium/chromium", "/proc", "/sys/fs/cgroup", "/output/state", "/dev"):
            candidate = copy.deepcopy(self.plan)
            candidate["runtime_mounts"][0]["destination"] = destination
            with self.subTest(destination=destination), self.assertRaises(lab.LabError):
                lab.validate_plan(candidate)
        candidate = copy.deepcopy(self.plan)
        candidate["runtime_mounts"].append(copy.deepcopy(candidate["runtime_mounts"][0]))
        with self.assertRaises(lab.LabError):
            lab.validate_plan(candidate)

    def test_exact_resource_parent_requires_the_same_immutable_chromium_alias(self):
        resources = self.stage / lab.CHROMIUM_RESOURCE_SOURCE
        resources.mkdir(parents=True)
        alias = resources / "chromium"
        alias.write_bytes((self.stage / self.plan["chromium_binary"]).read_bytes())
        alias.chmod(0o555)
        candidate = copy.deepcopy(self.plan)
        candidate["runtime_mounts"].append({"source": lab.CHROMIUM_RESOURCE_SOURCE,
            "destination": str(lab.CHROMIUM_SANDBOX_EXECUTABLE.parent)})
        candidate["files"] = lab.inventory(self.stage)
        self.assertIs(lab.validate_plan(candidate), candidate)
        alias.chmod(0o444)
        candidate["files"] = lab.inventory(self.stage)
        with self.assertRaisesRegex(lab.LabError, "exact approved executable"):
            lab.validate_plan(candidate)
        alias.chmod(0o600)
        alias.write_bytes(b"different Chromium executable")
        alias.chmod(0o555)
        candidate["files"] = lab.inventory(self.stage)
        with self.assertRaisesRegex(lab.LabError, "exact approved executable"):
            lab.validate_plan(candidate)

    def test_mandatory_initializer_cannot_be_missing_or_not_executable(self):
        for missing in (True, False):
            candidate = copy.deepcopy(self.plan)
            name = candidate["roles"]["safety_initializer"]
            if missing:
                candidate["files"] = [item for item in candidate["files"] if item["path"] != name]
            else:
                next(item for item in candidate["files"] if item["path"] == name)["mode"] = 0o444
            with self.assertRaises(lab.LabError):
                lab.validate_plan(candidate)

    def test_all_allow_and_malformed_seccomp_are_rejected(self):
        for raw in (b"", b"wrong", struct.pack("=HBBI", 0x06, 0, 0, 0x7FFF0000), b"x" * (4096 * 8 + 8)):
            with self.subTest(size=len(raw)), self.assertRaises(lab.LabError):
                lab.validate_filter(raw)
        lab.validate_filter(self.filter)

    def test_inventory_rejects_symlinks_hardlinks_and_special_files(self):
        target = self.stage / "symlink"
        target.symlink_to(self.stage / "chromium/chromium")
        with self.assertRaises(lab.LabError):
            lab.inventory(self.stage)
        target.unlink()
        os.link(self.stage / "chromium/chromium", target)
        with self.assertRaises(lab.LabError):
            lab.inventory(self.stage)
        target.unlink()
        os.mkfifo(target)
        with self.assertRaises(lab.LabError):
            lab.inventory(self.stage)

    def test_stage_byte_mutation_breaks_exact_inventory(self):
        (self.stage / "chromium/chromium").chmod(0o755)
        (self.stage / "chromium/chromium").write_bytes(b"different offline bytes")
        with patch.object(entry.os, "statvfs", return_value=Mock(f_flag=os.ST_RDONLY)):
            with self.assertRaisesRegex(entry.lab.LabError, "inventory"):
                entry.verify_stage(self.plan, self.stage)

    def test_stage_must_really_be_read_only(self):
        with patch.object(entry.os, "statvfs", return_value=Mock(f_flag=0)):
            with self.assertRaisesRegex(entry.lab.LabError, "read-only"):
                entry.verify_stage(self.plan, self.stage)

    def test_duplicate_json_and_source_metadata_spoof_are_rejected(self):
        path = self.directory / "plan.json"
        path.write_text('{"run_id": "first", "run_id": "second"}')
        with self.assertRaises(lab.LabError):
            lab.read_json(path)
        candidate = copy.deepcopy(self.plan)
        candidate["source_binding"]["source_dirty"] = "true"
        with self.assertRaises(lab.LabError):
            lab.validate_plan(candidate)

    def test_daemon_bindings_use_same_real_peer_identity_and_separate_pins(self):
        tokens = {"worker": "w" * 64, "supervisor": "s" * 64}
        base, egress, sandbox = entry.daemon_environment(self.plan, tokens, [])
        self.assertEqual(base["BROWSERD_REDIS_URL"], "redis://127.0.0.1:16379/0")
        self.assertEqual(egress["BROWSER_EGRESS_WORKER_TOKEN"], sandbox["BROWSERD_EGRESS_WORKER_TOKEN"])
        self.assertEqual(egress["BROWSER_EGRESS_SUPERVISOR_TOKEN"], sandbox["BROWSERD_EGRESS_SUPERVISOR_TOKEN"])
        self.assertEqual(egress["BROWSER_EGRESS_WORKER_EPOCH"], sandbox["BROWSERD_WORKER_EPOCH"])
        self.assertEqual(egress["BROWSER_EGRESS_EXPECTED_PEER_UID"], "1003")
        self.assertEqual(sandbox["BROWSERD_SANDBOX_EXPECTED_PEER_UID"], "1003")
        self.assertEqual(sandbox["BROWSERD_SANDBOX_RPC_MAX_FRAME_BYTES"], "1048576")
        self.assertGreaterEqual(int(egress["BROWSER_EGRESS_MAX_PLANS"]), 1000 + 64,
                                "retained terminal plans must cover the full lifecycle run and functional helpers")
        self.assertLessEqual(int(egress["BROWSER_EGRESS_MAX_PLANS"]), 4096,
                             "the isolated lifecycle run must retain a finite plan bound")
        self.assertNotIn("BROWSERD_SAFETY_STATE_FILE", base)
        self.assertNotIn("production_qualified", json.dumps([base, egress, sandbox]))

    def test_seccomp_fd_is_opened_after_uid_drop_without_shell_path_expansion(self):
        with patch.object(entry, "OUTPUT", self.output), patch.object(entry.os, "chown"), \
             patch.object(entry.subprocess, "Popen", return_value=Mock(pid=42)) as popen:
            processes = entry.Processes(1003)
            try:
                processes.start("sandbox", ["/opt/browserd/bin/browser-sandboxd"], {},
                                filter_path=Path('/opt/browserd/filter with $variables.bpf'))
                command = popen.call_args.args[0]
                self.assertEqual(command[:4], ["/bin/sh", "-c", 'exec 5< "$1"; shift; exec "$@"', "browserd-approved-seccomp"])
                self.assertEqual(command[4], '/opt/browserd/filter with $variables.bpf')
                self.assertEqual(stat.S_IMODE((self.output / "sandbox.log").stat().st_mode), 0o600)
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                self.assertIsNotNone(popen.call_args.kwargs["preexec_fn"])
            finally:
                for stream in processes.streams:
                    stream.close()

    def test_actual_child_nofile_limit_preserves_parent_and_refuses_insufficient_hard(self):
        original = resource.getrlimit(resource.RLIMIT_NOFILE)
        if original[1] != resource.RLIM_INFINITY and original[1] < 65536:
            self.skipTest("successful child case requires an inherited hard limit of at least 65536")
        script = '''
import importlib.util, json, os, pathlib, resource, subprocess, sys
spec = importlib.util.spec_from_file_location("lab_entry", sys.argv[1])
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
entry.OUTPUT = pathlib.Path(sys.argv[2])
hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1] if sys.argv[3] == "inherited" else int(sys.argv[3])
resource.setrlimit(resource.RLIMIT_NOFILE, (1024, hard))
before = resource.getrlimit(resource.RLIMIT_NOFILE)
# This already-unprivileged fixture cannot perform root-only setgroups/CAPBSET
# operations. Only that independent privilege-drop helper is substituted;
# Processes.start, its pre_exec resource setup, Popen and kernel limits are real.
entry.drop_privileges = lambda uid: None
processes = entry.Processes(os.getuid())
refused = False
code = None
try:
    child = processes.start("nofile-child", [sys.executable, "-c",
        "import json,resource; print(json.dumps(list(resource.getrlimit(resource.RLIMIT_NOFILE))))"], dict(os.environ))
    code = child.wait(timeout=10)
except subprocess.SubprocessError:
    refused = True
finally:
    cleanup = processes.stop()
log = (entry.OUTPUT / "nofile-child.log").read_text()
print(json.dumps({"before": before, "after": resource.getrlimit(resource.RLIMIT_NOFILE),
    "refused": refused, "child": json.loads(log) if log else None, "code": code, "cleanup": cleanup}))
'''
        for label, hard in (("sufficient", "inherited"), ("insufficient", "1024")):
            with self.subTest(label=label):
                output = self.directory / label
                output.mkdir(mode=0o700)
                result = subprocess.run([sys.executable, "-c", script, str(ROOT / "deploy/kernel-probe-lab-entry.py"),
                    str(output), hard], capture_output=True, text=True, check=True, timeout=15)
                observed = json.loads(result.stdout)
                self.assertEqual(observed["before"], observed["after"])
                self.assertEqual(observed["before"][0], 1024)
                self.assertTrue(observed["cleanup"])
                if label == "sufficient":
                    self.assertFalse(observed["refused"])
                    self.assertEqual(observed["code"], 0)
                    self.assertEqual(observed["child"], [65536, observed["before"][1]])
                else:
                    self.assertTrue(observed["refused"])
                    self.assertIsNone(observed["child"])
                    self.assertIsNone(observed["code"])
                self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE), original)

    def test_preflight_docker_flag_does_not_change_authorized_mounts(self):
        full = lab.docker_argv(self.plan, self.stage, self.output)
        diagnostic = lab.docker_argv(self.plan, self.stage, self.output, preflight=True)
        self.assertEqual(diagnostic, full + ["--preflight"])
        self.assertNotIn("receipt", json.dumps(diagnostic))

    def test_initializer_reason_matches_actual_native_cli_contract(self):
        native = (ROOT / "bins/browser-worker/src/bin/browserd-safety-initialize.rs").read_text()
        accepted = re.search(r'args\[5\] == "([^"]+)"', native)
        self.assertIsNotNone(accepted)
        self.assertEqual(entry.INITIALIZE_REASON, accepted[1])

    def test_cgroup_delegation_owns_required_read_only_proof_controls(self):
        directory = self.directory / "domain"
        directory.mkdir()
        for name in entry.CGROUP_CONTROL_FILES:
            (directory / name).write_text("domain\n" if name == "cgroup.type" else "")
        with patch.object(entry.os, "chown") as chown:
            entry.own_cgroup_controls(directory, 1003)
        changed = {call.args[0] for call in chown.call_args_list}
        self.assertEqual(changed, {directory, *(directory / name for name in entry.CGROUP_CONTROL_FILES)})
        self.assertIn(directory / "cgroup.controllers", changed)
        self.assertIn(directory / "cgroup.type", changed)
        self.assertTrue(all(call.args[1:] == (1003, 1003) for call in chown.call_args_list))
        (directory / "cgroup.type").write_text("domain threaded\n")
        with self.assertRaisesRegex(entry.lab.LabError, "domain"):
            entry.own_cgroup_controls(directory, 1003)

    def test_real_epoch_protocol_requires_exact_nonce_epoch_and_shape(self):
        nonce = str(uuid.uuid4())
        sandbox = {"status": "success", "value": {"result": "daemon_epoch_probe", "value": {"daemon_epoch": 1, "request_nonce": nonce}}}
        egress = {"protocol_version": 1, "nonce": nonce, "current_daemon_epoch": 1}
        entry.validate_epoch_response(sandbox, nonce, 1, sandbox=True)
        entry.validate_epoch_response(egress, nonce, 1, sandbox=False)
        for response in (dict(egress, nonce=str(uuid.uuid4())), dict(egress, current_daemon_epoch=2),
                         dict(egress, current_daemon_epoch=True), dict(egress, extra="injected")):
            with self.assertRaises(entry.lab.LabError):
                entry.validate_epoch_response(response, nonce, 1, sandbox=False)

    def test_scanner_database_metadata_requires_fresh_canonical_utc_date(self):
        now = datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        version = b"ClamAV 1.4.3/27800/Sun Oct 11 11:00:00 2026"
        self.assertEqual(entry.validate_scanner_version(version, now), hashlib.sha256(version).hexdigest())
        for raw in (b"ClamAV 1.4.3/27800/Sat Oct 10 10:00:00 2026",
                    b"ClamAV 1.4.3/27800/Sun Oct 11 13:00:00 2026", b"ClamAV 1.4.3/00001/Sun Oct 11 11:00:00 2026",
                    b"ClamAV 1.4.3/27800/Mon Oct 11 11:00:00 2026", b"offline fake scanner"):
            with self.subTest(raw=raw), self.assertRaises(entry.lab.LabError):
                entry.validate_scanner_version(raw, now)

    def test_diagnostic_cannot_be_promoted_to_production_receipt(self):
        # Response shapes here are offline parser fixtures, never written evidence.
        names = {"chromium_identity", "chromium_sandbox", "outer_sandbox", "context_create_dispose", "proxy_loopback",
            "direct_egress_denial", "target_pause_resume", "context_ownership", "emulation", "downloads", "pdf_streaming",
            "screencast_ack", "orphan_targets_zero", "worker_sigkill_cleanup", "cross_shard_isolation"}
        binding = {"run_id": self.run_id, "source_dirty": True}
        response = {"schema_version": 1, "binding": binding, "status": "preflight_completed", "diagnostic": True,
            "qualification": False, "cleanup_complete": True, "omitted_probes": ["start_stop_1000"],
            "observations": {name: {"status": "passed", "evidence": "offline fixture only"} for name in names}}
        self.assertEqual(entry.validate_diagnostic_response(response, binding, 0), "preflight_completed")
        for key, value in (("qualification", True), ("diagnostic", False), ("cleanup_complete", False),
                           ("omitted_probes", []), ("status", "passed"), ("binding", dict(binding, source_dirty=1))):
            changed = copy.deepcopy(response)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(entry.lab.LabError):
                entry.validate_diagnostic_response(changed, binding, 0)
        with self.assertRaises(entry.lab.LabError):
            entry.validate_diagnostic_response(response, binding, 2)
        changed = copy.deepcopy(response)
        changed["observations"]["start_stop_1000"] = {"status": "passed", "evidence": "offline"}
        with self.assertRaises(entry.lab.LabError):
            entry.validate_diagnostic_response(changed, binding, 0)
        changed = copy.deepcopy(response)
        changed["observations"]["downloads"] = {"status": "blocked", "reason": "fixture prerequisite missing"}
        with self.assertRaises(entry.lab.LabError):
            entry.validate_diagnostic_response(changed, binding, 0)
        changed["status"] = "blocked"
        self.assertEqual(entry.validate_diagnostic_response(changed, binding, 2), "blocked")


if __name__ == "__main__":
    unittest.main()
