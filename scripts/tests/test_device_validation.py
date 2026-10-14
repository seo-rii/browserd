"""Device installation must preserve candidate provenance and fail closed."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "device_validation.py"
spec = importlib.util.spec_from_file_location("device_validation", SCRIPT)
device = importlib.util.module_from_spec(spec)
spec.loader.exec_module(device)


class DeviceInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "browserd"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/validation.py").write_text("# test fixture\n")
        self.artifact = self.root / "artifact with spaces"
        self.artifact.mkdir()
        (self.artifact / "locales").mkdir()
        files = {"chrome-headless-shell": b"executable", "icudtl.dat": b"icu", "locales/ko.pak": b"pak"}
        catalog = {"schema_version": 1, "icu_data": "icudtl.dat",
                   "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}],
                   "time_zones": ["UTC", "Asia/Seoul"]}
        files["native-process-profiles.json"] = json.dumps(catalog).encode()
        for name, data in files.items():
            (self.artifact / name).write_bytes(data)
        (self.artifact / "chrome-headless-shell").chmod(0o500)
        sha = lambda data: hashlib.sha256(data).hexdigest()
        manifest = {"identity": {"binary_digest": sha(files["chrome-headless-shell"]),
                                "launch_profile_digest": sha(files["native-process-profiles.json"])},
                    "files": [{"relative_path": name, "digest": sha(data)} for name, data in files.items()]}
        (self.artifact / "compatibility.json").write_text(json.dumps(manifest))
        (self.artifact / "provenance.json").write_text(json.dumps({
            "qualification": "local_candidate", "operator_approval": False,
        }))
        self.state = self.root / "state"

    def install(self):
        return device.install(self.state, self.repo, self.artifact)

    def test_install_binds_manifest_and_private_settings_without_granting_trust(self):
        settings = self.install()
        self.assertEqual(settings["artifact_status"], "local_candidate")
        self.assertEqual(settings["manifest_sha256"], hashlib.sha256(
            (self.artifact / "compatibility.json").read_bytes()).hexdigest())
        self.assertEqual((self.state.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((self.state / "device.json").stat().st_mode & 0o777), 0o600)
        env = device.environment(settings, {"BROWSERD_TRUSTED_VALIDATION": "1",
                                           "BROWSERD_KERNEL_RUNNER": "/bin/true",
                                           "BROWSERD_SOAK_RUNNER": "/bin/true",
                                           "BROWSERD_VALIDATION_CGROUP_ROOT": "/tmp/fake",
                                           "BROWSERD_KERNEL_PROBE_CONFIG": "/etc/browserd/kernel-probe-approval.json",
                                           "BROWSERD_KERNEL_PROBE_CONFIG_SHA256": "a" * 64})
        self.assertNotIn("BROWSERD_TRUSTED_VALIDATION", env)
        self.assertNotIn("BROWSERD_KERNEL_RUNNER", env)
        self.assertNotIn("BROWSERD_SOAK_RUNNER", env)
        self.assertNotIn("BROWSERD_VALIDATION_CGROUP_ROOT", env)
        self.assertNotIn("BROWSERD_KERNEL_PROBE_CONFIG", env)
        self.assertNotIn("BROWSERD_KERNEL_PROBE_CONFIG_SHA256", env)
        self.assertEqual(env["BROWSERD_CHROMIUM_ARTIFACT_ROOT"], str(self.artifact))
        self.assertEqual(env["BROWSERD_TEST_CHROMIUM"], str(self.artifact / "chrome-headless-shell"))

    def test_candidate_cannot_silently_be_marked_approved(self):
        (self.artifact / "provenance.json").write_text(json.dumps({
            "qualification": "local_candidate", "operator_approval": True,
        }))
        with self.assertRaises(device.DeviceError):
            self.install()
        self.assertFalse((self.state / "device.json").exists())

    def test_installed_artifact_drift_is_rejected_before_execution(self):
        self.install()
        (self.artifact / "icudtl.dat").write_bytes(b"changed")
        with self.assertRaises(device.DeviceError):
            device.load(self.state)

    def test_manifest_replacement_cannot_rebind_existing_installation(self):
        self.install()
        path = self.artifact / "compatibility.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(device.DeviceError):
            device.load(self.state)

    def test_symlink_state_cannot_write_outside_owned_directory(self):
        outside = self.root / "unrelated"
        outside.mkdir()
        self.state.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(device.DeviceError):
            self.install()
        self.assertFalse((outside / "device.json").exists())

    def test_unrelated_settings_are_never_overwritten(self):
        self.state.mkdir(mode=0o700)
        path = self.state / "device.json"
        path.write_text('{"schema_version": 900, "other": true}\n')
        with self.assertRaises(device.DeviceError):
            self.install()
        self.assertIn('"other": true', path.read_text())

    def test_generated_env_handles_spaces_and_clears_qualification_variables(self):
        self.install()
        text = (self.state / "candidate.env").read_text()
        self.assertIn("unset BROWSERD_TRUSTED_VALIDATION", text)
        self.assertIn("artifact with spaces'", text)
        self.assertNotIn("export BROWSERD_TRUSTED_VALIDATION=1", text)
        self.assertIn("BROWSERD_KERNEL_PROBE_CONFIG BROWSERD_KERNEL_PROBE_CONFIG_SHA256", text)
        self.assertNotIn("export BROWSERD_KERNEL_PROBE_CONFIG", text)

    def live_host(self):
        settings = self.install()
        identity = hashlib.sha256((str(self.repo) + "\0" + str(self.state)).encode()).hexdigest()[:12]
        unit = f"browserd-validation-u{os.getuid()}-{identity}.service"
        root = Path("/sys/fs/cgroup/system.slice") / unit
        plan = {"schema_version": 1, "uid": os.getuid(), "repo": str(self.repo),
                "state_directory": str(self.state), "unit_name": unit,
                "unit_path": "/etc/systemd/system/" + unit,
                "socket_path": str(self.state / "control.sock")}
        device.write_private(self.state / "host-plan.json", json.dumps(plan))
        endpoint = socket.socket(socket.AF_UNIX)
        endpoint.bind(plan["socket_path"])
        os.chmod(plan["socket_path"], 0o600)
        self.addCleanup(endpoint.close)
        response = {"status": "ready", "uid": os.getuid(), "pid": 23456,
                    "unit_name": unit, "delegated_cgroup": str(root),
                    "validation_cgroup_root": str(root / "workloads"),
                    "controllers": ["cpu", "memory", "pids"],
                    "qualification": "unqualified"}
        return settings, response

    def host_doctor(self, settings, response):
        with patch.object(device, "query_host", return_value=response), \
                patch.object(device, "validate_host_runtime"), \
                patch.object(device.os, "access", return_value=False):
            return device.doctor(self.state, settings)

    def test_valid_host_delegation_does_not_claim_current_process_delegation(self):
        settings, response = self.live_host()
        report = self.host_doctor(settings, response)
        self.assertFalse(report["current_cgroup_delegated"])
        self.assertTrue(report["host_delegation"]["available"])
        self.assertTrue(report["host_delegation"]["validated"])
        self.assertEqual(report["host_delegation"]["validation_cgroup_root"], response["validation_cgroup_root"])
        self.assertFalse(any("bootstrap requires root" in item for item in report["blockers"]))
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report["operator_approval"])
        self.assertIn("deployment-specific kernel probe runner is not implemented", report["blockers"])

    def test_malformed_live_identity_paths_and_controllers_are_blocked(self):
        settings, response = self.live_host()
        changes = (
            {"uid": os.getuid() + 1}, {"uid": True}, {"pid": 0},
            {"unit_name": "code-server.service"},
            {"delegated_cgroup": "/sys/fs/cgroup"},
            {"validation_cgroup_root": "/tmp/fake/workloads"},
            {"validation_cgroup_root": response["delegated_cgroup"] + "/../workloads"},
            {"controllers": ["memory", "pids"]},
            {"controllers": "cpu memory pids"}, {"status": "not-ready"},
        )
        for change in changes:
            with self.subTest(change=change):
                report = self.host_doctor(settings, {**response, **change})
                self.assertFalse(report["host_delegation"]["available"])
                self.assertFalse(report["host_delegation"]["validated"])
                self.assertTrue(any("dedicated host delegation" in item for item in report["blockers"]))

    def test_host_plan_cannot_redirect_socket_or_unit_identity(self):
        settings, response = self.live_host()
        path = self.state / "host-plan.json"
        original = json.loads(path.read_text())
        for change in ({"socket_path": "/tmp/foreign.sock"}, {"uid": os.getuid() + 1},
                       {"unit_name": "foreign.service"}, {"repo": "/other/repo"},
                       {"state_directory": "/other/state"}):
            with self.subTest(change=change):
                device.write_private(path, json.dumps({**original, **change}))
                report = self.host_doctor(settings, response)
                self.assertFalse(report["host_delegation"]["available"])

    def test_missing_host_socket_is_safely_reported_as_unavailable(self):
        settings, _ = self.live_host()
        (self.state / "control.sock").unlink()
        with patch.object(device.os, "access", return_value=False):
            report = device.doctor(self.state, settings)
        self.assertFalse(report["host_delegation"]["available"])
        self.assertEqual(report["host_delegation"]["status"], "unavailable")
        self.assertTrue(any("dedicated host delegation" in item for item in report["blockers"]))

    def test_stopped_service_socket_is_safely_reported_as_unavailable(self):
        settings, _ = self.live_host()
        with patch.object(device, "query_host", side_effect=ConnectionRefusedError), \
                patch.object(device.os, "access", return_value=False):
            report = device.doctor(self.state, settings)
        self.assertFalse(report["host_delegation"]["available"])
        self.assertEqual(report["host_delegation"]["status"], "unavailable")

    def test_unowned_or_unwritable_cgroup_runtime_is_not_accepted(self):
        settings, response = self.live_host()
        with patch.object(device, "query_host", return_value=response), \
                patch.object(device, "validate_host_runtime", side_effect=device.DeviceError("cgroup ownership/write check failed")), \
                patch.object(device.os, "access", return_value=False):
            report = device.doctor(self.state, settings)
        self.assertFalse(report["host_delegation"]["available"])
        self.assertIn("ownership/write", report["host_delegation"]["error"])

    def test_public_host_metadata_or_socket_cannot_be_accepted(self):
        settings, response = self.live_host()
        for name in ("host-plan.json", "control.sock"):
            path = self.state / name
            os.chmod(path, 0o644)
            report = self.host_doctor(settings, response)
            self.assertFalse(report["host_delegation"]["available"])
            os.chmod(path, 0o600)

    def test_socket_client_rejects_a_server_with_another_uid(self):
        with patch.object(device.socket, "socket") as constructor:
            connection = constructor.return_value.__enter__.return_value
            connection.getsockopt.return_value = struct.pack("3i", 4321, os.getuid() + 1, 1003)
            with self.assertRaisesRegex(device.DeviceError, "uid"):
                device.query_host(self.state / "control.sock", os.getuid())
            connection.sendall.assert_not_called()

    def test_socket_client_binds_response_pid_to_server_credentials(self):
        with patch.object(device.socket, "socket") as constructor:
            connection = constructor.return_value.__enter__.return_value
            connection.getsockopt.return_value = struct.pack("3i", 4321, os.getuid(), 1003)
            connection.recv.return_value = json.dumps({"pid": 9999}).encode() + b"\n"
            with self.assertRaisesRegex(device.DeviceError, "pid"):
                device.query_host(self.state / "control.sock", os.getuid())

    def test_functional_runs_every_kernel_live_browser_proof(self):
        commands = []

        def execute(_name, planned, _log_dir, _env):
            commands.extend(planned)
            return self.root, {"status": "passed"}

        settings = {"repo": str(self.repo), "artifact_root": str(self.artifact),
                    "test_chromium": str(self.artifact / "chrome-headless-shell"), "manifest_sha256": "a" * 64}
        with patch.object(device, "execute", side_effect=execute), patch.object(device, "write_private"):
            self.assertEqual(device.functional(settings, self.root / "logs"), 0)

        def live(plan):
            suites, proofs = set(), set()
            for command in plan:
                argv = command.argv
                if argv[:5] != ("cargo", "test", "--locked", "-p", "browserd-worker") or "--ignored" not in argv:
                    continue
                suites |= {argv[index + 1] for index, part in enumerate(argv) if part == "--test"}
                proofs |= {argv[index + 1] for index, part in enumerate(argv) if part == "--lib"}
            return suites, proofs

        # device_validation imports the gate runner as the top-level validation module.
        kernel_suites, kernel_proofs = live(sys.modules["validation"].build_plan("kernel", SCRIPT.parents[1]))
        functional_suites, functional_proofs = live(commands)
        self.assertIn("live_chromium_shared_context", kernel_suites)
        self.assertIn("chromium_owner::approvals::live_tests::actual_owner_typed_approvals_bind_child_secret_files_and_blank_context", kernel_proofs)
        self.assertEqual(functional_suites, kernel_suites)
        self.assertEqual(functional_proofs, kernel_proofs)


if __name__ == "__main__":
    unittest.main()
