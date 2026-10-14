"""Offline orchestration tests; fixtures never approve a deployment or run probes."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / "production_kernel_runner.py"
spec = importlib.util.spec_from_file_location("production_kernel_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


class ProductionRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir(mode=0o700)
        self.receipt = self.logs / "receipt.json"
        self.expected = {"run_id": str(uuid.uuid4()), "tier": "kernel", "manifest_sha256": "a" * 64,
                         "kernel_release": platform.release(), "machine": platform.machine()}
        self.binding = dict(self.expected, config_sha256="b" * 64, probe_executable_sha256="c" * 64)
        self.env = {f"BROWSERD_VALIDATION_{key.upper()}": value for key, value in self.expected.items()}
        self.env.update(BROWSERD_VALIDATION_LOG_DIR=str(self.logs), BROWSERD_VALIDATION_RECEIPT=str(self.receipt),
                        BROWSERD_VALIDATION_CGROUP_ROOT="/sys/fs/cgroup/fixture/workloads",
                        BROWSERD_CHROMIUM_ARTIFACT_ROOT=str(self.root / "artifact"), BROWSERD_TRUSTED_VALIDATION="1")
        self.approval = Mock(path=self.root / "operator config.json", config_sha256="b" * 64,
                             probe=types.SimpleNamespace(path=self.root / "probe with spaces", sha256="c" * 64))

    def response(self, binding=None, status="passed", cleanup=True):
        binding = self.binding if binding is None else binding
        probes = {}
        for name in runner.KERNEL_PROBES:
            if status == "passed":
                path = self.logs / (name + ".json")
                runner._publish(path, {"schema_version": 1, "binding": binding, "probe": name,
                                       "status": "passed", "observations": {"offline_fixture": True}})
                probes[name] = {"status": "passed", "evidence": str(path)}
            else:
                probes[name] = {"status": status, "reason": "offline fixture incomplete"}
        path = self.logs / "production-response.json"
        runner._publish(path, {"schema_version": 1, "binding": binding, "status": status,
                               "cleanup_complete": cleanup, "probes": probes})
        return path

    def configuration_fixture(self):
        """User-owned fake inputs; root metadata is mocked only in parser tests."""
        artifact = self.root / "artifact"
        artifact.mkdir()
        (artifact / "locales").mkdir()
        content = {"chromium": b"offline fake browser", "icudtl.dat": b"offline ICU",
                   "locales/ko.pak": b"offline locale"}
        catalog = {"schema_version": 1, "icu_data": "icudtl.dat", "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}],
                   "time_zones": ["UTC"]}
        content["native-process-profiles.json"] = json.dumps(catalog).encode()
        for name, value in content.items():
            (artifact / name).write_bytes(value)
        (artifact / "chromium").chmod(0o500)
        sha = lambda value: hashlib.sha256(value).hexdigest()
        manifest = {"identity": {"binary_digest": sha(content["chromium"]),
                                "launch_profile_digest": sha(content["native-process-profiles.json"])},
                    "files": [{"relative_path": name, "digest": sha(value)} for name, value in content.items()]}
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        manifest_digest = sha((artifact / "compatibility.json").read_bytes())
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "library.so").write_bytes(b"offline library")
        paths = {}
        assets = []
        for role in sorted(runner.REQUIRED_ROLES):
            if role == "chromium_binary":
                path = artifact / "chromium"
            else:
                path = self.root / (role + ".input")
                if role == "runtime_manifest":
                    path.write_text(json.dumps({"schema_version": 1, "mounts": [{"source": str(runtime), "destination": "/usr/lib",
                        "files": [{"relative_path": "library.so", "sha256": sha(b"offline library")}]}]}))
                else:
                    path.write_bytes(("offline " + role).encode())
                    path.chmod(0o500)
            paths[role] = str(path)
            assets.append({"path": str(path), "sha256": sha(path.read_bytes()), "role": role})
        probe = self.root / "probe.input"
        probe.write_bytes(b"offline fake probe")
        probe.chmod(0o500)
        deployment = {
            "sandbox": {"socket_path": "/run/browserd/sandbox.sock", "expected_server_uid": os.getuid(), "daemon_epoch": 1,
                        "worker_id": "validation-worker", "worker_epoch": 1, "cgroup_root": "/sys/fs/cgroup/browserd/workloads",
                        "runtime_root": "/var/lib/browserd/sandboxes", "journal_directory": "/var/lib/browserd/sandbox/journal"},
            "egress": {"control_url": "http://127.0.0.1:20130", "install_socket": "/run/browserd/egress.sock",
                       "expected_server_uid": os.getuid(), "daemon_epoch": 1, "worker_token": "w" * 32,
                       "supervisor_token": "s" * 32, "policy_profile": "validation", "policy_digest": "e" * 64},
            "runtime": {"redis_url": "redis://127.0.0.1:6379/0", "redis_prefix": "owned-validation", "safety_pin_path": "/var/lib/browserd/validation/safety"},
            "worker": {"state_root": "/var/lib/browserd/validation/worker", "max_session_count": 2},
            "fixtures": {"bind_address": "0.0.0.0:18080", "origin": "http://validation.example.com:18080",
                         "host_direct_address": "127.0.0.1:18081", "private_direct_address": "10.0.0.1:18082"},
            "assets": {**{field: paths[role] for role, field in runner.ROLE_FIELDS.items()},
                       "chromium_sandbox_executable": "/opt/browser/chromium", "launch_gate_sandbox_executable": "/opt/browser/launch-gate",
                       "read_only_mounts": [{"source": str(runtime), "destination": "/usr/lib"}]},
        }
        config = {"schema_version": 1, "operator_approval": True, "isolated_validation": True, "validation_uid": os.getuid(),
                  "manifest_sha256": manifest_digest, "artifact_root": str(artifact), "approved_assets": assets,
                  "probe_executable": {"path": str(probe), "sha256": sha(probe.read_bytes())}, "deployment": deployment}
        path = self.root / "approval.json"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        env = dict(self.env, BROWSERD_CHROMIUM_ARTIFACT_ROOT=str(artifact), BROWSERD_KERNEL_PROBE_CONFIG=str(path),
                   BROWSERD_KERNEL_PROBE_CONFIG_SHA256=sha(path.read_bytes()))
        return config, path, env, manifest_digest

    def rewrite_config(self, path, config, env):
        path.write_text(json.dumps(config))
        return dict(env, BROWSERD_KERNEL_PROBE_CONFIG_SHA256=hashlib.sha256(path.read_bytes()).hexdigest())

    def offline_run(self, engine=None, **kwargs):
        if engine is None:
            engine = lambda _approval, binding, _logs: (0, self.response(binding), 0)
        with patch.object(runner, "check_delegation"), \
             patch.object(runner, "load_configuration", return_value=self.approval), \
             patch.object(runner, "execute_engine", side_effect=engine), \
             patch.object(runner, "print"):
            return runner.main(dict(self.env, **kwargs))

    def test_only_complete_same_run_evidence_and_positive_cleanup_publish_private_receipt(self):
        self.assertEqual(self.offline_run(), 0)
        receipt = json.loads(self.receipt.read_text())
        for key, value in self.binding.items():
            self.assertEqual(receipt[key], value)
        self.assertTrue(receipt["cleanup_complete"])
        self.assertEqual(set(receipt["probes"]), set(runner.KERNEL_PROBES))
        for probe in receipt["probes"].values():
            self.assertEqual(probe["status"], "passed")
            self.assertEqual(probe["evidence_sha256"], hashlib.sha256(Path(probe["evidence"]).read_bytes()).hexdigest())
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o600)
        self.assertNotIn("production_qualified", receipt)
        self.approval.close.assert_called_once()

    def test_incomplete_or_failed_engine_never_writes_receipt(self):
        for status, code in (("blocked", 2), ("failed", 1)):
            with self.subTest(status=status):
                path = self.logs / "production-response.json"
                path.unlink(missing_ok=True)
                engine = lambda _approval, binding, _logs: (code, self.response(binding, status, False), 0)
                self.assertEqual(self.offline_run(engine), code)
                self.assertFalse(self.receipt.exists())

    def test_failed_cleanup_missing_probe_bad_binding_or_exit_cannot_pass(self):
        mutations = [
            lambda value: value.update(cleanup_complete=False),
            lambda value: value["probes"].pop("chromium_sandbox"),
            lambda value: value["binding"].update(run_id=str(uuid.uuid4())),
            lambda value: value["probes"]["downloads"].update(status="skipped"),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                previous = self.logs
                self.logs = Path(temporary)
                path = self.response()
                value = json.loads(path.read_text())
                mutation(value)
                path.write_text(json.dumps(value))
                with self.assertRaises((runner.PrerequisiteError, runner.ProbeFailure)):
                    runner.validate_response(path, self.binding, self.logs, 0, 0)
                self.logs = previous
        path = self.response()
        with self.assertRaises(runner.ProbeFailure):
            runner.validate_response(path, self.binding, self.logs, 0, 7)

    def test_wrong_evidence_source_or_typed_binding_cannot_pass(self):
        self.binding["source_dirty"] = False
        path = self.response()
        evidence = self.logs / "outer_sandbox.json"
        value = json.loads(evidence.read_text())
        value["binding"]["source_dirty"] = 0
        evidence.write_text(json.dumps(value))
        with self.assertRaises(runner.ProbeFailure):
            runner.validate_response(path, self.binding, self.logs, 0, 0)

    def test_evidence_must_be_fresh_private_regular_and_inside_this_run(self):
        path = self.response()
        evidence = self.logs / "chromium_identity.json"
        evidence.chmod(0o644)
        with self.assertRaises(runner.PrerequisiteError):
            runner.validate_response(path, self.binding, self.logs, 0, 0)
        evidence.chmod(0o600)
        with self.assertRaises(runner.ProbeFailure):
            runner.validate_response(path, self.binding, self.logs, time_ns_future(), 0)
        value = json.loads(path.read_text())
        value["probes"]["chromium_identity"]["evidence"] = str(self.root / "old-evidence.json")
        path.write_text(json.dumps(value))
        with self.assertRaises(runner.ProbeFailure):
            runner.validate_response(path, self.binding, self.logs, 0, 0)

    def test_evidence_fifo_and_symlink_are_rejected_without_reading(self):
        for kind in ("fifo", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                log_dir = Path(temporary)
                target = log_dir / "unsafe.json"
                if kind == "fifo":
                    os.mkfifo(target, mode=0o600)
                else:
                    outside = self.root / "untouched"
                    outside.write_text("keep")
                    target.symlink_to(outside)
                with self.assertRaises((OSError, runner.PrerequisiteError)):
                    runner._pin(target, runner.MAX_JSON_BYTES, private_root=log_dir)

    def test_same_bytes_replacement_and_hardlink_break_pinned_evidence_continuity(self):
        path = self.logs / "evidence.json"
        runner._publish(path, {"fixture": True})
        pinned = runner._pin(path, runner.MAX_JSON_BYTES, private_root=self.logs)
        self.addCleanup(pinned.close)
        original = path.read_bytes()
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o600)
        with self.assertRaises(runner.PrerequisiteError):
            pinned.recheck()
        os.link(path, self.logs / "alias.json")
        with self.assertRaises(runner.PrerequisiteError):
            runner._pin(path, runner.MAX_JSON_BYTES, private_root=self.logs)

    def test_unapproved_default_and_bad_custom_config_block_before_engine(self):
        custom_cases = [{}, {"BROWSERD_KERNEL_PROBE_CONFIG": "/etc/example.json"},
                        {"BROWSERD_KERNEL_PROBE_CONFIG_SHA256": "b" * 64}]
        for change in custom_cases:
            with self.subTest(change=change), patch.object(runner, "check_delegation"), \
                 patch.object(runner, "DEFAULT_CONFIG", self.root / "missing-approval.json"), \
                 patch.object(runner, "execute_engine") as engine, patch.object(runner, "print"):
                self.assertEqual(runner.main(dict(self.env, **change)), 2)
                engine.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_root_approval_permissions_and_directory_ownership_are_explicit(self):
        for mode in (0o400, 0o440, 0o600, 0o640):
            runner._root_metadata(types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | mode), private=True)
        for uid, mode in ((os.getuid() or 1003, 0o600), (0, 0o644), (0, 0o660), (0, 0o755)):
            with self.subTest(uid=uid, mode=mode), self.assertRaises(runner.PrerequisiteError):
                runner._root_metadata(types.SimpleNamespace(st_uid=uid, st_mode=stat.S_IFREG | mode), private=True)
        with self.assertRaises(runner.PrerequisiteError):
            runner._root_metadata(types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777), directory=True)

    def test_complete_configuration_pins_files_mount_inventory_and_postexecution_digest(self):
        _config, _path, env, manifest_digest = self.configuration_fixture()
        with patch.object(runner, "_root_metadata"):
            approval = runner.load_configuration(env, manifest_digest)
            try:
                approval.recheck()
                (self.root / "runtime/library.so").write_bytes(b"changed runtime")
                with self.assertRaises(runner.PrerequisiteError):
                    approval.recheck()
            finally:
                approval.close()

    def test_user_owned_configuration_is_not_approval_even_with_all_true_fields_and_matching_hashes(self):
        _config, _path, env, manifest_digest = self.configuration_fixture()
        with self.assertRaises(runner.PrerequisiteError):
            runner.load_configuration(env, manifest_digest)

    def test_configuration_wrong_authority_fields_missing_roles_and_asset_hashes_fail_before_engine(self):
        original_config, path, env, manifest_digest = self.configuration_fixture()
        mutations = [
            lambda config: config.update(operator_approval=False),
            lambda config: config.update(operator_approval=1),
            lambda config: config.update(isolated_validation=False),
            lambda config: config.update(validation_uid=True),
            lambda config: config.update(validation_uid=os.getuid() + 1),
            lambda config: config.update(production_qualified=True),
            lambda config: config["approved_assets"].pop(),
            lambda config: config["approved_assets"][0].update(role="unknown_role"),
            lambda config: config["approved_assets"][0].update(sha256="f" * 64),
            lambda config: config["probe_executable"].update(sha256="f" * 64),
        ]
        for index, mutation in enumerate(mutations):
            config = json.loads(json.dumps(original_config))
            mutation(config)
            with self.subTest(index=index), patch.object(runner, "_root_metadata"):
                with self.assertRaises(runner.PrerequisiteError):
                    runner.load_configuration(self.rewrite_config(path, config, env), manifest_digest)

    def test_approval_file_digest_asset_role_path_and_original_artifact_binding_cannot_be_rebound(self):
        config, path, env, manifest_digest = self.configuration_fixture()
        with patch.object(runner, "_root_metadata"):
            with self.assertRaises(runner.PrerequisiteError):
                runner.load_configuration(dict(env, BROWSERD_KERNEL_PROBE_CONFIG_SHA256="f" * 64), manifest_digest)
            config["approved_assets"].append(dict(config["approved_assets"][0], role="runtime_file"))
            with self.assertRaisesRegex(runner.PrerequisiteError, "duplicate.*path"):
                runner.load_configuration(self.rewrite_config(path, config, env), manifest_digest)
            config["approved_assets"].pop()
            config["deployment"]["assets"]["seccomp_filter"] = "/etc/other-filter.bpf"
            with self.assertRaisesRegex(runner.PrerequisiteError, "differs from deployment"):
                runner.load_configuration(self.rewrite_config(path, config, env), manifest_digest)

    def test_optional_scanner_is_exact_typed_and_missing_scanner_never_claims_download_coverage(self):
        config, _path, _env, _digest = self.configuration_fixture()
        deployment = config["deployment"]
        runner.validate_deployment(deployment)
        deployment["worker"]["scanner"] = None
        runner.validate_deployment(deployment)
        scanner = {"socket_path": "/run/clamav/clamd.sock", "expected_uid": 1003,
                   "max_database_age_millis": 86400000, "max_future_skew_millis": 0}
        deployment["worker"]["scanner"] = scanner
        runner.validate_deployment(deployment)
        for change in ({"expected_uid": True}, {"max_database_age_millis": 0}, {"socket_path": "relative"}, {"trusted": True}):
            with self.subTest(change=change):
                deployment["worker"]["scanner"] = dict(scanner, **change)
                with self.assertRaises(runner.PrerequisiteError):
                    runner.validate_deployment(deployment)

    def test_privileged_evaluate_requires_explicit_boolean_approval_and_is_not_inferred(self):
        config, _path, _env, _digest = self.configuration_fixture()
        deployment = config["deployment"]
        runner.validate_deployment(deployment)
        self.assertNotIn("privileged_evaluate", deployment["worker"])
        for allowed in (False, True):
            deployment["worker"]["privileged_evaluate"] = allowed
            runner.validate_deployment(deployment)
            self.assertIs(deployment["worker"]["privileged_evaluate"], allowed)
        for invalid in (None, 0, 1, "true", []):
            with self.subTest(invalid=invalid):
                deployment["worker"]["privileged_evaluate"] = invalid
                with self.assertRaisesRegex(runner.PrerequisiteError, "explicit boolean"):
                    runner.validate_deployment(deployment)

    def test_private_or_malformed_fixture_and_nonloopback_control_inputs_do_not_admit_probes(self):
        config, _path, _env, _digest = self.configuration_fixture()
        for origin in ("http://127.0.0.1:18080", "https://validation.example.com", "http://validation.example.com:99999"):
            deployment = json.loads(json.dumps(config["deployment"]))
            deployment["fixtures"]["origin"] = origin
            with self.subTest(origin=origin), self.assertRaises(runner.PrerequisiteError):
                runner.validate_deployment(deployment)
        config["deployment"]["egress"]["control_url"] = "http://192.0.2.1:20130"
        with self.assertRaises(runner.PrerequisiteError):
            runner.validate_deployment(config["deployment"])

    def test_parent_example_matches_schema_after_replacing_only_its_placeholder_policy_digest(self):
        path = SCRIPT.parents[1] / "deploy/kernel-probe-approval.example.json"
        config = json.loads(path.read_text())
        self.assertIs(config["operator_approval"], False)
        config["deployment"]["egress"]["policy_digest"] = "e" * 64
        runner.validate_deployment(config["deployment"])

    def test_runtime_mount_only_allows_the_exact_chromium_parent_for_resource_overlay(self):
        config, _path, _env, _digest = self.configuration_fixture()
        for field in ("chromium_sandbox_executable", "launch_gate_sandbox_executable"):
            for destination in (Path(config["deployment"]["assets"][field]),
                                Path(config["deployment"]["assets"][field]) / "nested"):
                deployment = json.loads(json.dumps(config["deployment"]))
                deployment["assets"]["read_only_mounts"][0]["destination"] = str(destination)
                with self.subTest(field=field, destination=destination), self.assertRaisesRegex(runner.PrerequisiteError, "overlaps"):
                    runner.validate_deployment(deployment)
        deployment = json.loads(json.dumps(config["deployment"]))
        deployment["assets"]["chromium_sandbox_executable"] = "/browserd-chromium/chromium"
        deployment["assets"]["read_only_mounts"][0]["destination"] = "/browserd-chromium"
        runner.validate_deployment(deployment)
        deployment["assets"]["read_only_mounts"][0]["destination"] = str(Path(deployment["assets"]["launch_gate_sandbox_executable"]).parent)
        with self.assertRaisesRegex(runner.PrerequisiteError, "overlaps"):
            runner.validate_deployment(deployment)

    def test_duplicate_unknown_and_nonfinite_json_fail_closed(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(runner.PrerequisiteError):
                runner._json(raw)

    def test_runtime_inventory_covers_actual_files_not_only_a_subset(self):
        directory = self.root / "runtime"
        directory.mkdir()
        (directory / "lib.so").write_bytes(b"library")
        manifest = {"schema_version": 1, "mounts": [{"source": str(directory), "destination": "/usr/lib",
            "files": [{"relative_path": "lib.so", "sha256": hashlib.sha256(b"library").hexdigest()}]}]}
        deployment = {"assets": {"read_only_mounts": [{"source": str(directory), "destination": "/usr/lib"}]}}
        pins = []
        try:
            with patch.object(runner, "_root_metadata"):
                runner._runtime_inventory(json.dumps(manifest).encode(), deployment, pins)
                (directory / "unlisted.so").write_bytes(b"unlisted")
                with self.assertRaisesRegex(runner.PrerequisiteError, "omits"):
                    runner._runtime_inventory(json.dumps(manifest).encode(), deployment, pins)
        finally:
            for pinned in pins:
                pinned.close()

    def test_bound_source_metadata_and_dirty_runtime_evidence_are_preserved(self):
        env = dict(self.env, BROWSERD_VALIDATION_SOURCE_REVISION="d" * 40,
                   BROWSERD_VALIDATION_SOURCE_DIRTY="true", BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256="e" * 64)
        with patch.object(runner, "check_delegation"):
            binding, _logs, _receipt = runner.binding_from_environment(env)
        self.assertEqual(binding["source_revision"], "d" * 40)
        self.assertIs(binding["source_dirty"], True)
        self.assertEqual(binding["source_content_sha256"], "e" * 64)
        del env["BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256"]
        with self.assertRaisesRegex(runner.PrerequisiteError, "content digest"):
            runner.binding_from_environment(env)

    def lab_delegation(self):
        base = self.root / "cgroups"
        root = base / f"browserd-validation-u{os.getuid()}-{'a' * 12}.service" / "workloads"
        lab = root / ("lab-" + self.expected["run_id"])
        for directory in (root, lab, lab / "control", lab / "shards"):
            directory.mkdir(parents=True, exist_ok=True)
            for name, value in {
                "cgroup.type": "domain", "cgroup.controllers": "cpu memory pids",
                "cgroup.subtree_control": "cpu memory pids", "cgroup.procs": "",
            }.items():
                (directory / name).write_text(value)
        (lab / "control/cgroup.procs").write_text(str(os.getpid()))
        return base, root, lab

    def test_exact_owned_lab_proves_controller_and_common_ancestor_authority(self):
        base, root, lab = self.lab_delegation()
        with patch.object(runner, "CGROUP_ROOT", base), \
             patch.object(runner, "process_cgroup", return_value=lab / "control"), \
             patch.object(runner, "check_delegation", side_effect=runner.DelegationError("outside holder")):
            self.assertEqual(runner.check_production_delegation(root, self.expected["run_id"]), lab / "shards")
            (lab / "shards/cgroup.subtree_control").write_text("cpu pids")
            with self.assertRaisesRegex(runner.PrerequisiteError, "controllers"):
                runner.check_production_delegation(root, self.expected["run_id"])

    def test_lab_rejects_foreign_generation_process_membership_and_readonly_mount(self):
        base, root, lab = self.lab_delegation()
        with patch.object(runner, "CGROUP_ROOT", base), \
             patch.object(runner, "process_cgroup", return_value=lab / "control"), \
             patch.object(runner, "check_delegation", side_effect=runner.DelegationError("outside holder")):
            with self.assertRaisesRegex(runner.PrerequisiteError, "current-run"):
                runner.check_production_delegation(root, str(uuid.uuid4()))
            (lab / "control/cgroup.procs").write_text("999999999")
            with self.assertRaisesRegex(runner.PrerequisiteError, "membership"):
                runner.check_production_delegation(root, self.expected["run_id"])
            (lab / "control/cgroup.procs").write_text(str(os.getpid()))
            with patch.object(runner.os, "statvfs", return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)):
                with self.assertRaisesRegex(runner.PrerequisiteError, "writable"):
                    runner.check_production_delegation(root, self.expected["run_id"])

    def test_lab_rejects_symlinks_and_unrelated_approved_sandbox_root(self):
        base, root, lab = self.lab_delegation()
        with patch.object(runner, "CGROUP_ROOT", base), \
             patch.object(runner, "process_cgroup", return_value=lab / "control"), \
             patch.object(runner, "check_delegation", side_effect=runner.DelegationError("outside holder")):
            approval = types.SimpleNamespace(config={"deployment": {"sandbox": {"cgroup_root": str(lab / "shards")}}})
            env = dict(self.env, BROWSERD_VALIDATION_CGROUP_ROOT=str(root))
            runner._check_approved_delegation(env, self.expected, approval)
            approval.config["deployment"]["sandbox"]["cgroup_root"] = str(root / "unrelated")
            with self.assertRaisesRegex(runner.PrerequisiteError, "approved sandbox"):
                runner._check_approved_delegation(env, self.expected, approval)
            (lab / "shards").rename(lab / "other")
            (lab / "shards").symlink_to(lab / "other", target_is_directory=True)
            with self.assertRaisesRegex(runner.PrerequisiteError, "symlink"):
                runner.check_production_delegation(root, self.expected["run_id"])

    def test_existing_receipt_is_preserved_and_engine_is_not_started(self):
        self.receipt.write_bytes(b"earlier evidence")
        with patch.object(runner, "execute_engine") as engine, patch.object(runner, "print"):
            self.assertEqual(runner.main(self.env), 2)
        engine.assert_not_called()
        self.assertEqual(self.receipt.read_bytes(), b"earlier evidence")

    def test_publication_never_overwrites_and_directory_fsync_failure_removes_own_receipt(self):
        self.receipt.write_bytes(b"previous")
        with self.assertRaises(FileExistsError):
            runner._publish(self.receipt, {"new": True})
        self.assertEqual(self.receipt.read_bytes(), b"previous")
        self.receipt.unlink()
        original = os.fsync
        def fail_directory(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("offline injected directory fsync failure")
            return original(descriptor)
        with patch.object(runner.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                runner._publish(self.receipt, {"new": True})
        self.assertFalse(self.receipt.exists())
        self.assertEqual(list(self.logs.iterdir()), [])

    def test_engine_argv_is_literal_owned_output_and_no_inherited_injection(self):
        process = Mock(pid=234, poll=Mock(return_value=0), wait=Mock(return_value=0))
        with patch.object(runner.subprocess, "Popen", return_value=process) as spawned:
            code, response, _started = runner.execute_engine(self.approval, self.binding, self.logs)
        self.assertEqual(code, 0)
        self.assertEqual(response, self.logs / "production-response.json")
        self.assertEqual(spawned.call_args.args[0], [str(self.approval.probe.path), "--request",
            str(self.logs / "production-request.json"), "--response", str(response)])
        self.assertNotIn("shell", spawned.call_args.kwargs)
        self.assertEqual(spawned.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        request = json.loads((self.logs / "production-request.json").read_text())
        self.assertEqual(request["binding"], self.binding)
        self.assertEqual(request["deadline_seconds"], 7200)
        self.assertEqual((self.logs / "production-engine.log").stat().st_mode & 0o777, 0o600)

    def test_engine_timeout_and_interrupt_reap_only_owned_process_group(self):
        for error in (runner.subprocess.TimeoutExpired("fixture", 7200), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                log_dir = Path(temporary)
                process = Mock(pid=234, poll=Mock(return_value=None))
                process.wait.side_effect = [error, 0]
                with patch.object(runner.subprocess, "Popen", return_value=process), \
                     patch.object(runner.os, "killpg") as kill:
                    with self.assertRaises((runner.ProbeFailure, KeyboardInterrupt)):
                        runner.execute_engine(self.approval, self.binding, log_dir)
                kill.assert_called_once_with(234, signal.SIGTERM)
                self.assertFalse((log_dir / "receipt.json").exists())

    def test_postexecution_asset_or_evidence_drift_prevents_receipt(self):
        self.approval.recheck.side_effect = [None, runner.PrerequisiteError("asset changed")]
        self.assertEqual(self.offline_run(), 1)
        self.assertFalse(self.receipt.exists())

    def test_recreated_run_directory_cannot_publish_receipt_even_if_owned_and_private(self):
        def engine(_approval, binding, _logs):
            response = self.response(binding)
            original = self.logs.with_name("old-run")
            self.logs.rename(original)
            self.logs.mkdir(mode=0o700)
            return 0, response, 0
        self.assertEqual(self.offline_run(engine), 1)
        self.assertFalse(self.receipt.exists())


def time_ns_future():
    return (1 << 63) - 1


if __name__ == "__main__":
    unittest.main()
