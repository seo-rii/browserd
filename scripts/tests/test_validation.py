"""Behavior tests for the release validation runner; no Rust build or services needed."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "validation.py"
spec = importlib.util.spec_from_file_location("validation", SCRIPT)
validation = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validation
spec.loader.exec_module(validation)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def source_tree(self):
        root = self.root / "source"
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
        (root / "entry.rs").write_text("original source\n")
        subprocess.run(["git", "add", "entry.rs"], cwd=root, check=True, capture_output=True)
        subprocess.run(["git", "-c", "user.name=probe-test", "-c", "user.email=probe@example.invalid",
                        "commit", "-qm", "fixture"], cwd=root, check=True, capture_output=True)
        return root

    def test_source_snapshot_tracks_dirty_untracked_and_deleted_bytes(self):
        root = self.source_tree()
        original = validation.source_content_identity(root)
        self.assertRegex(original, r"^[0-9a-f]{64}$")
        self.assertFalse(validation.source_identity(root)["source_dirty"])
        (root / "entry.rs").write_text("modified source\n")
        modified = validation.source_content_identity(root)
        self.assertNotEqual(original, modified)
        (root / "extra.rs").write_text("untracked source\n")
        untracked = validation.source_content_identity(root)
        self.assertNotEqual(modified, untracked)
        (root / "entry.rs").unlink()
        self.assertNotEqual(untracked, validation.source_content_identity(root))

    def test_source_snapshot_excludes_only_bookkeeping_and_does_not_follow_links(self):
        root = self.source_tree()
        original = validation.source_content_identity(root)
        for name in validation.BOOKKEEPING_FILES:
            (root / name).write_text("task bookkeeping\n")
        self.assertEqual(original, validation.source_content_identity(root))
        self.assertFalse(validation.source_identity(root)["source_dirty"])
        external = self.root / "external"
        external.write_text("outside bytes\n")
        (root / "link").symlink_to(external)
        linked = validation.source_content_identity(root)
        external.write_text("different outside bytes\n")
        self.assertEqual(linked, validation.source_content_identity(root))
        (root / "link").unlink()
        (root / "link").symlink_to(self.root / "other")
        self.assertNotEqual(linked, validation.source_content_identity(root))

    def test_source_snapshot_refuses_symlink_ancestors_and_oversized_files(self):
        root = self.source_tree()
        directory = root / "nested"
        directory.mkdir()
        (directory / "entry.rs").write_text("nested source\n")
        subprocess.run(["git", "add", "nested/entry.rs"], cwd=root, check=True, capture_output=True)
        (directory / "entry.rs").unlink()
        directory.rmdir()
        directory.symlink_to(self.root, target_is_directory=True)
        self.assertIsNone(validation.source_content_identity(root))
        directory.unlink()
        directory.mkdir()
        with (root / "large").open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        self.assertIsNone(validation.source_content_identity(root))

    def test_qualification_source_metadata_cannot_be_spoofed_by_caller(self):
        metadata = self.root / "metadata.json"
        code = ("import json,os; from pathlib import Path; "
                f"Path({str(metadata)!r}).write_text(json.dumps(dict(os.environ))); "
                "raise SystemExit(2)")
        command = validation.Command("kernel-real-browser", (sys.executable, "-c", code), self.root)
        env = dict(os.environ, **{name: "caller-forged" for name in validation.SOURCE_VARIABLES})
        identity = {"source_revision": "a" * 40, "source_dirty": True}
        with patch.object(validation, "source_identity", return_value=identity), \
             patch.object(validation, "source_content_identity", return_value="b" * 64):
            _, report = validation.execute("kernel", [command], self.root / "logs", env,
                                           {"manifest_sha256": "c" * 64})
        values = json.loads(metadata.read_text())
        self.assertEqual(values["BROWSERD_VALIDATION_SOURCE_REVISION"], "a" * 40)
        self.assertEqual(values["BROWSERD_VALIDATION_SOURCE_DIRTY"], "true")
        self.assertEqual(values["BROWSERD_VALIDATION_SOURCE_CONTENT_SHA256"], "b" * 64)
        self.assertEqual(report["source_content_sha256"], "b" * 64)
        self.assertFalse(report["source_changed_during_run"])

    def test_current_receipt_cannot_pass_after_source_changes_during_run(self):
        code = ("import json,os; from pathlib import Path; "
                "receipt={key:os.environ['BROWSERD_VALIDATION_'+key.upper()] "
                "for key in ['run_id','tier','manifest_sha256','kernel_release','machine']}; "
                f"receipt['probes']={{name:{{'status':'passed','evidence':'fixture'}} for name in {validation.KERNEL_PROBES!r}}}; "
                "Path(os.environ['BROWSERD_VALIDATION_RECEIPT']).write_text(json.dumps(receipt))")
        command = validation.Command("kernel-real-browser", (sys.executable, "-c", code), self.root)
        for hashes, reason in [(["b" * 64, "c" * 64], "source changed during qualification"),
                               ([None, None], "source contents could not be verified for qualification")]:
            with self.subTest(hashes=hashes), \
                 patch.object(validation, "source_identity", return_value={"source_revision": "a" * 40, "source_dirty": True}), \
                 patch.object(validation, "source_content_identity", side_effect=hashes):
                _, report = validation.execute("kernel", [command], self.root / "logs", dict(os.environ),
                                               {"manifest_sha256": "d" * 64})
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["source_changed_during_run"], hashes[0] != hashes[1])
            if hashes[0] != hashes[1]:
                self.assertEqual(report["final_source_content_sha256"], hashes[1])
            self.assertEqual(report["reason"], reason)

    def native_artifact(self):
        artifact = self.root / "artifact"
        artifact.mkdir()
        content = {"bin/chromium": b"pinned browser", "bin/icudtl.dat": b"pinned ICU", "locales/ko.pak": b"pinned Korean locale"}
        catalog = {"schema_version": 1, "icu_data": "bin/icudtl.dat", "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}], "time_zones": ["Asia/Seoul", "UTC"]}
        content["native-process-profiles.json"] = json.dumps(catalog).encode()
        for name, data in content.items():
            path = artifact / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        manifest = {"identity": {"binary_digest": hashlib.sha256(content["bin/chromium"]).hexdigest(), "launch_profile_digest": hashlib.sha256(content["native-process-profiles.json"]).hexdigest()}, "files": [{"relative_path": name, "digest": hashlib.sha256(data).hexdigest()} for name, data in content.items()]}
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        return artifact, manifest, catalog

    def rewrite_catalog(self, artifact, manifest, catalog):
        data = json.dumps(catalog).encode()
        (artifact / "native-process-profiles.json").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        manifest["identity"]["launch_profile_digest"] = digest
        next(item for item in manifest["files"] if item["relative_path"] == "native-process-profiles.json")["digest"] = digest
        (artifact / "compatibility.json").write_text(json.dumps(manifest))

    def test_native_catalog_is_required_in_artifact_preflight(self):
        artifact, manifest, _ = self.native_artifact()
        manifest["files"] = [entry for entry in manifest["files"] if entry["relative_path"] != "native-process-profiles.json"]
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(validation.GateError, "verification"):
            validation.verify_artifact(artifact)

    def test_native_catalog_digest_must_match_launch_identity(self):
        artifact, manifest, _ = self.native_artifact()
        manifest["identity"]["launch_profile_digest"] = "f" * 64
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(validation.GateError, "verification"):
            validation.verify_artifact(artifact)

    def test_native_catalog_nonregular_or_symlink_file_is_rejected_before_read(self):
        for kind in ["fifo", "symlink"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                previous = self.root
                self.root = Path(temporary)
                artifact, _, _ = self.native_artifact()
                self.root = previous
                catalog = artifact / "native-process-profiles.json"
                data = catalog.read_bytes()
                catalog.unlink()
                if kind == "fifo":
                    os.mkfifo(catalog)
                else:
                    source = Path(temporary) / "external-catalog"
                    source.write_bytes(data)
                    catalog.symlink_to(source)
                original_open = Path.open
                def no_unsafe_catalog_read(path, *args, **kwargs):
                    if path == catalog:
                        self.fail("unsafe catalog must be rejected before opening it")
                    return original_open(path, *args, **kwargs)
                with patch.object(Path, "open", no_unsafe_catalog_read):
                    with self.assertRaisesRegex(validation.GateError, "verification"):
                        validation.verify_artifact(artifact)

    def test_native_catalog_schema_resources_and_exact_names_fail_closed(self):
        mutations = [
            {"schema_version": 2}, {"schema_version": True}, {"environment": {"LD_PRELOAD": "unsafe"}},
            {"icu_data": "locales/ko.pak"}, {"icu_data": "bin/missing.dat"},
            {"locales": [{"locale": "ko-KR", "pak": "unlisted.pak"}]},
            {"locales": [{"locale": "ko-KR", "pak": "locales/ko.pak", "extra": True}]},
            {"locales": [{"locale": "1ko-KR", "pak": "locales/ko.pak"}]},
            {"locales": [{"locale": "ko-" + "a" * 17, "pak": "locales/ko.pak"}]},
            {"locales": []}, {"time_zones": []}, {"time_zones": ["Asia/../Seoul"]},
            {"time_zones": ["Asia/Seoul", "Asia/Seoul"]},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as path:
                    previous = self.root
                    self.root = Path(path)
                    artifact, manifest, catalog = self.native_artifact()
                    self.root = previous
                    catalog.update(mutation)
                    self.rewrite_catalog(artifact, manifest, catalog)
                    with self.assertRaisesRegex(validation.GateError, "verification"):
                        validation.verify_artifact(artifact)

    def test_native_catalog_unique_binary_mapping_and_manifest_paths(self):
        for entry in [{"relative_path": "bin/chromium", "digest": "same"}, {"relative_path": "other-browser", "digest": "same"}]:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as path:
                previous = self.root
                self.root = Path(path)
                artifact, manifest, _ = self.native_artifact()
                self.root = previous
                entry = dict(entry, digest=manifest["identity"]["binary_digest"])
                if entry["relative_path"] == "other-browser":
                    (artifact / "other-browser").write_bytes((artifact / "bin/chromium").read_bytes())
                manifest["files"].append(entry)
                (artifact / "compatibility.json").write_text(json.dumps(manifest))
                with self.assertRaisesRegex(validation.GateError, "verification"):
                    validation.verify_artifact(artifact)

    def test_valid_native_artifact_binds_catalog_and_resources(self):
        artifact, _, _ = self.native_artifact()
        self.assertEqual(validation.verify_artifact(artifact), hashlib.sha256((artifact / "compatibility.json").read_bytes()).hexdigest())
        (artifact / "bin/icudtl.dat").write_bytes(b"changed ICU")
        with self.assertRaisesRegex(validation.GateError, "verification"):
            validation.verify_artifact(artifact)

    def test_invalid_native_artifact_blocks_kernel_and_soak_before_any_commands(self):
        artifact, manifest, _ = self.native_artifact()
        manifest["files"] = [entry for entry in manifest["files"] if entry["relative_path"] != "native-process-profiles.json"]
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        cgroup = self.root / "delegated"
        cgroup.mkdir()
        (cgroup / "cgroup.controllers").write_text("cpu memory pids")
        (cgroup / "cgroup.subtree_control").write_text("")
        marker = self.root / "should-not-run"
        command = validation.Command("never", (sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"), self.root)
        original_resolve = Path.resolve
        def delegated_resolve(path, *args, **kwargs):
            return Path("/sys/fs/cgroup/browserd-tests") if path == cgroup else original_resolve(path, *args, **kwargs)
        env = {"BROWSERD_KERNEL_RUNNER": sys.executable, "BROWSERD_SOAK_RUNNER": sys.executable,
               "BROWSERD_TRUSTED_VALIDATION": "1", "BROWSERD_VALIDATION_CGROUP_ROOT": str(cgroup),
               "BROWSERD_CHROMIUM_ARTIFACT_ROOT": str(artifact)}
        for tier in ["kernel", "soak"]:
            with self.subTest(tier=tier), patch.object(validation.Path, "resolve", delegated_resolve), \
                 patch.object(validation, "build_plan", return_value=[command]), \
                 patch.object(validation.platform, "system", return_value="Linux"):
                logs = self.root / f"{tier}-logs"
                self.assertEqual(validation.main([tier, "--log-dir", str(logs)], env=env), 2)
                report = json.loads(next(logs.glob("*/report.json")).read_text())
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(report["commands"], [])
                self.assertIn("verification", report["reason"])
                self.assertFalse(marker.exists())

    def test_adapter_cannot_pass_by_early_returning_without_service_urls(self):
        with self.assertRaisesRegex(validation.GateError, "BROWSERD_REDIS_TEST_URL"):
            validation.check_prerequisites("adapter", {}, self.root)

    def test_mixed_infrastructure_suites_run_only_in_adapter_and_once(self):
        root = SCRIPT.parent.parent
        required = {
            ("browser-gateway", "worker_notifications"),
            ("browserd-coordination", "notification_import"),
            ("browserd-coordination", "postgres_operation_events"),
            ("browserd-coordination", "postgres_webhook_store"),
            ("browserd-coordination", "safety_authority"),
        }
        inventory = validation.inventory(root)
        plans = {tier: validation.build_plan(tier, root) for tier in ("adapter", "fast", "kernel")}
        for package, target in sorted(required):
            with self.subTest(package=package, target=target):
                self.assertEqual(inventory[(package, target)], "adapter")
                for tier, commands in plans.items():
                    appearances = sum(
                        command.argv.count(target)
                        for command in commands
                        if "-p" in command.argv
                        and command.argv[command.argv.index("-p") + 1] == package
                    )
                    self.assertEqual(appearances, 1 if tier == "adapter" else 0)

    def test_unknown_infrastructure_target_and_same_name_in_another_package_still_block(self):
        for package, target in [
            ("browserd-coordination", "new_postgres_suite"),
            ("browserd-worker", "worker_notifications"),
        ]:
            with self.subTest(package=package, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                directory = root / "crates" / package
                (directory / "tests").mkdir(parents=True)
                (directory / "Cargo.toml").write_text(f'[package]\nname = "{package}"\n')
                (directory / "tests" / f"{target}.rs").write_text(
                    'fn probe() { let _ = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL"); }'
                )
                with self.assertRaisesRegex(validation.GateError, f"{package}/{target}"):
                    validation.inventory(root)

    def test_adapter_missing_postgres_blocks_before_any_mixed_suite_can_early_return(self):
        marker = self.root / "should-not-run"
        command = validation.Command("never", (sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"), self.root)
        env = {"BROWSERD_REDIS_TEST_URL": "redis://localhost/0"}
        logs = self.root / "logs"
        with patch.object(validation, "build_plan", return_value=[command]):
            self.assertEqual(validation.main(["adapter", "--log-dir", str(logs)], env=env), 2)
        report = json.loads(next(logs.glob("*/report.json")).read_text())
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["commands"], [])
        self.assertIn("BROWSERD_COORDINATION_TEST_DATABASE_URL", report["reason"])
        self.assertFalse(marker.exists())

    def test_adapter_requires_both_valid_service_urls_without_disclosing_postgres_password(self):
        valid = {
            "BROWSERD_REDIS_TEST_URL": "redis://localhost/0",
            "BROWSERD_COORDINATION_TEST_DATABASE_URL": "postgresql://localhost/browserd",
        }
        self.assertEqual(validation.check_prerequisites("adapter", valid, self.root), {})
        with self.assertRaisesRegex(validation.GateError, "BROWSERD_REDIS_TEST_URL"):
            validation.check_prerequisites("adapter", {"BROWSERD_COORDINATION_TEST_DATABASE_URL": valid["BROWSERD_COORDINATION_TEST_DATABASE_URL"]}, self.root)
        for url in ("https://user:do-not-print@localhost/browserd", "postgres://user:do-not-print@/browserd"):
            with self.subTest(url=url):
                with self.assertRaises(validation.GateError) as result:
                    validation.check_prerequisites("adapter", dict(valid, BROWSERD_COORDINATION_TEST_DATABASE_URL=url), self.root)
                self.assertIn("BROWSERD_COORDINATION_TEST_DATABASE_URL", str(result.exception))
                self.assertNotIn("do-not-print", str(result.exception))

    def test_adapter_inventory_cannot_silently_omit_the_gateway_mixed_suite(self):
        suites = {target: "adapter" for target in validation.ADAPTER_SUITES}
        del suites[("browser-gateway", "worker_notifications")]
        with patch.object(validation, "inventory", return_value=suites):
            with self.assertRaisesRegex(validation.GateError, "adapter inventory changed"):
                validation.build_plan("adapter", self.root)

    def test_live_browser_suites_are_explicit_ignored_kernel_commands(self):
        package = self.root / "crates/browserd-worker"
        (package / "tests").mkdir(parents=True)
        (package / "Cargo.toml").write_text('[package]\nname = "browserd-worker"\n')
        for name in ["live_chromium_input", "live_chromium_capture", "live_chromium_viewer", "live_chromium_emulation", "live_chromium_downloads", "live_chromium_workers", "live_chromium_evaluate"]:
            (package / "tests" / f"{name}.rs").write_text('#[ignore = "real Chromium"]\nfn probe() {}')
        self.assertEqual(set(validation.inventory(self.root).values()), {"kernel"})
        plan = validation.build_plan("kernel", self.root)
        live = [command for command in plan if "live_chromium_viewer" in command.argv]
        self.assertEqual(len(live), 1)
        self.assertIn("live_chromium_emulation", live[0].argv)
        self.assertIn("live_chromium_workers", live[0].argv)
        self.assertIn("live_chromium_evaluate", live[0].argv)
        self.assertFalse(any("live_chromium_evaluate" in command.argv for command in validation.build_plan("fast", self.root)))
        self.assertFalse(any("live_chromium_workers" in command.argv for command in validation.build_plan("fast", self.root)))
        self.assertEqual(live[0].argv[-2:], ("--", "--ignored"))
        self.assertFalse(any("live_chromium_viewer" in command.argv for command in validation.build_plan("fast", self.root)))
        fast_python = [command for command in validation.build_plan("fast", self.root) if "scripts/tests" in command.argv]
        self.assertTrue(all("-p" in command.argv for command in fast_python))
        self.assertTrue(any("test_chromium_*.py" in command.argv for command in plan))
        files = [command for command in plan if command.name == "file-input-artifacts"]
        self.assertEqual(len(files), 1)
        self.assertIn("--lib", files[0].argv)
        self.assertIn("chromium_owner::uploads::live_tests::actual_owner_file_inputs_preserve_names_bytes_and_scope", files[0].argv)
        self.assertEqual(files[0].argv[-3:], ("--", "--ignored", "--exact"))
        self.assertFalse(any(command.name == "file-input-artifacts" for command in validation.build_plan("fast", self.root)))
        secrets = [command for command in plan if command.name == "origin-bound-secrets"]
        self.assertEqual(len(secrets), 1)
        self.assertIn("--lib", secrets[0].argv)
        self.assertIn("chromium_owner::secrets::live_tests::actual_owner_secret_fill_preserves_origin_and_redacts_results", secrets[0].argv)
        self.assertEqual(secrets[0].argv[-3:], ("--", "--ignored", "--exact"))
        self.assertFalse(any(command.name == "origin-bound-secrets" for command in validation.build_plan("fast", self.root)))
        checkpoints = [command for command in plan if command.name == "storage-checkpoint"]
        self.assertEqual(len(checkpoints), 1)
        self.assertIn("--lib", checkpoints[0].argv)
        self.assertIn("chromium_owner::checkpoints::live_tests::actual_owner_checkpoint_roundtrip_without_network_or_reapplication", checkpoints[0].argv)
        self.assertEqual(checkpoints[0].argv[-3:], ("--", "--ignored", "--exact"))
        self.assertFalse(any(command.name == "storage-checkpoint" for command in validation.build_plan("fast", self.root)))
        frames = [command for command in plan if command.name == "frame-node-input"]
        self.assertEqual(len(frames), 1)
        self.assertIn("--lib", frames[0].argv)
        self.assertIn("chromium_owner::frames::live_tests::actual_owner_nested_frames_and_oopif_input_are_fenced", frames[0].argv)
        self.assertEqual(frames[0].argv[-3:], ("--", "--ignored", "--exact"))
        self.assertFalse(any(command.name == "frame-node-input" for command in validation.build_plan("fast", self.root)))

    def test_every_repository_live_browser_test_runs_ignored_only_in_kernel(self):
        root = SCRIPT.parent.parent
        worker = root / "crates/browserd-worker"
        suites = {path.stem for path in (worker / "tests").glob("live_*.rs")}
        self.assertIn("live_chromium_shared_context", suites)
        self.assertEqual(suites, set(validation.LIVE_BROWSER_SUITES))
        inventory = validation.inventory(root)
        kernel = validation.build_plan("kernel", root)
        fast = validation.build_plan("fast", root)
        live = [command for command in kernel if command.name == "browserd-worker"]
        self.assertEqual(len(live), 1)
        self.assertEqual(live[0].argv[-2:], ("--", "--ignored"))
        for suite in sorted(suites):
            with self.subTest(suite=suite):
                self.assertEqual(inventory[("browserd-worker", suite)], "kernel")
                self.assertIn(suite, live[0].argv)
                # Only the emulation fixture regressions run in fast, filtered and never ignored.
                self.assertFalse(any(suite in command.argv and command.name != "native-fixture-tests"
                                     for command in fast))
        # Library live_tests modules run by exact name; inline modules start at `mod live_tests {`.
        ignored = re.compile(r'#\[ignore(?:\s*=\s*"[^"]*")?\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+(\w+)')
        proofs = set()
        for path in (worker / "src").rglob("*.rs"):
            module = path.relative_to(worker / "src").with_suffix("").parts
            text = path.read_text()
            if module[-1] == "live_tests":
                proofs |= {"::".join(module) + "::" + name for name in ignored.findall(text)}
            elif "mod live_tests {" in text:
                prefix = "::".join(module + ("live_tests",))
                proofs |= {prefix + "::" + name for name in ignored.findall(text.split("mod live_tests {", 1)[1])}
        self.assertIn("chromium_owner::approvals::live_tests::actual_owner_typed_approvals_bind_child_secret_files_and_blank_context", proofs)
        self.assertGreaterEqual(len(proofs), 5)
        for proof in sorted(proofs):
            with self.subTest(proof=proof):
                commands = [command for command in kernel if proof in command.argv]
                self.assertEqual(len(commands), 1)
                self.assertEqual(commands[0].argv[:6], ("cargo", "test", "--locked", "-p", "browserd-worker", "--lib"))
                self.assertEqual(commands[0].argv[-3:], ("--", "--ignored", "--exact"))
                self.assertFalse(any(proof in command.argv for command in fast))

    def test_unlisted_live_suite_cannot_fall_into_the_fast_tier(self):
        package = self.root / "crates/browserd-worker"
        (package / "tests").mkdir(parents=True)
        (package / "Cargo.toml").write_text('[package]\nname = "browserd-worker"\n')
        (package / "tests/live_chromium_unlisted.rs").write_text('#[ignore = "real Chromium"]\nfn probe() {}')
        with self.assertRaisesRegex(validation.GateError, "live_chromium_unlisted"):
            validation.inventory(self.root)

    def test_live_browser_binary_is_the_pinned_executable_not_an_unrelated_system_build(self):
        binary = self.root / "chromium"
        binary.write_bytes(b"pinned executable"); binary.chmod(0o700)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        (self.root / "compatibility.json").write_text(json.dumps({"identity":{"binary_digest":digest}, "files":[{"relative_path":"chromium","digest":digest}]}))
        self.assertEqual(validation.pinned_test_chromium(self.root, {}), str(binary))
        with self.assertRaises(validation.GateError):
            validation.pinned_test_chromium(self.root, {"BROWSERD_TEST_CHROMIUM":"/usr/bin/chromium"})
        binary.chmod(0o600)
        with self.assertRaises(validation.GateError):
            validation.pinned_test_chromium(self.root, {})

    def test_kernel_executes_the_exact_nested_bubblewrap_namespace_authority_check(self):
        with patch.object(validation, "inventory", return_value={}):
            commands = validation.build_plan("kernel", self.root)
        nested = [command for command in commands if command.name == "nested-netns"]
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0].argv, (
            "cargo", "test", "--locked", "-p", "browserd-sandbox", "--lib",
            "netns_listener_tests::parent_user_namespace_enters_the_exact_nested_bubblewrap_namespace",
            "--", "--ignored", "--exact",
        ))

    def test_fast_runs_all_artifact_fixture_regressions_without_launching_the_browser(self):
        commands = validation.build_plan("fast", SCRIPT.parent.parent)
        command = next(command for command in commands if command.name == "native-fixture-tests")
        self.assertEqual(command.argv, (
            "cargo", "test", "--locked", "-p", "browserd-worker",
            "--test", "live_chromium_emulation", "live_chromium::",
        ))

    def test_fast_requires_all_kernel_probe_preparation_regressions_exactly_once(self):
        root = SCRIPT.parent.parent
        commands = validation.build_plan("fast", root)
        required = {
            "kernel-probe-assets-tests": "test_prepare_kernel_probe_assets.py",
            "kernel-probe-seccomp-tests": "test_kernel_probe_seccomp.py",
            "kernel-probe-lab-tests": "test_kernel_probe_lab.py",
        }
        for name, pattern in required.items():
            with self.subTest(command=name):
                matches = [command for command in commands if command.name == name]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].argv, (
                    sys.executable, "-m", "unittest", "discover", "-s",
                    "scripts/tests", "-p", pattern,
                ))
                self.assertEqual(matches[0].cwd, root)
                self.assertTrue((root / "scripts/tests" / pattern).is_file())

    def test_adapter_rejects_wrong_protocol_without_disclosing_password(self):
        env = {
            "BROWSERD_REDIS_TEST_URL": "https://user:do-not-print@localhost",
            "BROWSERD_COORDINATION_TEST_DATABASE_URL": "postgres://localhost/browserd",
        }
        with self.assertRaises(validation.GateError) as result:
            validation.check_prerequisites("adapter", env, self.root)
        self.assertNotIn("do-not-print", str(result.exception))

    def test_kernel_requires_explicit_runner_even_on_linux(self):
        with self.assertRaisesRegex(validation.GateError, "BROWSERD_KERNEL_RUNNER"):
            validation.check_prerequisites("kernel", {}, self.root)

    def test_explicit_delegated_cgroup_is_accepted_without_assuming_process_cgroup(self):
        (self.root / "cgroup.controllers").write_text("cpu memory pids")
        (self.root / "cgroup.subtree_control").write_text("")
        env = {"BROWSERD_SOAK_RUNNER": sys.executable, "BROWSERD_TRUSTED_VALIDATION": "1",
               "BROWSERD_VALIDATION_CGROUP_ROOT": str(self.root),
               "BROWSERD_CHROMIUM_ARTIFACT_ROOT": str(self.root / "artifact")}
        with patch.object(validation.Path, "resolve", return_value=Path("/sys/fs/cgroup/delegated")), \
             patch.object(validation, "verify_artifact", return_value="a" * 64), \
             patch.object(validation.platform, "system", return_value="Linux"):
            result = validation.check_prerequisites("soak", env, self.root)
        self.assertEqual(result["manifest_sha256"], "a" * 64)

    def test_inventory_assigns_external_and_kernel_suites_once(self):
        root = SCRIPT.parent.parent
        inventory = validation.inventory(root)
        self.assertEqual(inventory[("browserd-coordination", "redis_gateway_actions")], "adapter")
        self.assertEqual(inventory[("browserd-sandbox", "linux_backend")], "kernel")
        self.assertEqual(inventory[("browserd-launch-gate", "launch_gate")], "process")
        self.assertEqual(inventory[("browserd-worker", "cdp_driver")], "fast")
        plan = validation.build_plan("adapter", root)
        commands = " ".join(" ".join(item.argv) for item in plan)
        for package, target in validation.ADAPTER_SUITES:
            package_commands = [command for command in plan if command.name == package]
            self.assertEqual(sum(command.argv.count(target) for command in package_commands), 1)
        self.assertNotIn("--workspace", commands)

    def test_fast_includes_viewer_and_kernel_owns_ignored_namespace_probe(self):
        root = SCRIPT.parent.parent
        fast = {command.name for command in validation.build_plan("fast", root)}
        self.assertTrue({"viewer-test", "viewer-check"}.issubset(fast))
        self.assertTrue({"device-tools-tests", "device-host-tests", "production-probe-tests"}.issubset(fast))
        self.assertIn("native-fixture-tests", fast)
        kernel = validation.build_plan("kernel", root)
        namespace = next(command for command in kernel if command.name == "foreign-netns")
        self.assertIn("--ignored", namespace.argv)
        self.assertIn("--exact", namespace.argv)

    def test_command_failure_records_exit_and_does_not_run_later_command(self):
        marker = self.root / "should-not-exist"
        commands = [
            validation.Command("failure", (sys.executable, "-c", "raise SystemExit(7)"), self.root),
            validation.Command("later", (sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"), self.root),
        ]
        run_dir, report = validation.execute("fast", commands, self.root / "logs", dict(os.environ))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["commands"][0]["exit_code"], 7)
        self.assertFalse(marker.exists())
        self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
        for path in run_dir.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads((run_dir / "report.json").read_text())["status"], "failed")

    def test_missing_executable_has_a_failed_report(self):
        command = validation.Command("missing", (str(self.root / "missing"),), self.root)
        _, report = validation.execute("fast", [command], self.root / "logs", dict(os.environ))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["commands"][0]["exit_code"], 127)

    def test_incomplete_external_kernel_or_soak_runner_blocks_without_passing(self):
        for tier in ("kernel", "soak"):
            with self.subTest(tier=tier):
                marker = self.root / (tier + "-later-command")
                commands = [
                    validation.Command(tier + "-real-browser", (sys.executable, "-c", "raise SystemExit(2)"), self.root),
                    validation.Command("later", (sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"), self.root),
                ]
                directory, report = validation.execute(tier, commands, self.root / "logs", dict(os.environ),
                                                        {"manifest_sha256": "a" * 64})
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(report["commands"][0]["exit_code"], 2)
                self.assertIn("incomplete", report["reason"])
                self.assertFalse(marker.exists())
                self.assertFalse((directory / "receipt.json").exists())

    def test_exit_two_cannot_disguise_an_ordinary_command_failure(self):
        for tier, name, qualification in [
            ("fast", "fast-real-browser", {"manifest_sha256": "a" * 64}),
            ("kernel", "ordinary-test", {"manifest_sha256": "a" * 64}),
            ("kernel", "kernel-real-browser", None),
        ]:
            with self.subTest(tier=tier, name=name, qualification=qualification):
                command = validation.Command(name, (sys.executable, "-c", "raise SystemExit(2)"), self.root)
                _, report = validation.execute(tier, [command], self.root / "logs", dict(os.environ), qualification)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["commands"][0]["exit_code"], 2)

    def test_timeout_is_a_failure_with_pid_and_exit_metadata(self):
        command = validation.Command("timeout", (sys.executable, "-c", "import time; time.sleep(60)"), self.root, 0.02)
        _, report = validation.execute("fast", [command], self.root / "logs", dict(os.environ))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["commands"][0]["exit_code"], 124)
        self.assertIsInstance(report["commands"][0]["pid"], int)

    def test_zero_exit_without_real_browser_receipt_does_not_pass(self):
        command = validation.Command("kernel-real-browser", (sys.executable, "-c", "pass"), self.root)
        _, report = validation.execute("kernel", [command], self.root / "logs", dict(os.environ),
                                       {"manifest_sha256": "a" * 64})
        self.assertEqual(report["status"], "failed")
        self.assertIn("receipt", report["reason"])
        self.assertIn("kernel_release", report)
        self.assertIn("machine", report)
        self.assertIn("source_revision", report)
        self.assertIsInstance(report["source_dirty"], bool)

    def test_artifact_hashes_are_checked_before_kernel_commands(self):
        artifact, _, _ = self.native_artifact()
        self.assertEqual(len(validation.verify_artifact(artifact)), 64)
        (artifact / "bin/chromium").write_bytes(b"changed bytes")
        with self.assertRaisesRegex(validation.GateError, "verification"):
            validation.verify_artifact(artifact)

    def test_receipt_rejects_skip_missing_probe_and_wrong_run(self):
        expected = {"run_id": "current", "tier": "kernel", "manifest_sha256": "a" * 64,
                    "kernel_release": "qualified-kernel", "machine": "x86_64"}
        receipt = dict(expected, probes={name: {"status": "passed", "evidence": "kernel-run.log"}
                                         for name in validation.KERNEL_PROBES})
        validation.validate_receipt(receipt, expected, 1)
        for mutation in [
            dict(receipt, run_id="old"),
            dict(receipt, kernel_release="different-kernel"),
            dict(receipt, probes={}),
            dict(receipt, probes={name: {"status": "skipped", "evidence": "none"}
                                  for name in validation.KERNEL_PROBES}),
        ]:
            with self.subTest(receipt=mutation):
                with self.assertRaises(validation.GateError):
                    validation.validate_receipt(mutation, expected, 1)

    def test_soak_cannot_claim_72_hours_after_a_short_command(self):
        expected = {"run_id": "current", "tier": "soak", "manifest_sha256": "a" * 64}
        receipt = dict(expected, probes={name: {"status": "passed", "evidence": "soak.log"}
                                         for name in validation.SOAK_PROBES})
        with self.assertRaisesRegex(validation.GateError, "72 hours"):
            validation.validate_receipt(receipt, expected, 10)
        validation.validate_receipt(receipt, expected, 72 * 60 * 60)

    def test_unconfigured_kernel_cli_writes_blocked_metadata(self):
        result = validation.main(["kernel", "--log-dir", str(self.root / "logs")], env={})
        self.assertEqual(result, 2)
        report = json.loads(next((self.root / "logs").glob("*/report.json")).read_text())
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["commands"], [])


if __name__ == "__main__":
    unittest.main()
