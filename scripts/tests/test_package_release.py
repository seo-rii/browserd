"""Offline filesystem tests: no compiler, package installation, or services are started."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "package_release.py"
spec = importlib.util.spec_from_file_location("package_release", SCRIPT)
release = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = release
spec.loader.exec_module(release)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def chromium_artifact(self, *, catalog=None, extra_files=None):
        artifact = self.root / "artifact"
        artifact.mkdir(exist_ok=True)
        resources = {"chrome-headless-shell": b"pinned", "icudtl.dat": b"approved ICU",
                     "locales/ko.pak": b"approved locale pack"}
        resources.update(extra_files or {})
        if catalog is None:
            catalog = {"schema_version": 1, "icu_data": "icudtl.dat",
                       "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}],
                       "time_zones": ["Asia/Seoul", "UTC"]}
        raw_catalog = json.dumps(catalog, sort_keys=True).encode()
        resources["native-process-profiles.json"] = raw_catalog
        identity = {"binary_digest": hashlib.sha256(resources["chrome-headless-shell"]).hexdigest(),
                    "product_version": "HeadlessChrome/153.0.8010.12", "chromium_revision": "1" * 40,
                    "launch_profile_digest": hashlib.sha256(raw_catalog).hexdigest()}
        identity.update({name: "a" * 64 for name in (
            "browser_protocol_schema_digest", "js_protocol_schema_digest", "extension_bundle_digest",
            "font_bundle_digest", "certificate_runtime_bundle_digest")})
        manifest = {"identity": identity, "files": [
            {"relative_path": name, "digest": hashlib.sha256(data).hexdigest()}
            for name, data in resources.items()]}
        for name, data in resources.items():
            path = artifact / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        return artifact, manifest, resources

    def test_archive_order_timestamps_permissions_and_bytes_are_deterministic(self):
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"
        entries = {"bin/browser-worker": (b"binary", 0o755), "viewer/index.html": (b"html", 0o644)}
        release.write_archive(first, entries, 1700000000)
        release.write_archive(second, dict(reversed(list(entries.items()))), 1700000000)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            self.assertEqual(archive.getnames(), sorted(entries))
            for item in archive.getmembers():
                self.assertEqual((item.mtime, item.uid, item.gid), (1700000000, 0, 0))
                self.assertEqual((item.uname, item.gname), ("", ""))

    def test_archive_refuses_secret_runtime_and_traversal_entries(self):
        for name in [".env", "deploy/production.env", "runtime/session.json", "logs/error.log", "../escaped", "sdk/.git/config", "/absolute"]:
            with self.subTest(name=name), self.assertRaises(release.PackageError):
                release.write_archive(self.root / "bad.tar.gz", {name: (b"secret", 0o644)}, 1)
        with self.assertRaises(release.PackageError):
            release.write_archive(self.root / "private.tar.gz", {"chromium/key.txt": (b"-----BEGIN PRIVATE KEY-----", 0o644)}, 1)

    def test_input_symlinks_are_not_followed(self):
        (self.root / "data").write_text("value")
        (self.root / "link").symlink_to(self.root / "data")
        with self.assertRaises(release.PackageError):
            release.read_input(self.root / "link")

    def test_binary_pem_parser_markers_are_not_mistaken_for_embedded_keys(self):
        binary = self.root / "binary"
        binary.write_bytes(b"\x7fELF\x00PEM parser: -----BEGIN PRIVATE KEY-----")
        self.assertEqual(release.read_input(binary), binary.read_bytes())
        release.write_archive(self.root / "binary.tar.gz", {"bin/browser-worker": (binary.read_bytes(), 0o555)}, 1)

    def test_artifact_inventory_verifies_every_declared_digest(self):
        artifact, _, resources = self.chromium_artifact()
        entries, _ = release.chromium_entries(artifact)
        self.assertEqual(entries["chromium/chrome-headless-shell"][0], b"pinned")
        for name, data in resources.items():
            with self.subTest(resource=name):
                (artifact / name).write_bytes(b"modified")
                with self.assertRaises(release.PackageError):
                    release.chromium_entries(artifact)
                (artifact / name).write_bytes(data)

    def test_native_profile_catalog_is_required_for_packaging(self):
        artifact, manifest, _ = self.chromium_artifact()
        manifest["files"] = [item for item in manifest["files"]
                             if item["relative_path"] != "native-process-profiles.json"]
        (artifact / "compatibility.json").write_text(json.dumps(manifest))
        with self.assertRaises(release.PackageError):
            release.chromium_entries(artifact)

    def test_native_catalog_schema_resources_and_binary_mapping_are_bound(self):
        for defect in ("schema", "unlisted-resource", "catalog-digest", "ambiguous-binary"):
            with self.subTest(defect=defect):
                catalog = {"schema_version": 2 if defect == "schema" else 1,
                           "icu_data": "icudtl.dat",
                           "locales": [{"locale": "ko-KR", "pak": "locales/missing.pak"
                                        if defect == "unlisted-resource" else "locales/ko.pak"}],
                           "time_zones": ["Asia/Seoul"]}
                extra = {"duplicate-binary": b"pinned"} if defect == "ambiguous-binary" else None
                artifact, manifest, _ = self.chromium_artifact(catalog=catalog, extra_files=extra)
                if defect == "catalog-digest":
                    manifest["identity"]["launch_profile_digest"] = "b" * 64
                    (artifact / "compatibility.json").write_text(json.dumps(manifest))
                with self.assertRaises(release.PackageError):
                    release.chromium_entries(artifact)

    def test_archive_contains_exact_verified_native_profile_resources(self):
        artifact, _, resources = self.chromium_artifact()
        manifest_bytes = (artifact / "compatibility.json").read_bytes()
        entries, digest = release.chromium_entries(artifact)
        self.assertEqual(digest, hashlib.sha256(manifest_bytes).hexdigest())
        output = self.root / "native-profile.tar.gz"
        release.write_archive(output, entries, 1700000000)
        with tarfile.open(output) as archive:
            self.assertEqual(set(archive.getnames()), {"chromium/compatibility.json",
                                                     *["chromium/" + name for name in resources]})
            for name, data in resources.items():
                self.assertEqual(archive.extractfile("chromium/" + name).read(), data)

    def test_packaging_rejects_manifest_replacement_after_initial_verification(self):
        artifact, manifest, _ = self.chromium_artifact()
        original_read = release.read_input
        changed = json.dumps(dict(manifest, identity=dict(manifest["identity"],
                                                       product_version="HeadlessChrome/replaced"))).encode()

        def replaced_manifest(path):
            return changed if path == artifact / "compatibility.json" else original_read(path)

        with patch.object(release, "read_input", side_effect=replaced_manifest), \
                self.assertRaises(release.PackageError):
            release.chromium_entries(artifact)

    def test_packaging_checks_catalog_bytes_selected_for_archive(self):
        artifact, _, resources = self.chromium_artifact()
        original_read = release.read_input
        changed = resources["native-process-profiles.json"] + b"\n"

        def replaced_catalog(path):
            return changed if path == artifact / "native-process-profiles.json" else original_read(path)

        with patch.object(release, "read_input", side_effect=replaced_catalog), \
                self.assertRaises(release.PackageError):
            release.chromium_entries(artifact)

    def test_archived_native_catalog_is_validated_after_initial_verification(self):
        artifact, _, _ = self.chromium_artifact(catalog={
            "schema_version": 2, "icu_data": "icudtl.dat",
            "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}],
            "time_zones": ["Asia/Seoul"]})
        digest = hashlib.sha256((artifact / "compatibility.json").read_bytes()).hexdigest()
        # Isolate packaging's own catalog check: all archived bytes match the
        # manifest, but the catalog must also satisfy the native launch contract.
        with patch.object(release.validation, "verify_artifact", return_value=digest), \
                self.assertRaises(release.PackageError):
            release.chromium_entries(artifact)

    def test_source_policy_rejects_dirty_release_but_labels_dev_explicitly(self):
        with self.assertRaises(release.PackageError):
            release.source_policy({"revision": "a" * 40, "dirty": True}, False)
        self.assertEqual(release.source_policy({"revision": "a" * 40, "dirty": True}, True), "development-unqualified")
        self.assertEqual(release.source_policy({"revision": "a" * 40, "dirty": False}, False), "release-candidate")

    def test_qualification_requires_all_current_clean_gates_and_matching_kernel_artifact(self):
        source = {"revision": "a" * 40, "dirty": False}
        reports = [{"tier": tier, "status": "passed", "source_revision": source["revision"], "source_dirty": False,
                    "kernel_release": "kernel-a", "machine": "x86_64", "manifest_sha256": "b" * 64,
                    "probes": list(release.validation.KERNEL_PROBES if tier == "kernel" else release.validation.SOAK_PROBES if tier == "soak" else []),
                    "commands": [{"exit_code": 0, "duration_seconds": 72 * 3600 if tier == "soak" else 1}]} for tier in release.TIERS]
        result = release.qualification(reports, source, "b" * 64, True)
        self.assertTrue(result["qualified"])
        for changed in [reports[:-1], [dict(item, source_dirty=True) for item in reports],
                        [dict(item, source_revision="c" * 40) for item in reports],
                        [dict(item, manifest_sha256="d" * 64) for item in reports],
                        [dict(item, status="blocked") for item in reports]]:
            self.assertFalse(release.qualification(changed, source, "b" * 64, True)["qualified"])
        changed = [dict(item, kernel_release="kernel-b") if item["tier"] == "soak" else item for item in reports]
        self.assertFalse(release.qualification(changed, source, "b" * 64, True)["qualified"])
        self.assertFalse(release.qualification(reports, source, "b" * 64, False)["qualified"])
        missing_probes = [dict(item, probes=[]) if item["tier"] == "kernel" else item for item in reports]
        self.assertFalse(release.qualification(missing_probes, source, "b" * 64, True)["qualified"])

    def test_report_sanitization_does_not_bundle_environment_or_private_logs(self):
        report = {"tier": "fast", "status": "passed", "source_revision": "a" * 40, "source_dirty": False,
                  "environment": {"API_KEY": "secret-value"}, "commands": [{"exit_code": 0, "log": "/private/secret.log"}]}
        sanitized = release.public_gate_report(report)
        self.assertNotIn("secret", json.dumps(sanitized))

    def test_wheel_normalization_rejects_secret_members_and_uses_fixed_metadata(self):
        wheel = self.root / "client.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("browserd/__init__.py", "client")
            archive.writestr("browserd_client-0.1.0.dist-info/METADATA", "metadata")
        one = release.normalized_wheel(wheel, 1700000000)
        two = release.normalized_wheel(wheel, 1700000000)
        self.assertEqual(one, two)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("browserd/.env", "TOKEN=secret")
        with self.assertRaises(release.PackageError):
            release.normalized_wheel(wheel, 1700000000)

    def test_payload_staging_includes_only_declared_assets(self):
        repo = self.root / "repo"
        binaries = self.root / "binaries"
        for path in [binaries, repo / "sdk/typescript/dist", repo / "sdk/python/browserd", repo / "viewer-web/src", repo / "deploy"]:
            path.mkdir(parents=True)
        for name in release.BINARIES:
            (binaries / name).write_bytes(b"executable")
            (binaries / name).chmod(0o755)
        for name in ["sdk/typescript/dist/index.js", "sdk/typescript/dist/index.d.ts", "sdk/typescript/package.json", "sdk/typescript/README.md", "sdk/python/README.md", "viewer-web/index.html", "viewer-web/styles.css", "viewer-web/src/app.mjs"]:
            (repo / name).write_text("asset")
        (repo / "sdk/python/browserd/__init__.py").write_text("client")
        (repo / ".env").write_text("SECRET=must-not-bundle")
        (repo / "deploy/.env.example").write_text("BROWSERD_AUTH_HMAC_SECRET=REPLACE_SECRET\n")
        artifact, _, _ = self.chromium_artifact()
        wheel = self.root / "client.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("browserd/__init__.py", "client")
            archive.writestr("browserd_client-0.1.0.dist-info/METADATA", "Name: browserd-client\nVersion: 0.1.0\n")
            archive.writestr("browserd_client-0.1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
            archive.writestr("browserd_client-0.1.0.dist-info/RECORD", "")
        with patch.object(release, "ROOT", repo):
            entries, _ = release.collect_payload(binaries, wheel, artifact, 1700000000)
        self.assertIn("bin/browser-sandboxd", entries)
        self.assertIn("sdk/python/client.whl", entries)
        self.assertIn("viewer/src/app.mjs", entries)
        self.assertFalse(any(b"must-not-bundle" in data for data, _mode in entries.values()))
        output = self.root / "development.tar.gz"
        with patch.object(release, "ROOT", repo), \
             patch.object(release.validation, "source_identity", return_value={"source_revision": "a" * 40, "source_dirty": True}), \
             patch.object(release.subprocess, "check_output", return_value="1700000000\n"):
            code = release.main(["--binary-dir", str(binaries), "--python-wheel", str(wheel),
                                 "--chromium-artifact-root", str(artifact), "--dev-dirty", "--output", str(output)])
        self.assertEqual(code, 0)
        with tarfile.open(output) as archive:
            manifest = json.load(archive.extractfile("manifest.json"))
        self.assertFalse(manifest["deployment"]["qualified"])
        self.assertEqual(manifest["candidate"], "development-unqualified")

    def test_epoch_helper_reads_both_actual_formats_without_mutating_state(self):
        helper_spec = importlib.util.spec_from_file_location("next_epochs", SCRIPT.parent.parent / "deploy/next_epochs.py")
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        worker = self.root / "worker.epoch"
        daemon = self.root / "daemon.epoch"
        worker.write_text("7\n")
        daemon.write_text("browserd-egressd-daemon-epoch-v1\n11\n")
        self.assertEqual(helper.next_epoch(worker, daemon=False), 8)
        self.assertEqual(helper.next_epoch(daemon, daemon=True), 12)
        self.assertEqual(helper.next_epoch(self.root / "first-boot", daemon=True), 1)
        self.assertEqual(worker.read_text(), "7\n")
        self.assertEqual(daemon.read_text(), "browserd-egressd-daemon-epoch-v1\n11\n")
        daemon.write_text("11\n")
        with self.assertRaises(ValueError):
            helper.next_epoch(daemon, daemon=True)


if __name__ == "__main__":
    unittest.main()
