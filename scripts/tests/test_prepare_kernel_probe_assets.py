"""Offline asset handoff tests; never require root, launch services, or qualify."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "deploy/prepare-kernel-probe-assets.py"
spec = importlib.util.spec_from_file_location("prepare_kernel_probe_assets", SCRIPT)
provision = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = provision
spec.loader.exec_module(provision)


class AssetPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.addCleanup(self.restore_permissions)
        self.artifact = self.root / "artifact"
        self.artifact.mkdir()
        self.binary_dir = self.root / "binaries"
        self.binary_dir.mkdir()
        self.output = self.root / "prepared"
        catalog = {"schema_version": 1, "icu_data": "bin/icudtl.dat",
                   "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}],
                   "time_zones": ["Asia/Seoul", "UTC"]}
        self.files = {"bin/chromium": b"actual pinned browser", "bin/icudtl.dat": b"actual ICU",
                      "locales/ko.pak": b"actual Korean locale", "native-process-profiles.json": json.dumps(catalog).encode()}
        for name, data in self.files.items():
            path = self.artifact / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o500 if name == "bin/chromium" else 0o400)
        self.manifest = {"identity": {"binary_digest": provision.digest(self.files["bin/chromium"]),
                                      "launch_profile_digest": provision.digest(self.files["native-process-profiles.json"])},
                         "files": [{"relative_path": name, "digest": provision.digest(data)} for name, data in self.files.items()]}
        self.manifest_raw = (json.dumps(self.manifest, indent=3) + "\n").encode()
        (self.artifact / "compatibility.json").write_bytes(self.manifest_raw)
        (self.artifact / "provenance.json").write_bytes(b'{"qualification":"local_candidate"}\n')
        (self.artifact / "empty").mkdir()
        for name in [*provision.REQUIRED_BINARIES, "browser-worker"]:
            (self.binary_dir / name).write_bytes(("actual native " + name).encode())
            (self.binary_dir / name).chmod(0o700)
        self.source_identity = {"source_revision": "a" * 40, "source_dirty": True}

    def restore_permissions(self):
        for directory, names, files in os.walk(self.root, followlinks=False):
            Path(directory).chmod(0o700)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o600)

    def prepare(self, **options):
        with patch.object(provision.validation, "source_identity", return_value=self.source_identity), \
             patch.object(provision.validation, "source_content_identity", return_value="b" * 64):
            return provision.prepare(self.artifact, self.binary_dir, self.output, **options)

    def installer(self):
        module = types.ModuleType("prepared_asset_installer")
        exec(compile((self.output / "install-assets.py").read_bytes(), "install-assets.py", "exec"), module.__dict__)
        return module

    def simulated_root_install(self, installer, destination, **options):
        """Only ownership/ancestor checks are mocked; checksum/copy/publish run."""
        parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        # The installer owns and closes this duplicate itself.
        try:
            with patch.object(installer.os, "geteuid", return_value=0), \
                 patch.object(installer, "safe_destination_parent", return_value=([os.dup(parent_fd)], [])), \
                 patch.object(installer.os, "fchown") as chown:
                result = installer.install_prepared(self.output)
                self.assertTrue(chown.called)
                self.assertTrue(all(call.args[1:] == (0, 0) for call in chown.call_args_list))
                return result
        finally:
            os.close(parent_fd)

    def test_preparation_preserves_exact_manifest_and_all_artifact_bytes(self):
        result = self.prepare()
        copied = self.output / "assets/chromium"
        self.assertEqual((copied / "compatibility.json").read_bytes(), self.manifest_raw)
        self.assertEqual((copied / "provenance.json").read_bytes(), (self.artifact / "provenance.json").read_bytes())
        self.assertTrue((copied / "empty").is_dir())
        for name, data in self.files.items():
            self.assertEqual((copied / name).read_bytes(), data)
            self.assertNotEqual((copied / name).stat().st_ino, (self.artifact / name).stat().st_ino)
        self.assertEqual(result["manifest_sha256"], provision.digest(self.manifest_raw))
        self.assertEqual(result["status"], "prepared")
        self.assertFalse(result["operator_approval"])
        self.assertFalse(result["production_qualified"])
        self.assertEqual(result["source_revision"], "a" * 40)
        self.assertEqual(result["source_content_sha256"], "b" * 64)
        self.assertFalse(Path(result["install_destination"]).exists())
        self.assertFalse((self.output / "assets/bin/browser-worker").exists())

    def test_inventory_is_complete_and_runtime_mounts_pin_every_copied_file(self):
        result = self.prepare()
        inventory_raw = (self.output / "inventory.json").read_bytes()
        inventory = json.loads(inventory_raw)
        self.assertEqual(result["inventory_sha256"], provision.digest(inventory_raw))
        assets = self.output / "assets"
        actual = {str(path.relative_to(assets)) for path in assets.rglob("*") if path.is_file()}
        expected = {entry["relative_path"] for entry in inventory["files"]}
        self.assertEqual(actual, expected)
        for entry in inventory["files"]:
            path = assets / entry["relative_path"]
            self.assertEqual(provision.digest(path.read_bytes()), entry["sha256"])
            self.assertEqual(path.stat().st_size, entry["size"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), entry["mode"] & 0o700)
        runtime = json.loads((assets / "kernel-probe-runtime-manifest.json").read_bytes())
        runtime_files = {}
        for mount in runtime["mounts"]:
            self.assertEqual(mount["source"], mount["destination"])
            prefix = Path(mount["source"]).name
            runtime_files.update({prefix + "/" + entry["relative_path"]: entry["sha256"] for entry in mount["files"]})
        self.assertEqual(runtime_files, {entry["relative_path"]: entry["sha256"] for entry in inventory["files"]
                                        if entry["relative_path"] != "kernel-probe-runtime-manifest.json"})

    def test_output_and_metadata_are_private_and_payload_is_read_only(self):
        self.prepare()
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for name in ("inventory.json", "preparation.json", "install-assets.py", "install-command.txt"):
            self.assertEqual(stat.S_IMODE((self.output / name).stat().st_mode), 0o600)
        for path in (self.output / "assets").rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o222)
            self.assertFalse(path.stat().st_mode & 0o077)

    def test_content_based_default_destination_is_independent_of_output_path(self):
        first = self.prepare()
        self.output = self.root / "second-prepared"
        second = self.prepare()
        self.assertEqual(first["asset_content_sha256"], second["asset_content_sha256"])
        self.assertEqual(first["install_destination"], second["install_destination"])
        self.assertEqual(Path(first["install_destination"]).name, first["asset_content_sha256"])

    def test_optional_worker_is_copied_only_when_requested(self):
        self.prepare(include_worker=True)
        self.assertEqual((self.output / "assets/bin/browser-worker").read_bytes(), (self.binary_dir / "browser-worker").read_bytes())

    def test_existing_output_is_never_modified(self):
        self.output.mkdir()
        (self.output / "marker").write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual((self.output / "marker").read_bytes(), b"preserve")

    def test_missing_or_nonexecutable_native_binary_cannot_prepare(self):
        path = self.binary_dir / provision.REQUIRED_BINARIES[0]
        path.chmod(0o600)
        with self.assertRaisesRegex(provision.PreparationError, "executable"):
            self.prepare()
        self.assertFalse(self.output.exists())
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_artifact_digest_mismatch_cannot_prepare(self):
        path = self.artifact / "bin/icudtl.dat"
        path.chmod(0o600)
        path.write_bytes(b"changed bytes")
        with self.assertRaises(provision.validation.GateError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_symlink_and_fifo_in_artifact_are_rejected_without_traversal(self):
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind):
                path = self.artifact / "unsafe"
                if kind == "symlink":
                    path.symlink_to(self.binary_dir)
                else:
                    os.mkfifo(path)
                with self.assertRaisesRegex(provision.PreparationError, "symlinks or special"):
                    self.prepare()
                self.assertFalse(self.output.exists())
                path.unlink()

    def test_symlink_source_and_output_ancestors_are_rejected(self):
        link = self.root / "linked"
        link.symlink_to(self.artifact, target_is_directory=True)
        with self.assertRaises(OSError):
            provision.prepare(link, self.binary_dir, self.output)
        link.unlink()
        link.symlink_to(self.root, target_is_directory=True)
        self.output = link / "prepared"
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse((self.root / "prepared").exists())

    def test_relative_dot_and_overlapping_paths_are_rejected(self):
        for value in ("relative/path", str(self.root / ".." / "escape")):
            with self.subTest(value=value), self.assertRaises(provision.PreparationError):
                provision.absolute_path(value)
        self.output = self.artifact / "output"
        with self.assertRaisesRegex(provision.PreparationError, "separate"):
            self.prepare()

    def test_install_destination_cannot_overlap_source_or_output(self):
        with self.assertRaisesRegex(provision.PreparationError, "separate"):
            self.prepare(install_destination=self.artifact / "installation")
        self.assertFalse(self.output.exists())
        self.assertEqual((self.artifact / "compatibility.json").read_bytes(), self.manifest_raw)

    def test_artifact_race_fails_and_removes_only_new_output(self):
        original = provision.copy_file
        changed = False

        def race(root_fd, relative, target, expected):
            nonlocal changed
            result = original(root_fd, relative, target, expected)
            if relative == "compatibility.json" and not changed:
                changed = True
                (self.artifact / "raced-file").write_bytes(b"new source entry")
            return result

        with patch.object(provision, "copy_file", side_effect=race), \
             self.assertRaisesRegex(provision.PreparationError, "source artifact changed"):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertTrue((self.artifact / "raced-file").exists())

    def test_copied_artifact_digest_drift_cannot_publish_preparation(self):
        original = provision.copy_file

        def corrupt(root_fd, relative, target, expected):
            result = original(root_fd, relative, target, expected)
            if relative == "bin/chromium":
                target.chmod(0o700)
                target.write_bytes(b"wrong copied executable")
            return result

        with patch.object(provision, "copy_file", side_effect=corrupt), \
             self.assertRaises(provision.validation.GateError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_native_binary_race_cannot_publish_preparation(self):
        original = provision.copy_file

        def race(root_fd, relative, target, expected):
            result = original(root_fd, relative, target, expected)
            if relative == "browserd-kernel-probe":
                (self.binary_dir / relative).write_bytes(b"raced native binary")
            return result

        with patch.object(provision, "copy_file", side_effect=race), \
             self.assertRaisesRegex(provision.PreparationError, "source binary changed"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_root_command_authenticates_installer_before_executing_it(self):
        result = self.prepare()
        args = shlex.split((self.output / "install-command.txt").read_text())
        self.assertEqual(args[:3], ["/usr/bin/python3", "-I", "-c"])
        self.assertEqual(args[5], result["installer_sha256"])
        self.assertEqual(provision.digest(Path(args[4]).read_bytes()), args[5])
        self.assertIn("O_NOFOLLOW", args[3])
        self.assertIn("installer checksum mismatch", args[3])

    def test_installer_refuses_nonroot_before_any_installation(self):
        self.prepare()
        installer = self.installer()
        with patch.object(installer.os, "geteuid", return_value=1003), \
             patch.object(installer, "open_directory") as open_directory, \
             self.assertRaisesRegex(installer.PreparationError, "root shell"):
            installer.install_prepared(self.output)
        open_directory.assert_not_called()

    def test_tampered_inventory_is_rejected_before_destination_access(self):
        self.prepare()
        installer = self.installer()
        (self.output / "inventory.json").write_bytes(b"tampered inventory")
        with patch.object(installer.os, "geteuid", return_value=0), \
             patch.object(installer, "safe_destination_parent") as destination, \
             self.assertRaisesRegex(installer.PreparationError, "reviewed checksum"):
            installer.install_prepared(self.output)
        destination.assert_not_called()

    def test_extra_file_or_symlink_in_prepared_assets_is_rejected(self):
        self.prepare()
        installer = self.installer()
        assets = self.output / "assets"
        assets.chmod(0o700)
        extra = assets / "extra"
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind):
                if kind == "file":
                    extra.write_bytes(b"unlisted")
                    extra.chmod(0o400)
                else:
                    extra.symlink_to(self.artifact)
                with patch.object(installer.os, "geteuid", return_value=0), \
                     patch.object(installer, "safe_destination_parent") as destination, \
                     self.assertRaises(installer.PreparationError):
                    installer.install_prepared(self.output)
                destination.assert_not_called()
                extra.unlink()

    def test_prepared_mode_drift_is_rejected_before_destination_access(self):
        self.prepare()
        installer = self.installer()
        (self.output / "assets/bin/browserd-kernel-probe").chmod(0o700)
        with patch.object(installer.os, "geteuid", return_value=0), \
             patch.object(installer, "safe_destination_parent") as destination, \
             self.assertRaisesRegex(installer.PreparationError, "private ownership and modes"):
            installer.install_prepared(self.output)
        destination.assert_not_called()

    def test_installer_rejects_world_writable_destination_ancestor(self):
        self.prepare()
        installer = self.installer()
        with self.assertRaisesRegex(installer.PreparationError, "root-owned and not writable"):
            installer.safe_destination_parent(self.root / "new-assets")

    def test_installer_copies_exact_bytes_and_publishes_read_only_tree(self):
        destination = self.root / "installed"
        result = self.prepare(install_destination=destination)
        installer = self.installer()
        installed = self.simulated_root_install(installer, destination)
        self.assertEqual(installed["status"], "installed")
        self.assertFalse(installed["operator_approval"])
        self.assertFalse(installed["production_qualified"])
        self.assertEqual(installed["inventory_sha256"], result["inventory_sha256"])
        inventory = json.loads((self.output / "inventory.json").read_bytes())
        for entry in inventory["files"]:
            path = destination / entry["relative_path"]
            self.assertEqual(provision.digest(path.read_bytes()), entry["sha256"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), entry["mode"])
        for name in ["", *inventory["directories"]]:
            self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o555)
        self.assertEqual(list(self.root.glob(".installed.install-*")), [])

    def test_installer_never_replaces_existing_destination(self):
        destination = self.root / "installed"
        self.prepare(install_destination=destination)
        destination.mkdir()
        (destination / "marker").write_bytes(b"preserve")
        installer = self.installer()
        with self.assertRaisesRegex(installer.PreparationError, "already exists"):
            self.simulated_root_install(installer, destination)
        self.assertEqual((destination / "marker").read_bytes(), b"preserve")

    def test_root_checksum_failure_cleans_partial_tree_and_keeps_sources(self):
        destination = self.root / "installed"
        self.prepare(install_destination=destination)
        path = self.output / "assets/bin/browserd-kernel-probe"
        path.chmod(0o700)
        path.write_bytes(b"tampered executable")
        path.chmod(0o500)
        installer = self.installer()
        with self.assertRaisesRegex(installer.PreparationError, "checksum or mode"):
            self.simulated_root_install(installer, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".installed.install-*")), [])
        self.assertEqual(path.read_bytes(), b"tampered executable")

    def test_atomic_publish_cannot_replace_raced_destination(self):
        destination = self.root / "installed"
        self.prepare(install_destination=destination)
        installer = self.installer()
        original = installer.publish_new

        def race(source, target, parent_fd):
            destination.mkdir()
            (destination / "marker").write_bytes(b"keep raced destination")
            return original(source, target, parent_fd)

        with patch.object(installer, "publish_new", side_effect=race), self.assertRaises(FileExistsError):
            self.simulated_root_install(installer, destination)
        self.assertEqual((destination / "marker").read_bytes(), b"keep raced destination")
        self.assertEqual(list(self.root.glob(".installed.install-*")), [])


if __name__ == "__main__":
    unittest.main()
