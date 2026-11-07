"""Offline candidate provisioning tests; never start a browser or obtain privileges."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "prepare_device_artifact.py"
spec = importlib.util.spec_from_file_location("prepare_device_artifact", SCRIPT)
provision = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = provision
spec.loader.exec_module(provision)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.binary = self.source / "chrome-headless-shell"
        self.binary.write_bytes(b"pinned executable")
        self.binary.chmod(0o700)
        (self.source / "icudtl.dat").write_bytes(b"actual ICU")
        (self.source / "locales").mkdir()
        (self.source / "locales/ko.pak").write_bytes(b"actual Korean pack")
        (self.source / "locales/en-US.pak").write_bytes(b"actual English pack")
        self.destination = self.root / "private/candidate"
        self.library = self.root / "actual-library.so"
        self.font = self.root / "actual-font.ttf"
        self.certificate = self.root / "actual-ca.crt"
        for path, data in [(self.library, b"actual library"), (self.font, b"actual font"),
                           (self.certificate, b"actual certificate")]:
            path.write_bytes(data)
        self.observation = {
            "version": {"product": "HeadlessChrome/153.0.8010.12", "revision": "revision-from-CDP",
                        "protocolVersion": "1.3", "jsVersion": "15.3", "userAgent": "actual-UA"},
            "protocol": {"version": {"major": "1", "minor": "3"},
                         "domains": [{"domain": "Browser", "commands": [{"name": "getVersion"}]},
                                     {"domain": "Runtime", "commands": [{"name": "evaluate"}]}]},
            "launch_arguments": [["--remote-debugging-pipe"],
                                 ["--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1"]],
        }

    def collect(self, binary, work):
        self.assertEqual(binary.name, "chrome-headless-shell")
        self.assertEqual(binary.read_bytes(), b"pinned executable")
        self.assertNotEqual(binary.stat().st_ino, self.binary.stat().st_ino)
        return self.observation

    def inventories(self, binary):
        return {"libraries": [self.library], "fonts": [self.font], "certificates": [self.certificate]}

    def prepare(self, **kwargs):
        return provision.prepare(self.binary, self.destination, collect=self.collect,
                                 inventory=self.inventories, **kwargs)

    def restore_writable(self):
        if self.destination.exists():
            for path in [self.destination, *self.destination.rglob("*")]:
                path.chmod(0o700 if path.is_dir() else 0o600)

    def test_candidate_binds_observed_identity_and_exact_copied_files(self):
        result = self.prepare()
        self.addCleanup(self.restore_writable)
        manifest = json.loads((self.destination / "compatibility.json").read_bytes())
        self.assertEqual(set(manifest), {"identity", "files"})
        identity = manifest["identity"]
        self.assertEqual(identity["product_version"], "153.0.8010.12")
        self.assertEqual(identity["chromium_revision"], "revision-from-CDP")
        for entry in manifest["files"]:
            path = self.destination / entry["relative_path"]
            self.assertEqual(entry["digest"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertFalse(path.is_symlink())
        self.assertEqual(identity["binary_digest"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(result["manifest_sha256"], hashlib.sha256((self.destination / "compatibility.json").read_bytes()).hexdigest())
        for identity_key, name in [
            ("browser_protocol_schema_digest", "protocol/browser.json"),
            ("js_protocol_schema_digest", "protocol/js.json"),
            ("extension_bundle_digest", "bundles/extensions.json"),
            ("font_bundle_digest", "bundles/fonts.json"),
            ("certificate_runtime_bundle_digest", "bundles/certificate-runtime.json")]:
            self.assertEqual(identity[identity_key], hashlib.sha256((self.destination / name).read_bytes()).hexdigest())
        provenance = json.loads((self.destination / "provenance.json").read_bytes())
        self.assertEqual(provenance["qualification"], "local_candidate")
        self.assertFalse(provenance["operator_approval"])
        self.assertFalse(provenance["production_qualified"])
        self.assertNotIn("provenance.json", [entry["relative_path"] for entry in manifest["files"]])
        self.assertEqual(provenance["browser_version"], self.observation["version"])
        self.assertEqual(provenance["launch_arguments"], self.observation["launch_arguments"])
        self.assertEqual(json.loads((self.destination / "protocol/combined.json").read_bytes()), self.observation["protocol"])

    def test_chromium_brand_uses_version_only_identity_and_retains_raw_observation(self):
        self.observation["version"]["product"] = "Chromium/153.0.8010.12"
        self.prepare()
        self.addCleanup(self.restore_writable)
        manifest = json.loads((self.destination / "compatibility.json").read_bytes())
        provenance = json.loads((self.destination / "provenance.json").read_bytes())
        self.assertEqual(manifest["identity"]["product_version"], "153.0.8010.12")
        self.assertEqual(provenance["browser_version"]["product"], "Chromium/153.0.8010.12")

    def test_invalid_browser_product_cannot_create_a_candidate(self):
        for product in ["153.0.8010.12", "Chrome/", "Chrome/153/extra", "Other/153"]:
            with self.subTest(product=product):
                self.observation["version"]["product"] = product
                try:
                    with self.assertRaisesRegex(provision.ProvisionError, "product"):
                        self.prepare()
                    self.assertFalse(self.destination.exists())
                    self.assertEqual(self.binary.read_bytes(), b"pinned executable")
                finally:
                    self.restore_writable()
                    if self.destination.exists():
                        shutil.rmtree(self.destination)

    def test_cache_changes_cannot_modify_copied_candidate(self):
        self.prepare()
        self.addCleanup(self.restore_writable)
        original = (self.destination / self.binary.name).read_bytes()
        self.binary.write_bytes(b"modified source")
        self.assertEqual((self.destination / self.binary.name).read_bytes(), original)
        self.assertNotEqual(self.binary.stat().st_ino, (self.destination / self.binary.name).stat().st_ino)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.destination / self.binary.name).stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((self.destination / "compatibility.json").stat().st_mode), 0o400)

    def test_native_catalog_uses_exact_locale_resources_and_allowlist(self):
        self.prepare()
        self.addCleanup(self.restore_writable)
        catalog = json.loads((self.destination / "native-process-profiles.json").read_bytes())
        self.assertEqual(catalog, {"schema_version": 1, "icu_data": "icudtl.dat",
                                  "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"},
                                              {"locale": "en-US", "pak": "locales/en-US.pak"}],
                                  "time_zones": ["Asia/Seoul", "UTC"]})
        manifest = json.loads((self.destination / "compatibility.json").read_bytes())
        provision.validate_native_catalog(manifest, (self.destination / "native-process-profiles.json").read_bytes())

    def test_bundle_inventories_record_original_paths_and_file_digests(self):
        self.prepare()
        self.addCleanup(self.restore_writable)
        inventory = json.loads((self.destination / "bundles/certificate-runtime.json").read_bytes())
        self.assertEqual({entry["kind"] for entry in inventory["files"]}, {"library", "certificate"})
        for entry in inventory["files"]:
            original = Path(entry["source_path"])
            self.assertEqual(entry["digest"], hashlib.sha256(original.read_bytes()).hexdigest())
            copied = self.destination / entry["relative_path"]
            self.assertEqual(copied.read_bytes(), original.read_bytes())
            self.assertNotEqual(copied.stat().st_ino, original.stat().st_ino)
        fonts = json.loads((self.destination / "bundles/fonts.json").read_bytes())
        self.assertEqual(fonts["files"][0]["source_path"], str(self.font))

    def test_existing_destination_is_never_replaced_or_removed(self):
        self.destination.mkdir(parents=True)
        marker = self.destination / "existing"
        marker.write_bytes(b"keep")
        with self.assertRaises(provision.ProvisionError):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_failed_browser_collection_removes_only_new_partial_candidate(self):
        def failed_collect(binary, work):
            raise provision.ProvisionError("browser unavailable")
        with self.assertRaisesRegex(provision.ProvisionError, "browser unavailable"):
            provision.prepare(self.binary, self.destination, collect=failed_collect, inventory=self.inventories)
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.binary.read_bytes(), b"pinned executable")

    def test_missing_required_icu_or_korean_pack_fails_and_cleans(self):
        for relative in ["icudtl.dat", "locales/ko.pak"]:
            with self.subTest(relative=relative):
                path = self.source / relative
                contents = path.read_bytes()
                path.unlink()
                with self.assertRaises(provision.ProvisionError):
                    self.prepare()
                self.assertFalse(self.destination.exists())
                path.write_bytes(contents)

    def test_source_symlink_and_nonregular_resources_are_rejected(self):
        for kind in ["symlink", "fifo"]:
            with self.subTest(kind=kind):
                path = self.source / "unsafe"
                if kind == "symlink":
                    path.symlink_to(self.library)
                else:
                    os.mkfifo(path)
                with self.assertRaises(provision.ProvisionError):
                    self.prepare()
                self.assertFalse(self.destination.exists())
                path.unlink()

    def test_missing_or_duplicate_real_schema_domains_are_rejected(self):
        for domains in [[{"domain": "Browser"}], [{"domain": "Runtime"}],
                        [{"domain": "Browser"}, {"domain": "Runtime"}, {"domain": "Runtime"}]]:
            with self.subTest(domains=domains):
                previous = self.observation["protocol"]["domains"]
                self.observation["protocol"]["domains"] = domains
                with self.assertRaises(provision.ProvisionError):
                    self.prepare()
                self.assertFalse(self.destination.exists())
                self.observation["protocol"]["domains"] = previous

    def test_missing_runtime_inventory_cannot_fabricate_bundle_identity(self):
        for kind in ["libraries", "fonts", "certificates"]:
            with self.subTest(kind=kind):
                def missing(binary):
                    result = self.inventories(binary)
                    result[kind] = []
                    return result
                with self.assertRaises(provision.ProvisionError):
                    provision.prepare(self.binary, self.destination, collect=self.collect, inventory=missing)
                self.assertFalse(self.destination.exists())

    def test_destination_inside_source_and_symlink_parent_are_rejected(self):
        self.destination = self.source / "candidate"
        with self.assertRaises(provision.ProvisionError):
            self.prepare()
        self.assertFalse(self.destination.exists())
        link = self.root / "link"
        link.symlink_to(self.root / "private")
        self.destination = link / "candidate"
        with self.assertRaises(provision.ProvisionError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_combined_schema_bytes_are_preserved_and_bound(self):
        raw = json.dumps(self.observation["protocol"], indent=3).encode()
        self.observation["protocol_bytes"] = raw
        self.prepare()
        self.addCleanup(self.restore_writable)
        self.assertEqual((self.destination / "protocol/combined.json").read_bytes(), raw)
        provenance = json.loads((self.destination / "provenance.json").read_bytes())
        self.assertEqual(provenance["combined_protocol_sha256"], hashlib.sha256(raw).hexdigest())

    def test_mismatched_raw_schema_and_empty_version_are_rejected(self):
        self.observation["protocol_bytes"] = b"{}"
        with self.assertRaises(provision.ProvisionError):
            self.prepare()
        self.assertFalse(self.destination.exists())
        del self.observation["protocol_bytes"]
        self.observation["version"]["revision"] = ""
        with self.assertRaises(provision.ProvisionError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_runtime_inventory_resolves_actual_libraries_and_font_files(self):
        def output(arguments):
            if arguments[0] == "ldd":
                return f"linux-vdso.so.1 (0x1234)\nlibactual => {self.library} (0x5678)\n"
            self.assertEqual(arguments, ["fc-list", "--format=%{file}\\n"])
            return str(self.font) + "\n"
        with patch.object(provision, "inventory_output", side_effect=output):
            inventory = provision.runtime_inventory(self.binary)
        self.assertEqual(inventory["libraries"], [self.library])
        self.assertEqual(inventory["fonts"], [self.font])
        self.assertTrue(all(path.is_absolute() and path.is_file() for path in inventory["certificates"]))

    def test_unresolved_runtime_libraries_fail_instead_of_omitting_them(self):
        with patch.object(provision, "inventory_output", return_value="libmissing.so => not found\n"):
            with self.assertRaisesRegex(provision.ProvisionError, "unresolved"):
                provision.runtime_inventory(self.binary)


if __name__ == "__main__":
    unittest.main()
