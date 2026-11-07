#!/usr/bin/env python3
"""Prepare a private, unqualified Chromium candidate from real local file copies.

This tool does not grant operator approval or emit qualification receipts. Its
short-lived discovery browser retains Chromium's sandbox. The full protocol is
read through a temporary loopback-only debugging endpoint, never a daemon launch.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_profile_artifact import validate_native_catalog


DEFAULT_BINARY = Path.home() / ".cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell"
JS_DOMAINS = frozenset({"Console", "Debugger", "HeapProfiler", "Profiler", "Runtime", "Schema"})
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_PROTOCOL_BYTES = 16 * 1024 * 1024
MAX_INVENTORY_FILES = 4096
DISCOVERY_SECONDS = 30


class ProvisionError(ValueError):
    pass


def encode_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def check_path(path: Path) -> None:
    if not path.is_absolute():
        raise ProvisionError("provisioning paths must be absolute")
    for component in [*reversed(path.parents), path]:
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise ProvisionError("provisioning paths cannot contain symlinks")


def copy_file(source: Path, destination: Path, *, executable: bool = False) -> str:
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_FILE_BYTES:
            raise ProvisionError("source resource must be a bounded, nonempty regular file")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700 if executable else 0o600)
        hasher = hashlib.sha256()
        total = 0
        try:
            while block := os.read(source_fd, 1024 * 1024):
                total += len(block)
                if total > MAX_FILE_BYTES:
                    raise ProvisionError("source resource exceeds its size bound")
                hasher.update(block)
                remaining = memoryview(block)
                while remaining:
                    remaining = remaining[os.write(output_fd, remaining):]
            os.fsync(output_fd)
        finally:
            os.close(output_fd)
        after = os.fstat(source_fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ProvisionError("source resource changed during its snapshot")
        return hasher.hexdigest()
    finally:
        os.close(source_fd)


def stop_child(child: subprocess.Popen) -> None:
    # Both discovery launches own dedicated process groups, including descendants.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
    else:
        # The launcher may exit before a descendant; clear the remaining group.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for stream in [child.stdin, child.stdout]:
        if stream is not None:
            stream.close()


def collect_browser(binary: Path, work: Path) -> dict:
    fixture = Path(__file__).with_name("chromium_pipe_fixture.py")
    profile = work / "pipe-profile"
    profile.mkdir(mode=0o700)
    pipe_arguments = ["--headless", "--remote-debugging-pipe", "--no-startup-window",
                      "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                      "--disable-component-update", "--disable-extensions",
                      "--disable-component-extensions-with-background-pages",
                      "--disable-features=PreloadTopChromeWebUI,WebUIOmniboxPopup,WebUIOmniboxAimPopup",
                      "--site-per-process", "--disable-dev-shm-usage", f"--user-data-dir={profile}"]
    with (work / "pipe.stderr").open("xb") as diagnostics:
        child = subprocess.Popen([sys.executable, str(fixture), str(binary), str(profile), str(work / "pipe-evidence.jsonl")],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=diagnostics,
                                 start_new_session=True)
        try:
            child.stdin.write(encode_json({"id": 1, "method": "Browser.getVersion"}) + b"\0")
            child.stdin.flush()
            deadline = time.monotonic() + DISCOVERY_SECONDS
            pending = bytearray()
            version = None
            while version is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([child.stdout], [], [], max(0, remaining))[0]:
                    raise ProvisionError("sandbox-enabled Chromium version discovery timed out")
                block = os.read(child.stdout.fileno(), 65536)
                if not block:
                    raise ProvisionError("sandbox-enabled Chromium exited during version discovery")
                pending.extend(block)
                if len(pending) > MAX_PROTOCOL_BYTES:
                    raise ProvisionError("Chromium discovery frame exceeds its size bound")
                while (end := pending.find(0)) >= 0:
                    frame = json.loads(pending[:end])
                    del pending[:end + 1]
                    if frame.get("id") == 1:
                        if "error" in frame or not isinstance(frame.get("result"), dict):
                            raise ProvisionError("Chromium rejected version discovery")
                        version = frame["result"]
                        break
        finally:
            stop_child(child)

    protocol_profile = work / "protocol-profile"
    protocol_profile.mkdir(mode=0o700)
    endpoint_arguments = ["--headless", "--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1",
                          "--no-startup-window", "--no-first-run", "--no-default-browser-check",
                          "--disable-background-networking", "--disable-component-update", "--disable-extensions",
                          "--disable-component-extensions-with-background-pages", "--disable-dev-shm-usage",
                          f"--user-data-dir={protocol_profile}"]
    with (work / "protocol.stderr").open("xb") as diagnostics:
        child = subprocess.Popen([str(binary), *endpoint_arguments], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=diagnostics, start_new_session=True)
        try:
            deadline = time.monotonic() + DISCOVERY_SECONDS
            active_port = protocol_profile / "DevToolsActivePort"
            while not active_port.exists():
                if child.poll() is not None:
                    raise ProvisionError("sandbox-enabled Chromium exited during protocol discovery")
                if time.monotonic() >= deadline:
                    raise ProvisionError("sandbox-enabled Chromium protocol discovery timed out")
                time.sleep(0.05)
            if active_port.is_symlink() or active_port.stat().st_size > 4096:
                raise ProvisionError("invalid private discovery endpoint")
            port = int(active_port.read_text().splitlines()[0])
            if not 1 <= port <= 65535:
                raise ProvisionError("invalid private discovery port")
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=DISCOVERY_SECONDS)
            try:
                connection.request("GET", "/json/protocol")
                response = connection.getresponse()
                if response.status != 200:
                    raise ProvisionError("Chromium protocol endpoint rejected discovery")
                raw_protocol = response.read(MAX_PROTOCOL_BYTES + 1)
                if len(raw_protocol) > MAX_PROTOCOL_BYTES:
                    raise ProvisionError("Chromium protocol schema exceeds its size bound")
                protocol = json.loads(raw_protocol)
            finally:
                connection.close()
        finally:
            stop_child(child)
    return {"version": version, "protocol": protocol, "protocol_bytes": raw_protocol,
            "launch_arguments": [pipe_arguments, endpoint_arguments]}


def inventory_output(arguments: list[str]) -> str:
    try:
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProvisionError("runtime inventory tool unavailable") from error
    if result.returncode or len(result.stdout) > MAX_PROTOCOL_BYTES:
        raise ProvisionError("runtime inventory collection failed")
    return result.stdout.decode("utf-8", errors="strict")


def runtime_inventory(binary: Path) -> dict[str, list[Path]]:
    libraries = set()
    for line in inventory_output(["ldd", str(binary)]).splitlines():
        value = line.strip()
        if "not found" in value:
            raise ProvisionError("Chromium has an unresolved runtime library")
        value = value.split("=>", 1)[-1].strip().split(" (", 1)[0].strip()
        if value.startswith("/"):
            libraries.add(Path(value).resolve(strict=True))
    # Companion EGL/Vulkan libraries have additional dependencies not present in
    # the main executable's ldd inventory.
    for companion in sorted(binary.parent.glob("*.so*")):
        libraries.add(companion.resolve(strict=True))
        for line in inventory_output(["ldd", str(companion)]).splitlines():
            value = line.strip()
            if "not found" in value:
                raise ProvisionError("Chromium companion has an unresolved runtime library")
            value = value.split("=>", 1)[-1].strip().split(" (", 1)[0].strip()
            if value.startswith("/"):
                libraries.add(Path(value).resolve(strict=True))
    fonts = {Path(line).resolve(strict=True) for line in inventory_output(["fc-list", "--format=%{file}\\n"]).splitlines() if line}
    certificates = [Path("/etc/ssl/certs/ca-certificates.crt"), Path("/etc/ssl/openssl.cnf")]
    if not all(path.is_file() for path in certificates):
        raise ProvisionError("device certificate runtime files are unavailable")
    return {"libraries": sorted(libraries), "fonts": sorted(fonts),
            "certificates": [path.resolve(strict=True) for path in certificates]}


def schema_documents(observation: dict) -> tuple[bytes, bytes, bytes]:
    version, protocol = observation.get("version"), observation.get("protocol")
    if not isinstance(version, dict) or any(not isinstance(version.get(key), str) or not version[key]
                                           or len(version[key]) > 1024 or any(ord(char) < 32 for char in version[key])
                                           for key in ["product", "revision"]):
        raise ProvisionError("invalid actual Chromium version observation")
    if not isinstance(protocol, dict) or not isinstance(protocol.get("version"), dict):
        raise ProvisionError("invalid actual Chromium protocol schema")
    domains = protocol.get("domains")
    if not isinstance(domains, list) or not domains:
        raise ProvisionError("actual Chromium protocol domains are missing")
    names = []
    for domain in domains:
        if not isinstance(domain, dict) or not isinstance(domain.get("domain"), str) or not domain["domain"]:
            raise ProvisionError("invalid actual Chromium protocol domain")
        names.append(domain["domain"])
    if len(set(names)) != len(names) or not {"Browser", "Runtime"} <= set(names):
        raise ProvisionError("actual Chromium protocol domains are incomplete or duplicated")
    combined = observation.get("protocol_bytes", encode_json(protocol))
    if not isinstance(combined, bytes) or len(combined) > MAX_PROTOCOL_BYTES or json.loads(combined) != protocol:
        raise ProvisionError("recorded Chromium protocol bytes differ from the observed schema")
    browser = dict(protocol, domains=[domain for domain in domains if domain["domain"] not in JS_DOMAINS])
    javascript = dict(protocol, domains=[domain for domain in domains if domain["domain"] in JS_DOMAINS])
    return combined, encode_json(browser), encode_json(javascript)


def prepare(binary: Path, destination: Path, *, collect=collect_browser, inventory=runtime_inventory) -> dict:
    binary, destination = Path(binary), Path(destination)
    check_path(binary)
    check_path(destination)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ProvisionError("Chromium source must be an executable regular file")
    if binary.parent == destination or binary.parent in destination.parents:
        raise ProvisionError("candidate destination cannot be inside the source bundle")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ProvisionError("candidate destination already exists") from error
    try:
        files: dict[str, str] = {}
        for directory, directories, filenames in os.walk(binary.parent, followlinks=False):
            current = Path(directory)
            for name in directories:
                path = current / name
                if path.is_symlink():
                    raise ProvisionError("Chromium source directories cannot be symlinks")
            for name in sorted(filenames):
                source = current / name
                if source.is_symlink() or not source.is_file():
                    raise ProvisionError("Chromium source resources must be regular files without symlinks")
                relative = source.relative_to(binary.parent).as_posix()
                if len(files) >= MAX_INVENTORY_FILES:
                    raise ProvisionError("Chromium source inventory exceeds its bound")
                files[relative] = copy_file(source, destination / relative, executable=source == binary)
        if not {binary.name, "icudtl.dat", "locales/ko.pak"} <= set(files):
            raise ProvisionError("Chromium source bundle lacks required native resources")
        with tempfile.TemporaryDirectory(prefix="browserd-candidate-discovery-") as temporary:
            observation = collect(destination / binary.name, Path(temporary))
        combined, browser_schema, js_schema = schema_documents(observation)
        brand, separator, product_version = observation["version"]["product"].partition("/")
        if (not separator or brand not in {"Chrome", "Chromium", "HeadlessChrome"}
                or not product_version or "/" in product_version):
            raise ProvisionError("invalid actual Chromium product observation")
        inventories = inventory(destination / binary.name)
        if not isinstance(inventories, dict) or set(inventories) != {"libraries", "fonts", "certificates"}:
            raise ProvisionError("invalid actual runtime inventory")
        records = {}
        for kind, category in [("library", "libraries"), ("font", "fonts"), ("certificate", "certificates")]:
            sources = inventories[category]
            if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_INVENTORY_FILES:
                raise ProvisionError("actual runtime inventory is missing or exceeds its bound")
            entries = []
            seen = set()
            for source in sorted(Path(path) for path in sources):
                if not source.is_absolute():
                    raise ProvisionError("runtime source paths must be absolute")
                canonical = source.resolve(strict=True)
                if canonical in seen:
                    continue
                seen.add(canonical)
                relative = f"runtime/{category}/{canonical.as_posix().lstrip('/')}"
                file_digest = copy_file(canonical, destination / relative)
                files[relative] = file_digest
                entries.append({"kind": kind, "source_path": str(canonical), "relative_path": relative, "digest": file_digest})
            records[category] = entries
        catalog = {"schema_version": 1, "icu_data": "icudtl.dat",
                   "locales": [{"locale": "ko-KR", "pak": "locales/ko.pak"}],
                   "time_zones": ["Asia/Seoul", "UTC"]}
        if "locales/en-US.pak" in files:
            catalog["locales"].append({"locale": "en-US", "pak": "locales/en-US.pak"})
        documents = {
            "native-process-profiles.json": encode_json(catalog),
            "protocol/combined.json": combined,
            "protocol/browser.json": browser_schema,
            "protocol/js.json": js_schema,
            "bundles/extensions.json": encode_json({"schema_version": 1, "policy": "disabled", "files": []}),
            "bundles/fonts.json": encode_json({"schema_version": 1, "files": records["fonts"]}),
            "bundles/certificate-runtime.json": encode_json({"schema_version": 1, "files": records["libraries"] + records["certificates"]}),
        }
        for relative, data in documents.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as output:
                output.write(data)
            files[relative] = digest_bytes(data)
        identity = {
            "binary_digest": files[binary.name], "product_version": product_version,
            "chromium_revision": observation["version"]["revision"],
            "browser_protocol_schema_digest": files["protocol/browser.json"],
            "js_protocol_schema_digest": files["protocol/js.json"],
            "launch_profile_digest": files["native-process-profiles.json"],
            "extension_bundle_digest": files["bundles/extensions.json"],
            "font_bundle_digest": files["bundles/fonts.json"],
            "certificate_runtime_bundle_digest": files["bundles/certificate-runtime.json"],
        }
        manifest = {"identity": identity, "files": [{"relative_path": name, "digest": files[name]} for name in sorted(files)]}
        validate_native_catalog(manifest, documents["native-process-profiles.json"])
        raw_manifest = encode_json(manifest)
        (destination / "compatibility.json").write_bytes(raw_manifest)
        provenance = {
            "schema_version": 1, "qualification": "local_candidate", "operator_approval": False,
            "production_qualified": False, "created_at": datetime.now(timezone.utc).isoformat(),
            "source_binary": str(binary), "source_binary_digest": files[binary.name],
            "browser_version": observation["version"], "launch_arguments": observation["launch_arguments"],
            "combined_protocol_sha256": digest_bytes(combined),
            "protocol_derivation": {"source": "actual local Chromium /json/protocol",
                                    "javascript_domains": sorted(JS_DOMAINS),
                                    "browser_domains": "all remaining domains",
                                    "individual_schema_format": "canonical JSON partition of observed combined schema"},
            "bundle_identity_format": "SHA-256 of inventory JSON binding original paths and copied file bytes",
            "runtime_configuration": "copied device inventories; sandbox mounts and font discovery require qualification",
            "sandbox": "Chromium sandbox enabled in both discovery launches; outer browserd sandbox not qualified",
            "copy_method": "independent read-only file copies; user-owned candidate is not operator-approved immutable deployment storage",
            "manifest_sha256": digest_bytes(raw_manifest),
        }
        (destination / "provenance.json").write_bytes(encode_json(provenance))
        for path in destination.rglob("*"):
            if path.is_file():
                path.chmod(0o500 if path == destination / binary.name else 0o400)
        for path in sorted((path for path in destination.rglob("*") if path.is_dir()), key=lambda path: len(path.parts), reverse=True):
            path.chmod(0o500)
        destination.chmod(0o500)
        return {"artifact_root": str(destination), "manifest_sha256": digest_bytes(raw_manifest),
                "binary_digest": identity["binary_digest"], "qualification": "local_candidate",
                "operator_approval": False, "file_count": len(files)}
    except Exception as error:
        # This directory was created exclusively above. Never delete an existing
        # candidate or mutate the source cache after a failed attempt.
        for directory, directories, filenames in os.walk(destination):
            Path(directory).chmod(0o700)
            for name in filenames:
                (Path(directory) / name).chmod(0o600)
        shutil.rmtree(destination)
        if isinstance(error, ProvisionError):
            raise
        raise ProvisionError("candidate preparation failed") from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        try:
            result = prepare(arguments.binary, arguments.destination)
        except ProvisionError as error:
            print(json.dumps({"status": "failed", "reason": str(error)}), file=sys.stderr)
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
