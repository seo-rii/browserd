#!/usr/bin/env python3
"""Build a deterministic, offline-installable browserd single-host candidate archive.

No services are started or installed. --build runs locked offline Cargo and SDK builds;
otherwise supply --binary-dir and --python-wheel. Supplied binaries are explicitly
unqualified. --dev-dirty permits review bundles, never a deployment-qualified release.
--require-qualified refuses to package unless all five current clean-source gate reports
match the Chromium artifact and kernel/machine, and binaries were built by this invocation.
Host PostgreSQL, Redis, bubblewrap, system libraries, seccomp filter and a delegated cgroup
remain operator-provided prerequisites; the archive never claims to provision them.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import validation
from native_profile_artifact import NativeProfileArtifactError, validate_native_catalog

TIERS = validation.TIERS
BINARIES = ("browser-egressd", "browser-sandboxd", "browser-worker", "browser-gateway", "browserd-launch-gate")
ROOT = Path(__file__).resolve().parents[1]
ALLOWED_ROOTS = {"bin", "chromium", "sdk", "viewer", "deploy", "qualification"}


class PackageError(Exception):
    pass


def contains_private_key(data: bytes) -> bool:
    marker = br"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    if b"\0" not in data[:4096]:
        return re.search(marker, data) is not None
    # TLS libraries contain PEM parser marker constants. Require an actual encoded key block
    # in binaries, rather than rejecting every executable that can parse a PEM key.
    return re.search(marker + br"\r?\n[A-Za-z0-9+/=\r\n]{32,}-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", data) is not None


def safe_name(name: str) -> None:
    path = PurePosixPath(name)
    if (path.is_absolute() or not path.parts or ".." in path.parts or "\\" in name
            or (path.parts[0] not in ALLOWED_ROOTS and name not in {"manifest.json", "SHA256SUMS"})):
        raise PackageError(f"bundle path is outside the release allowlist: {name}")
    for part in path.parts:
        lower = part.lower()
        if (lower in {".git", "node_modules", "__pycache__", "target", "credentials", "id_rsa", "id_ed25519"}
                or lower.endswith((".pyc", ".key", ".env")) or (lower.startswith(".env") and part != ".env.example")):
            raise PackageError(f"secret/build/runtime input is not permitted: {name}")


def read_input(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in path.parents):
        raise PackageError(f"input must be a regular file without symlink ancestors: {path}")
    data = path.read_bytes()
    if contains_private_key(data):
        raise PackageError("private key material is not permitted in a release bundle")
    return data


def source_policy(source: dict, allow_dirty: bool) -> str:
    if source.get("dirty") or not source.get("revision"):
        if not allow_dirty:
            raise PackageError("release packaging requires clean committed source; use --dev-dirty only for an unqualified review bundle")
        return "development-unqualified"
    return "release-candidate"


def chromium_entries(root: Path) -> tuple[dict, str]:
    try:
        digest = validation.verify_artifact(root)
        raw = read_input(root / "compatibility.json")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise PackageError("Chromium manifest changed while packaging")
        manifest = json.loads(raw)
        entries = {"chromium/compatibility.json": (raw, 0o444)}
        for item in manifest["files"]:
            name = "chromium/" + item["relative_path"]
            safe_name(name)
            if name in entries:
                raise PackageError("Chromium manifest contains duplicate file paths")
            path = root / item["relative_path"]
            data = read_input(path)
            if hashlib.sha256(data).hexdigest() != item["digest"]:
                raise PackageError("Chromium artifact changed while packaging")
            entries[name] = (data, 0o555 if path.stat().st_mode & 0o111 else 0o444)
        # Validate the catalog from the same bytes selected for this archive. A
        # second read from the artifact root could validate a different catalog.
        validate_native_catalog(manifest, entries["chromium/native-process-profiles.json"][0])
        return entries, digest
    except (validation.GateError, NativeProfileArtifactError, OSError, ValueError, KeyError, TypeError) as error:
        raise PackageError("Chromium compatibility manifest/files failed verification") from error


def public_gate_report(report: dict) -> dict:
    if not isinstance(report, dict) or not isinstance(report.get("commands", []), list):
        raise PackageError("gate report has an invalid structure")
    public = {key: report[key] for key in (
        "schema_version", "run_id", "tier", "status", "started_at", "finished_at",
        "source_revision", "source_dirty", "kernel_release", "machine", "manifest_sha256", "probes",
    ) if key in report}
    public["commands"] = [{key: command[key] for key in ("name", "exit_code", "duration_seconds") if key in command}
                          for command in report.get("commands", [])]
    public["probes"] = [name for name in (*validation.KERNEL_PROBES, *validation.SOAK_PROBES)
                        if name in report.get("probes", [])]
    return public


def qualification(reports: list[dict], source: dict, artifact_digest: str, built_here: bool) -> dict:
    reasons = []
    if source.get("dirty"):
        reasons.append("source is dirty")
    if not built_here:
        reasons.append("prebuilt binaries have operator-supplied provenance")
    by_tier = {}
    for report in reports:
        tier = report.get("tier")
        if tier not in TIERS or tier in by_tier:
            reasons.append("gate reports contain an unknown or duplicate tier")
            continue
        by_tier[tier] = report
    for tier in TIERS:
        report = by_tier.get(tier, {})
        if (report.get("status") != "passed" or not report.get("commands")
                or any(command.get("exit_code") != 0 for command in report.get("commands", []))
                or report.get("source_revision") != source.get("revision")
                or report.get("source_dirty") is not False):
            reasons.append(f"{tier} lacks a passed report for the current clean revision")
    for tier in ("kernel", "soak"):
        report = by_tier.get(tier, {})
        if report.get("manifest_sha256") != artifact_digest:
            reasons.append(f"{tier} report does not qualify this Chromium artifact")
        probes = validation.KERNEL_PROBES if tier == "kernel" else validation.SOAK_PROBES
        if not set(probes).issubset(report.get("probes", [])):
            reasons.append(f"{tier} lacks required behavior evidence")
        if tier == "soak" and (not report.get("commands") or report["commands"][-1].get("duration_seconds", 0) < 72 * 3600):
            reasons.append("soak report lacks a measured 72-hour workload")
    kernel = by_tier.get("kernel", {})
    soak = by_tier.get("soak", {})
    if (not kernel.get("kernel_release") or not kernel.get("machine")
            or any(kernel.get(key) != soak.get(key) for key in ("kernel_release", "machine"))):
        reasons.append("kernel and soak must qualify the same kernel release and machine")
    return {"qualified": not reasons, "reasons": reasons,
            "kernel_release": kernel.get("kernel_release"), "machine": kernel.get("machine"),
            "scope": "single-host, one worker, dedicated_process; qualification is specific to this kernel/artifact"}


def normalized_wheel(path: Path, epoch: int) -> bytes:
    data = read_input(path)
    result = io.BytesIO()
    stamp = time.gmtime(max(315532800, min(epoch, 4354819198)))[:6]
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as target:
        names = source.namelist()
        if len(names) != len(set(names)):
            raise PackageError("Python wheel contains duplicate members")
        for name in sorted(names):
            safe_name("sdk/" + name)
            if name.endswith("/"):
                continue
            if source.getinfo(name).external_attr >> 16 & 0o170000 == 0o120000:
                raise PackageError("Python wheel must not contain symlinks")
            value = source.read(name)
            if contains_private_key(value):
                raise PackageError("Python wheel contains private key material")
            info = zipfile.ZipInfo(name, stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            target.writestr(info, value)
    return result.getvalue()


def write_archive(output: Path, entries: dict[str, tuple[bytes, int]], epoch: int) -> None:
    for name, (data, _mode) in entries.items():
        safe_name(name)
        if contains_private_key(data):
            raise PackageError("private key material is not permitted in a release bundle")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Publish only a complete archive; never overwrite an earlier candidate silently.
    if output.exists():
        raise PackageError("output already exists; choose a new candidate archive path")
    descriptor, temporary = tempfile.mkstemp(prefix=".browserd-package-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as raw, gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, (data, mode) in sorted(entries.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = epoch
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
        os.link(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)


def collect_payload(binary_dir: Path, wheel: Path, chromium: Path, epoch: int) -> tuple[dict, str]:
    entries, artifact_digest = chromium_entries(chromium)
    for name in BINARIES:
        path = binary_dir / name
        if not os.access(path, os.X_OK):
            raise PackageError(f"required executable is missing or not executable: {name}")
        entries[f"bin/{name}"] = (read_input(path), 0o555)
    for name in ["index.js", "index.d.ts"]:
        if not (ROOT / "sdk/typescript/dist" / name).is_file():
            raise PackageError("TypeScript SDK must be built before packaging")
    for path in sorted((ROOT / "sdk/typescript/dist").rglob("*")):
        if path.is_file():
            entries["sdk/typescript/dist/" + path.relative_to(ROOT / "sdk/typescript/dist").as_posix()] = (read_input(path), 0o444)
    for name in ("package.json", "README.md"):
        entries[f"sdk/typescript/{name}"] = (read_input(ROOT / "sdk/typescript" / name), 0o444)
    normalized = normalized_wheel(wheel, epoch)
    with zipfile.ZipFile(io.BytesIO(normalized)) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise PackageError("Python SDK input is not a complete wheel")
        metadata_root = metadata[0].rsplit("/", 1)[0]
        if any(f"{metadata_root}/{name}" not in archive.namelist() for name in ("WHEEL", "RECORD")):
            raise PackageError("Python SDK wheel lacks installation metadata")
        if b"Name: browserd-client\n" not in archive.read(metadata[0]):
            raise PackageError("Python wheel names an unexpected SDK package")
        for path in (ROOT / "sdk/python/browserd").glob("*.py"):
            member = "browserd/" + path.name
            if archive.read(member) != read_input(path):
                raise PackageError("Python wheel does not match the current SDK source")
    entries["sdk/python/" + wheel.name] = (normalized, 0o444)
    entries["sdk/python/README.md"] = (read_input(ROOT / "sdk/python/README.md"), 0o444)
    for path in [ROOT / "viewer-web/index.html", ROOT / "viewer-web/styles.css", *sorted((ROOT / "viewer-web/src").glob("*.mjs"))]:
        entries["viewer/" + path.relative_to(ROOT / "viewer-web").as_posix()] = (read_input(path), 0o444)
    for path in sorted((ROOT / "deploy").rglob("*")):
        if path.is_file():
            relative = path.relative_to(ROOT).as_posix()
            safe_name(relative)
            if path.name != ".env.example" and path.suffix not in {".service", ".sh", ".py"}:
                raise PackageError(f"unexpected deployment input: {relative}")
            value = read_input(path)
            if path.name == ".env.example":
                for line in value.decode().splitlines():
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    name, setting = line.split("=", 1)
                    if (name.endswith(("TOKEN", "SECRET", "PASSWORD", "POSTGRES_URL", "REDIS_URL"))
                            and "REPLACE" not in setting):
                        raise PackageError("deployment example contains a configured credential or service URL")
            entries[relative] = (value, 0o555 if path.suffix in {".sh", ".py"} else 0o444)
    return entries, artifact_digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build", action="store_true")
    mode.add_argument("--binary-dir", type=Path)
    parser.add_argument("--python-wheel", type=Path, help="required with --binary-dir; must match current SDK source")
    parser.add_argument("--chromium-artifact-root", type=Path, required=True)
    parser.add_argument("--gate-report", action="append", type=Path, default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dev-dirty", action="store_true")
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args(argv)
    try:
        source = validation.source_identity(ROOT)
        source = {"revision": source["source_revision"], "dirty": source["source_dirty"]}
        candidate = source_policy(source, args.dev_dirty)
        epoch = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True).strip())
        # Verify the heavyweight external artifact before spending resources on a build.
        artifact_digest = validation.verify_artifact(args.chromium_artifact_root)
        reports = []
        for path in args.gate_report:
            raw = read_input(path)
            report = public_gate_report(json.loads(raw))
            report["original_report_sha256"] = hashlib.sha256(raw).hexdigest()
            reports.append(report)
        preflight = qualification(reports, source, artifact_digest, args.build)
        if args.require_qualified and (args.dev_dirty or not preflight["qualified"]):
            raise PackageError("deployment qualification is incomplete before build: " + "; ".join(preflight["reasons"] or ["development mode is unqualified"]))
        with tempfile.TemporaryDirectory(prefix="browserd-release-inputs-") as temporary:
            binary_dir = args.binary_dir
            wheel = args.python_wheel
            if args.build:
                wheels = Path(temporary) / "wheels"
                wheels.mkdir()
                build = [validation.Command("rust-release", tuple(["cargo", "build", "--locked", "--offline", "--release", "--workspace"] + [part for name in BINARIES for part in ("--bin", name)]), ROOT, 7200),
                         validation.Command("typescript-install", ("npm", "ci", "--offline", "--ignore-scripts"), ROOT / "sdk/typescript"),
                         validation.Command("typescript-build", ("npm", "run", "build"), ROOT / "sdk/typescript"),
                         validation.Command("python-wheel", (sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--no-index", "--wheel-dir", str(wheels), "."), ROOT / "sdk/python")]
                env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch), PYTHONDONTWRITEBYTECODE="1")
                run_dir, report = validation.execute("release-build", build, Path.home() / "logs", env)
                print(f"release build: {report['status']}; report: {run_dir / 'report.json'}")
                if report["status"] != "passed":
                    raise PackageError("release build failed; inspect the private build logs")
                candidates = list(wheels.glob("*.whl"))
                if len(candidates) != 1:
                    raise PackageError("Python build did not produce exactly one wheel")
                wheel = candidates[0]
                binary_dir = ROOT / "target/release"
            if wheel is None:
                raise PackageError("--python-wheel is required with supplied binaries")
            entries, artifact_digest = collect_payload(binary_dir, wheel, args.chromium_artifact_root, epoch)
            state = qualification(reports, source, artifact_digest, args.build)
            if args.dev_dirty:
                state["qualified"] = False
                state["reasons"].append("--dev-dirty explicitly requests an unqualified review bundle")
            if args.require_qualified and not state["qualified"]:
                raise PackageError("deployment qualification is incomplete: " + "; ".join(state["reasons"]))
            for index, report in enumerate(reports):
                entries[f"qualification/{index:02d}-{report.get('tier', 'unknown')}.json"] = (json.dumps(report, indent=2, sort_keys=True).encode() + b"\n", 0o444)
            after = validation.source_identity(ROOT)
            if (after["source_revision"], after["source_dirty"]) != (source["revision"], source["dirty"]):
                raise PackageError("source changed while packaging; retry from a stable tree")
            manifest = {"schema_version": 1, "candidate": candidate, "source": source, "source_date_epoch": epoch,
                        "build": "locked-offline-local" if args.build else "operator-supplied-unverified",
                        "deployment": state, "chromium_manifest_sha256": artifact_digest,
                        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mode": oct(mode)} for name, (data, mode) in sorted(entries.items())]}
            entries["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n", 0o444)
            entries["SHA256SUMS"] = ("".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, (data, _mode) in sorted(entries.items())).encode(), 0o444)
            write_archive(args.output, entries, epoch)
        print(f"packaged {args.output}; deployment qualified: {state['qualified']}")
        return 0
    except (PackageError, validation.GateError, OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"release packaging refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
