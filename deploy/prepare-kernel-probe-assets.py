#!/usr/bin/env python3
"""Copy verified probe inputs and prepare a root installation handoff.

Preparation does not install anything, start services, approve a deployment, or
issue qualification evidence. The generated installer only publishes a new
content-pinned, root-owned asset directory; its command pins the installer bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import validation

MAX_FILES = 8192
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
REQUIRED_BINARIES = (
    "browserd-kernel-probe", "browser-sandboxd", "browser-egressd", "browserd-launch-gate",
)


class PreparationError(ValueError):
    pass


def encode_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative_path(value):
    if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
        raise PreparationError("unsafe relative asset path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PreparationError("unsafe relative asset path")
    return parts


def absolute_path(value):
    path = Path(value)
    if not path.is_absolute() or str(path) != os.fspath(value) or path == Path("/"):
        raise PreparationError("paths must be canonical absolute paths without dot components")
    relative_path(str(path)[1:])
    return path


def stamp(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def directory_identity(metadata):
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid


def open_directory(path):
    """Pin every ancestor and reject links; retain handles for connection checks."""
    path = absolute_path(path)
    handles = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    links = []
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=handles[-1])
            links.append((handles[-1], part, child, directory_identity(os.fstat(child))))
            handles.append(child)
        return handles, links
    except BaseException:
        for handle in reversed(handles):
            os.close(handle)
        raise


def check_connections(links):
    for parent, name, child, identity in links:
        if (directory_identity(os.fstat(child)) != identity or
                directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity):
            raise PreparationError("asset directory changed during preparation or installation")


def close_handles(handles):
    for handle in reversed(handles):
        os.close(handle)


def inventory_tree(root_fd):
    """Inventory all entries without following links or opening special files."""
    files, directories, total = {}, {}, 0

    def visit(directory_fd, prefix):
        nonlocal total
        directories[prefix] = stamp(os.fstat(directory_fd))
        for name in sorted(os.listdir(directory_fd)):
            relative_path(name)
            relative = f"{prefix}/{name}" if prefix else name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory_fd)
                try:
                    if stamp(os.fstat(child)) != stamp(metadata):
                        raise PreparationError("asset directory raced its inventory")
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
                if metadata.st_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise PreparationError("asset size exceeds its preparation bound")
                files[relative] = stamp(metadata)
            else:
                raise PreparationError("asset trees must not contain symlinks or special files")
            if len(files) + len(directories) > MAX_FILES:
                raise PreparationError("asset tree exceeds its entry bound")
        if directories[prefix] != stamp(os.fstat(directory_fd)):
            raise PreparationError("asset directory changed during inventory")

    visit(root_fd, "")
    return files, directories


def open_relative_file(root_fd, relative):
    parts = relative_path(relative)
    handle = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle)
            os.close(handle)
            handle = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=handle)
    finally:
        os.close(handle)


def copy_file(root_fd, relative, target, expected):
    handle = open_relative_file(root_fd, relative)
    output = None
    try:
        before = os.fstat(handle)
        if (not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES or
                stamp(before) != expected):
            raise PreparationError("asset changed before its copy")
        mode = 0o555 if before.st_mode & 0o111 else 0o444
        output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        hasher, count = hashlib.sha256(), 0
        while block := os.read(handle, 1024 * 1024):
            count += len(block)
            if count > before.st_size:
                raise PreparationError("asset grew during its copy")
            hasher.update(block)
            remaining = memoryview(block)
            while remaining:
                remaining = remaining[os.write(output, remaining):]
        if count != before.st_size or stamp(os.fstat(handle)) != expected:
            raise PreparationError("asset changed during its copy")
        os.fchmod(output, mode & 0o700)
        os.fsync(output)
        return {"relative_path": relative, "sha256": hasher.hexdigest(), "size": count, "mode": mode}
    finally:
        if output is not None:
            os.close(output)
        os.close(handle)


def write_new(path, data, mode=0o600):
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        remaining = memoryview(data)
        while remaining:
            remaining = remaining[os.write(handle, remaining):]
        os.fsync(handle)
    finally:
        os.close(handle)


def safe_destination_parent(destination):
    """Create only missing root asset parents, never follow or repair unsafe ones."""
    path = absolute_path(destination)
    handles = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    links = []
    try:
        for part in path.parts[1:-1]:
            metadata = os.fstat(handles[-1])
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise PreparationError("installation ancestors must be root-owned and not writable by others")
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handles[-1])
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=handles[-1])
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handles[-1])
            metadata = os.fstat(child)
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                os.close(child)
                raise PreparationError("installation ancestors must be root-owned and not writable by others")
            links.append((handles[-1], part, child, directory_identity(metadata)))
            handles.append(child)
        return handles, links
    except BaseException:
        close_handles(handles)
        raise


def publish_new(source, destination, parent_fd):
    """Linux renameat2(RENAME_NOREPLACE) prevents replacing a raced destination."""
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def remove_tree_fd(parent_fd, name):
    """Remove only an owned partial tree through pinned directory handles."""
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        os.fchmod(child, 0o700)
        for entry in os.listdir(child):
            metadata = os.stat(entry, dir_fd=child, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                remove_tree_fd(child, entry)
            else:
                os.unlink(entry, dir_fd=child)
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent_fd)


def install_prepared(bundle):
    """Used only by the separately generated, content-pinned root installer."""
    if os.geteuid() != 0:
        raise PreparationError("installation requires a root shell outside a NoNewPrivileges process")
    source_handles, source_links = open_directory(bundle)
    parent_handles = []
    partial = None
    try:
        source_fd = source_handles[-1]
        metadata = os.fstat(source_fd)
        if metadata.st_uid != SOURCE_UID or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise PreparationError("prepared bundle must retain its private owner and mode")
        handle = open_relative_file(source_fd, "inventory.json")
        try:
            before = os.fstat(handle)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != SOURCE_UID or
                    stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 4 * 1024 * 1024):
                raise PreparationError("unsafe prepared inventory")
            raw = b""
            while block := os.read(handle, 1024 * 1024):
                raw += block
                if len(raw) > 4 * 1024 * 1024:
                    raise PreparationError("prepared inventory exceeds its bound")
            if stamp(os.fstat(handle)) != stamp(before) or digest(raw) != EXPECTED_INVENTORY_SHA256:
                raise PreparationError("prepared inventory changed or does not match the reviewed checksum")
        finally:
            os.close(handle)
        inventory = json.loads(raw)
        entries = inventory["files"]
        directories = inventory["directories"]
        if inventory["schema_version"] != 1 or not entries or len(entries) + len(directories) > MAX_FILES:
            raise PreparationError("invalid prepared inventory")
        for name in directories:
            relative_path(name)
        expected_files = {}
        for entry in entries:
            name = entry["relative_path"]
            relative_path(name)
            if (name in expected_files or entry["mode"] not in {0o444, 0o555} or
                    not isinstance(entry["size"], int) or not 0 <= entry["size"] <= MAX_FILE_BYTES or
                    len(entry["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in entry["sha256"])):
                raise PreparationError("invalid prepared file entry")
            expected_files[name] = entry
        assets_fd = os.open("assets", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd)
        try:
            initial_files, initial_directories = inventory_tree(assets_fd)
            if set(initial_files) != set(expected_files) or set(initial_directories) != {"", *directories}:
                raise PreparationError("prepared asset tree differs from its exact inventory")
            for name, metadata in initial_files.items():
                if metadata[3] != SOURCE_UID or stat.S_IMODE(metadata[2]) != expected_files[name]["mode"] & 0o700:
                    raise PreparationError("prepared assets must retain private ownership and modes")
            for metadata in initial_directories.values():
                if metadata[3] != SOURCE_UID or stat.S_IMODE(metadata[2]) != 0o500:
                    raise PreparationError("prepared assets must retain private ownership and modes")
            destination = absolute_path(INSTALL_DESTINATION)
            parent_handles, parent_links = safe_destination_parent(destination)
            parent_fd = parent_handles[-1]
            try:
                os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise PreparationError("installation destination already exists; it will never be replaced")
            partial = f".{destination.name}.install-{uuid.uuid4().hex}"
            os.mkdir(partial, 0o700, dir_fd=parent_fd)
            partial_path = Path(f"/proc/self/fd/{parent_fd}") / partial
            for name in sorted(directories, key=lambda value: (value.count("/"), value)):
                (partial_path / name).mkdir(mode=0o700)
            for name, entry in expected_files.items():
                copied = copy_file(assets_fd, name, partial_path / name, initial_files[name])
                if copied != entry:
                    raise PreparationError("prepared asset checksum or mode differs from its reviewed inventory")
                handle = os.open(partial_path / name, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fchown(handle, 0, 0)
                    os.fchmod(handle, entry["mode"])
                    os.fsync(handle)
                finally:
                    os.close(handle)
            if inventory_tree(assets_fd) != (initial_files, initial_directories):
                raise PreparationError("prepared assets changed during installation")
            if stamp(os.stat("assets", dir_fd=source_fd, follow_symlinks=False)) != initial_directories[""]:
                raise PreparationError("prepared asset root changed during installation")
            check_connections(source_links)
            check_connections(parent_links)
            for name in sorted(["", *directories], key=lambda value: value.count("/"), reverse=True):
                handle = os.open(partial_path / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fchown(handle, 0, 0)
                    os.fchmod(handle, 0o555)
                    os.fsync(handle)
                finally:
                    os.close(handle)
            publish_new(partial, destination.name, parent_fd)
            partial = None
            os.fsync(parent_fd)
            return {"status": "installed", "install_destination": str(destination),
                    "inventory_sha256": EXPECTED_INVENTORY_SHA256,
                    "operator_approval": False, "production_qualified": False}
        finally:
            os.close(assets_fd)
    finally:
        if partial is not None:
            remove_tree_fd(parent_handles[-1], partial)
        close_handles(parent_handles)
        close_handles(source_handles)


def render_installer(inventory_sha256, destination, source_uid):
    helpers = [PreparationError, encode_json, digest, relative_path, absolute_path, stamp,
               directory_identity, open_directory, check_connections, close_handles,
               inventory_tree, open_relative_file, copy_file, safe_destination_parent,
               publish_new, remove_tree_fd, install_prepared]
    source = ("#!/usr/bin/env python3\n"
              '"""Install only the checksum-pinned NEW asset tree; do not configure or approve services."""\n'
              "import argparse, hashlib, json, os, stat, sys, uuid\nfrom pathlib import Path\n"
              f"MAX_FILES={MAX_FILES}\nMAX_FILE_BYTES={MAX_FILE_BYTES}\nMAX_TOTAL_BYTES={MAX_TOTAL_BYTES}\n"
              f"SOURCE_UID={source_uid!r}\nEXPECTED_INVENTORY_SHA256={inventory_sha256!r}\n"
              f"INSTALL_DESTINATION={str(destination)!r}\n\n")
    source += "\n\n".join(inspect.getsource(helper) for helper in helpers)
    source += ("\n\nif __name__ == '__main__':\n"
               "    parser=argparse.ArgumentParser(description=__doc__)\n"
               "    parser.add_argument('--bundle', required=True)\n"
               "    options=parser.parse_args()\n"
               "    try:\n        print(json.dumps(install_prepared(options.bundle), sort_keys=True))\n"
               "    except (OSError, ValueError, KeyError, TypeError) as error:\n"
               "        print('asset installation failed: ' + str(error), file=sys.stderr)\n"
               "        raise SystemExit(2)\n")
    return source.encode()


def installation_command(installer, bundle, checksum):
    loader = ("import hashlib,os,stat,sys; p=sys.argv[1]; "
              "f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); s=os.fstat(f); "
              "assert stat.S_ISREG(s.st_mode) and s.st_size<=1048576,'unsafe installer'; "
              "d=os.read(f,1048577); a=os.fstat(f); os.close(f); "
              "assert (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)=="
              "(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns),'installer changed'; "
              "assert hashlib.sha256(d).hexdigest()==sys.argv[2],'installer checksum mismatch'; "
              "sys.argv=[p,'--bundle',sys.argv[3]]; "
              "exec(compile(d,p,'exec'),{'__name__':'__main__','__file__':p})")
    return " ".join(shlex.quote(value) for value in
                    ["/usr/bin/python3", "-I", "-c", loader, str(installer), checksum, str(bundle)]) + "\n"


def prepare(artifact_root, binary_dir, output_dir, *, install_destination=None,
            include_worker=False, source_root=None):
    artifact_root, binary_dir, output_dir = map(absolute_path, (artifact_root, binary_dir, output_dir))
    if any(output_dir == root or output_dir.is_relative_to(root) or root.is_relative_to(output_dir)
           for root in (artifact_root, binary_dir)):
        raise PreparationError("output must be separate from both source trees")
    source_root = source_root or Path(__file__).resolve().parents[1]
    source = validation.source_identity(source_root)
    source["source_content_sha256"] = validation.source_content_identity(source_root)
    artifact_handles, artifact_links = open_directory(artifact_root)
    binary_handles, binary_links = [], []
    output_handles, output_links = [], []
    created = False
    output_identity = None
    output_parent_fd = None
    try:
        binary_handles, binary_links = open_directory(binary_dir)
        artifact_fd, binary_fd = artifact_handles[-1], binary_handles[-1]
        artifact_files, artifact_directories = inventory_tree(artifact_fd)
        manifest_sha256 = validation.verify_artifact(artifact_root)
        manifest_handle = open_relative_file(artifact_fd, "compatibility.json")
        try:
            manifest = json.loads(os.read(manifest_handle, 1024 * 1024 + 1))
        finally:
            os.close(manifest_handle)
        chromium = [entry["relative_path"] for entry in manifest["files"]
                    if entry["digest"] == manifest["identity"]["binary_digest"]]
        if len(chromium) != 1 or not artifact_files[chromium[0]][2] & 0o111:
            raise PreparationError("artifact must contain one executable pinned Chromium binary")
        binaries = [*REQUIRED_BINARIES, *( ["browser-worker"] if include_worker else [])]
        binary_files = {}
        for name in binaries:
            metadata = os.stat(name, dir_fd=binary_fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111 or not metadata.st_size:
                raise PreparationError("required native binaries must be nonempty executable regular files")
            binary_files[name] = stamp(metadata)
        if (len(artifact_files) + len(artifact_directories) + len(binary_files) + 3 > MAX_FILES or
                any(metadata[5] > MAX_FILE_BYTES for metadata in binary_files.values()) or
                sum(metadata[5] for metadata in [*artifact_files.values(), *binary_files.values()]) > MAX_TOTAL_BYTES):
            raise PreparationError("combined probe inputs exceed their preparation bound")
        output_handles, output_links = open_directory(output_dir.parent)
        parent_fd = output_handles[-1]
        output_parent_fd = parent_fd
        os.mkdir(output_dir.name, 0o700, dir_fd=parent_fd)
        created = True
        output_identity = directory_identity(os.stat(output_dir.name, dir_fd=parent_fd, follow_symlinks=False))
        output_fd = os.open(output_dir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        if directory_identity(os.fstat(output_fd)) != output_identity:
            os.close(output_fd)
            raise PreparationError("output directory changed before preparation")
        os.fchmod(output_fd, 0o700)
        output_identity = directory_identity(os.fstat(output_fd))
        output_links.append((parent_fd, output_dir.name, output_fd, output_identity))
        output_handles.append(output_fd)
        assets = output_dir / "assets"
        assets.mkdir(mode=0o700)
        directories = ["bin", "chromium", *(f"chromium/{name}" for name in artifact_directories if name)]
        for name in sorted(directories, key=lambda value: (value.count("/"), value)):
            (assets / name).mkdir(mode=0o700)
        entries = []
        for name, metadata in sorted(artifact_files.items()):
            entry = copy_file(artifact_fd, name, assets / "chromium" / name, metadata)
            entry["relative_path"] = "chromium/" + name
            entries.append(entry)
        for name, metadata in sorted(binary_files.items()):
            entry = copy_file(binary_fd, name, assets / "bin" / name, metadata)
            entry["relative_path"] = "bin/" + name
            entries.append(entry)
        entries.sort(key=lambda entry: entry["relative_path"])
        asset_content_sha256 = digest(encode_json({"directories": sorted(directories), "files": entries}))
        destination = absolute_path(install_destination or f"/opt/browserd/kernel-probe/{asset_content_sha256}")
        if any(destination == root or destination.is_relative_to(root) or root.is_relative_to(destination)
               for root in (artifact_root, binary_dir, output_dir)):
            raise PreparationError("installation destination must be separate from preparation and source trees")
        runtime_manifest = {"schema_version": 1, "mounts": []}
        for mount in ("chromium", "bin"):
            runtime_manifest["mounts"].append({
                "source": str(destination / mount), "destination": str(destination / mount),
                "files": [{"relative_path": entry["relative_path"][len(mount) + 1:], "sha256": entry["sha256"]}
                          for entry in entries if entry["relative_path"].startswith(mount + "/")],
            })
        runtime_raw = encode_json(runtime_manifest)
        write_new(assets / "kernel-probe-runtime-manifest.json", runtime_raw, 0o400)
        entries.append({"relative_path": "kernel-probe-runtime-manifest.json", "sha256": digest(runtime_raw),
                        "size": len(runtime_raw), "mode": 0o444})
        entries.sort(key=lambda entry: entry["relative_path"])
        check_connections(output_links)
        if validation.verify_artifact(assets / "chromium") != manifest_sha256:
            raise PreparationError("copied artifact does not retain the original compatibility manifest")
        if inventory_tree(artifact_fd) != (artifact_files, artifact_directories):
            raise PreparationError("source artifact changed during preparation")
        for name, metadata in binary_files.items():
            if stamp(os.stat(name, dir_fd=binary_fd, follow_symlinks=False)) != metadata:
                raise PreparationError("source binary changed during preparation")
        check_connections(artifact_links)
        check_connections(binary_links)
        check_connections(output_links)
        for name in sorted(["", *directories], key=lambda value: value.count("/"), reverse=True):
            (assets / name).chmod(0o500)
        inventory = {"schema_version": 1, "asset_content_sha256": asset_content_sha256,
                     "manifest_sha256": manifest_sha256, "directories": sorted(directories), "files": entries}
        inventory_raw = encode_json(inventory)
        inventory_sha256 = digest(inventory_raw)
        write_new(output_dir / "inventory.json", inventory_raw)
        installer_raw = render_installer(inventory_sha256, destination, os.geteuid())
        write_new(output_dir / "install-assets.py", installer_raw)
        installer_sha256 = digest(installer_raw)
        command = installation_command(output_dir / "install-assets.py", output_dir, installer_sha256)
        write_new(output_dir / "install-command.txt", command.encode())
        lookup = {entry["relative_path"]: entry["sha256"] for entry in entries}
        result = {"schema_version": 1, "status": "prepared", "operator_approval": False,
                  "production_qualified": False, **source,
                  "artifact_root": str(destination / "chromium"), "chromium_executable": str(destination / "chromium" / chromium[0]),
                  "manifest_sha256": manifest_sha256, "asset_content_sha256": asset_content_sha256,
                  "inventory_sha256": inventory_sha256, "install_destination": str(destination),
                  "installer_sha256": installer_sha256, "root_install_command_file": str(output_dir / "install-command.txt"),
                  "probe_executable": {"path": str(destination / "bin/browserd-kernel-probe"), "sha256": lookup["bin/browserd-kernel-probe"]},
                  "runtime_manifest": {"path": str(destination / "kernel-probe-runtime-manifest.json"), "sha256": digest(runtime_raw)},
                  "remaining_prerequisites": ["approved bwrap and seccomp filter", "isolated deployment services and runtime configuration",
                                              "operator-approved probe configuration", "successful production kernel probes"]}
        write_new(output_dir / "preparation.json", encode_json(result))
        for directory in [output_dir, *[assets / name for name in ["", *directories]]]:
            handle = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(handle)
            finally:
                os.close(handle)
        check_connections(output_links)
        return result
    except BaseException:
        if created:
            if directory_identity(os.stat(output_dir.name, dir_fd=output_parent_fd, follow_symlinks=False)) == output_identity:
                remove_tree_fd(output_parent_fd, output_dir.name)
        raise
    finally:
        close_handles(output_handles)
        close_handles(binary_handles)
        close_handles(artifact_handles)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--binary-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--install-destination", type=Path)
    parser.add_argument("--include-worker", action="store_true")
    options = parser.parse_args()
    try:
        result = prepare(options.artifact_root, options.binary_dir, options.output_dir,
                         install_destination=options.install_destination, include_worker=options.include_worker)
    except (OSError, ValueError, validation.GateError) as error:
        print(f"asset preparation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
