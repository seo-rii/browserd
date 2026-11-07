"""Native process profile contract shared by validation and release packaging.

Callers verify all declared file bytes separately. This module verifies that the
catalog bytes and their declared resources match the production launch contract.
It does not establish operator approval or deployment qualification.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re


CATALOG_PATH = "native-process-profiles.json"
MAX_CATALOG_BYTES = 1024 * 1024
MAX_RESOURCE_BYTES = 128 * 1024 * 1024


class NativeProfileArtifactError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise NativeProfileArtifactError("duplicate JSON field")
        result[key] = value
    return result


def decode_json(raw: bytes) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError) as error:
        raise NativeProfileArtifactError("invalid artifact JSON") from error
    if not isinstance(value, dict):
        raise NativeProfileArtifactError("artifact JSON must be an object")
    return value


def _path(value: object) -> str:
    if (not isinstance(value, str) or not value or "\\" in value
            or any(ord(char) < 32 for char in value)
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or PurePosixPath(value).is_absolute()):
        raise NativeProfileArtifactError("unsafe artifact resource path")
    return value


def _digest(value: object) -> str:
    if (not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            or value == "0" * 64):
        raise NativeProfileArtifactError("invalid artifact resource digest")
    return value


def validate_manifest(manifest: dict) -> dict[str, str]:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("identity"), dict):
        raise NativeProfileArtifactError("artifact identity missing")
    identity = manifest["identity"]
    binary_digest = _digest(identity.get("binary_digest"))
    catalog_digest = _digest(identity.get("launch_profile_digest"))
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise NativeProfileArtifactError("artifact files missing")
    files = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"relative_path", "digest"}:
            raise NativeProfileArtifactError("invalid artifact file entry")
        name, digest = _path(entry["relative_path"]), _digest(entry["digest"])
        if name in files:
            raise NativeProfileArtifactError("duplicate artifact file path")
        files[name] = digest
    if sum(digest == binary_digest for digest in files.values()) != 1:
        raise NativeProfileArtifactError("ambiguous or missing Chromium binary")
    if files.get(CATALOG_PATH) != catalog_digest:
        raise NativeProfileArtifactError("native catalog is not bound to launch identity")
    return files


def validate_native_catalog(manifest: dict, catalog_bytes: bytes) -> dict:
    files = validate_manifest(manifest)
    if len(catalog_bytes) > MAX_CATALOG_BYTES:
        raise NativeProfileArtifactError("native catalog exceeds its size bound")
    if hashlib.sha256(catalog_bytes).hexdigest() != files[CATALOG_PATH]:
        raise NativeProfileArtifactError("native catalog bytes differ from launch identity")
    catalog = decode_json(catalog_bytes)
    if set(catalog) != {"schema_version", "icu_data", "locales", "time_zones"}:
        raise NativeProfileArtifactError("invalid native catalog fields")
    if type(catalog["schema_version"]) is not int or catalog["schema_version"] != 1:
        raise NativeProfileArtifactError("unsupported native catalog schema")
    binary = next(name for name, digest in files.items()
                  if digest == manifest["identity"]["binary_digest"])
    icu = _path(catalog["icu_data"])
    if icu != str(PurePosixPath(binary).parent / "icudtl.dat") or icu not in files:
        raise NativeProfileArtifactError("ICU must be a verified file beside Chromium")
    locales, zones = catalog["locales"], catalog["time_zones"]
    if (not isinstance(locales, list) or not 1 <= len(locales) <= 256
            or not isinstance(zones, list) or not 1 <= len(zones) <= 1024):
        raise NativeProfileArtifactError("invalid native profile allowlist bounds")
    names = set()
    for entry in locales:
        if not isinstance(entry, dict) or set(entry) != {"locale", "pak"}:
            raise NativeProfileArtifactError("invalid native locale entry")
        locale = entry["locale"]
        if (not isinstance(locale, str) or not locale or len(locale) > 64
                or re.fullmatch(r"[A-Za-z]", locale[0]) is None
                or any(re.fullmatch(r"[A-Za-z0-9]{1,16}", part) is None for part in locale.split("-"))
                or locale in names):
            raise NativeProfileArtifactError("invalid or duplicate native locale")
        names.add(locale)
        if _path(entry["pak"]) not in files:
            raise NativeProfileArtifactError("locale pak is not a verified artifact file")
    names = set()
    for zone in zones:
        if (not isinstance(zone, str) or not zone or len(zone) > 128
                or any(re.fullmatch(r"[A-Za-z0-9_+\-]+", part) is None for part in zone.split("/"))
                or zone in names):
            raise NativeProfileArtifactError("invalid or duplicate native timezone")
        names.add(zone)
    return catalog
