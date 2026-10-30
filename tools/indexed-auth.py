#!/usr/bin/env python3
"""Verify original signed APK indexes and their complete offline payload closure."""
from __future__ import annotations

import hashlib
import errno
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

MODEL = "canonical-apk-and-upstream-index-v1"
CANONICAL_PUBLIC_SHA = "fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1"
OWN = {"foxcore-cli", "foxcore-cli-ram", "foxhole-openwrt-client", "hysteria", "hysteria-server-ram"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}")
PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.~+-]{0,159}")
SHA = re.compile(r"[a-f0-9]{64}")
MAX_INDEX = 8388608
MAX_DUMP = 67108864


def upstream_url(value: dict, url: object) -> bool:
    if not isinstance(url, str):
        return False
    architecture = value.get("architecture", "")
    if not isinstance(architecture, str) or not NAME.fullmatch(architecture):
        return False
    versions, targets = value.get("supportedOpenWrt"), value.get("supportedTargets")
    if not isinstance(versions, list) or not isinstance(targets, list) or not versions or not targets:
        return False
    for version in versions:
        if not isinstance(version, str) or not re.fullmatch(r"25\.12\.[0-9]+", version):
            return False
        prefix = "https://downloads.openwrt.org/releases/" + version + "/"
        if re.fullmatch(re.escape(prefix + "packages/" + architecture + "/") +
                        r"[A-Za-z0-9_.+-]+/packages\.adb", url):
            return True
        for target in targets:
            if target not in ("x86/64", "armsr/armv8", "mediatek/filogic"):
                return False
            if (url == prefix + "targets/" + target + "/packages/packages.adb" or
                    re.fullmatch(re.escape(prefix + "targets/" + target + "/kmods/") +
                                 r"[A-Za-z0-9_.-]+/packages\.adb", url)):
                return True
    return False


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Regular authentication asset required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise ValueError("Invalid authentication byte count")
    return value


def asset(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError("Unsafe authentication asset name")
    path = root / name
    digest(path)
    return path


def stage(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
        shutil.copyfile(source, destination)


def identity(item: dict) -> tuple[str, str, str]:
    if (not isinstance(item, dict) or not PACKAGE.fullmatch(item.get("name", "")) or
            not VERSION.fullmatch(item.get("version", "")) or
            not NAME.fullmatch(item.get("architecture", ""))):
        raise ValueError("Unsafe indexed package identity")
    return item["name"], item["version"], item["architecture"]


def schema(value: dict, packages: list[dict], *, own_names: frozenset[str] | None = None) -> tuple[list[dict], list[dict], set[str]]:
    owned = OWN if own_names is None else own_names
    if (not isinstance(owned, (set, frozenset)) or not owned or len(owned) > 26 or
            any(not isinstance(name, str) or not PACKAGE.fullmatch(name) for name in owned)):
        raise ValueError("Exact bounded owned package identities required")
    verification = value.get("verification", {})
    if (verification.get("signatureModel") != MODEL or
            not SHA.fullmatch(verification.get("factorySourceSha256", ""))):
        raise ValueError("Original firmware-bound indexed authentication required")
    indexes = value.get("repositoryIndexes")
    bindings = value.get("packageAuthentications")
    if (not isinstance(indexes, list) or not 1 <= len(indexes) <= 16 or
            not isinstance(bindings, list) or len(bindings) != len(packages) or
            not packages or len(packages) > 256):
        raise ValueError("Bounded complete indexed authentication required")
    files, keys, by_file, key_roles = set(), set(), {}, {}
    for item in indexes:
        if (not isinstance(item, dict) or not NAME.fullmatch(item.get("file", "")) or
                item["file"] in files or not SHA.fullmatch(item.get("sha256", "")) or
                not 1 <= integer(item.get("bytes")) <= MAX_INDEX or
                item.get("role") not in ("foxhole", "upstream")):
            raise ValueError("Invalid original repository index")
        url = urlsplit(item.get("sourceUrl", ""))
        if (len(item.get("sourceUrl", "")) > 4096 or url.scheme != "https" or not url.hostname or
                url.username or url.password or url.port is not None or url.fragment or url.query or
                "%" in item["sourceUrl"] or any(part in (".", "..") for part in url.path.split("/"))):
            raise ValueError("Public HTTPS index provenance required")
        if item["role"] == "foxhole" and (url.hostname != "github.com" or not re.fullmatch(
                r"/foxhole-team/foxhole-openwrt-client/releases/download/v[0-9]+\.[0-9]+\.[0-9]+"
                r"(?:[-+][A-Za-z0-9.-]+)?/[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.adb", url.path)):
            raise ValueError("Exact FoxHole release index provenance required")
        if item["role"] == "upstream" and not upstream_url(value, item["sourceUrl"]):
            raise ValueError("Official upstream index provenance required")
        trust = item.get("trustKeyFiles")
        if (not isinstance(trust, list) or not 1 <= len(trust) <= 16 or
                len(set(trust)) != len(trust) or
                any(not isinstance(key, str) or not NAME.fullmatch(key) for key in trust)):
            raise ValueError("Exact role-specific trust keys required")
        if item["role"] == "foxhole" and trust != ["foxhole-openwrt-apk.pem"]:
            raise ValueError("Canonical public-key asset name required")
        files.add(item["file"])
        for key in trust:
            if key in key_roles and key_roles[key] != item["role"]:
                raise ValueError("Trust key cannot cross repository roles")
            key_roles[key] = item["role"]
        keys.update(trust)
        by_file[item["file"]] = item
    if len(keys) > 32 or keys & files:
        raise ValueError("Ambiguous index/key assets")
    trust = value.get("trustKeys")
    if not isinstance(trust, list) or len(trust) != len(keys):
        raise ValueError("Complete public trust-key byte authority required")
    key_records, key_hashes = {}, set()
    for item in trust:
        if (not isinstance(item, dict) or not NAME.fullmatch(item.get("file", "")) or
                item["file"] in key_records or not SHA.fullmatch(item.get("sha256", "")) or
                item["sha256"] in key_hashes or
                not 1 <= integer(item.get("bytes")) <= 16384 or
                value.get("filesSha256", {}).get(item["file"]) != item["sha256"]):
            raise ValueError("Invalid trust-key byte record")
        if (key_roles.get(item["file"]) == "foxhole") != (item["sha256"] == CANONICAL_PUBLIC_SHA):
            raise ValueError("Public signing authority differs from repository role")
        key_records[item["file"]] = item
        key_hashes.add(item["sha256"])
    if set(key_records) != keys:
        raise ValueError("Unused or missing public trust-key asset")
    records = {item["file"]: item for item in packages}
    if len(records) != len(packages) or set(records) & (files | keys):
        raise ValueError("Ambiguous indexed package assets")
    seen = set()
    for item in bindings:
        ident = identity(item)
        record = records.get(item.get("file"))
        index = by_file.get(item.get("indexFile"))
        if (record is None or item["file"] in seen or index is None or
                ident != (record["name"], record["version"], record["arch"]) or
                not SHA.fullmatch(item.get("packageIdentity", "")) or
                (index["role"] == "foxhole") != (record["name"] in owned)):
            raise ValueError("Package is not bound to its role-specific signed index")
        seen.add(item["file"])
    if seen != set(records):
        raise ValueError("Incomplete indexed package bindings")
    if set(value.get("filesSha256", {})) != set(records) | files | keys:
        raise ValueError("Exact package/index/key manifest required")
    if integer(value.get("repositoryIndexBytes")) != sum(item["bytes"] for item in indexes):
        raise ValueError("Repository index byte total differs")
    if integer(value.get("trustKeyBytes")) != sum(item["bytes"] for item in trust):
        raise ValueError("Trust-key byte total differs")
    return indexes, bindings, keys


def run(command: list[str], timeout: int = 120) -> bytes:
    result = subprocess.run(command, capture_output=True, check=True, timeout=timeout)
    if b"ERROR:" in result.stderr or b"ERROR:" in result.stdout:
        raise ValueError("Native APK authentication or solver refused the closure")
    return result.stdout


def dump(apk: str, path: Path) -> dict:
    raw = run([apk, "adbdump", "--format", "json", str(path)])
    if len(raw) > MAX_DUMP:
        raise ValueError("Repository metadata exceeds limit")
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get("pkgname-spec") not in
            (None, "${name}-${version}.apk") or
            not isinstance(value.get("packages"), list) or
            not 1 <= len(value["packages"]) <= 50000):
        raise ValueError("Unsupported original repository naming or metadata")
    return value


def verify(apk: str, root: Path, value: dict, packages: list[dict], roots: list[str],
           architecture: str, factory_keys: Path, *, own_names: frozenset[str] | None = None) -> dict:
    indexes, bindings, key_names = schema(value, packages, own_names=own_names)
    owned = OWN if own_names is None else own_names
    factory = {digest(path) for path in factory_keys.iterdir() if path.is_file() and not path.is_symlink()}
    if not factory or CANONICAL_PUBLIC_SHA in factory:
        raise ValueError("Independent original firmware trust keys required")
    for name, expected in value["filesSha256"].items():
        if not SHA.fullmatch(expected) or digest(asset(root, name)) != expected:
            raise ValueError("Authentication asset differs from anchored metadata")
    if sum(asset(root, name).stat().st_size for name in key_names) != value["trustKeyBytes"]:
        raise ValueError("Trust-key byte total differs")
    if any(asset(root, item["file"]).stat().st_size != item["bytes"] for item in value["trustKeys"]):
        raise ValueError("Public trust-key asset byte count differs")
    if not roots or len(set(roots)) != len(roots) or not set(roots) <= {item["name"] for item in packages}:
        raise ValueError("Exact nonempty indexed root packages required")
    with tempfile.TemporaryDirectory(prefix="foxhole-indexed-apk-") as temporary:
        work = Path(temporary)
        combined = work / "keys"
        combined.mkdir()
        repositories = work / "repositories.list"
        repo_paths = {}
        metadata = {}
        trusted_paths = {}
        for index in indexes:
            path = asset(root, index["file"])
            if path.stat().st_size != index["bytes"]:
                raise ValueError("Original index byte count differs")
            directory = work / index["file"]
            directory.mkdir()
            trusted = directory / "keys"
            trusted.mkdir()
            for name in index["trustKeyFiles"]:
                key = asset(root, name)
                key_hash = digest(key)
                allowed = {CANONICAL_PUBLIC_SHA} if index["role"] == "foxhole" else factory
                if key_hash not in allowed:
                    raise ValueError("Repository trust role differs from original authority")
                if key.stat().st_size > 16384:
                    raise ValueError("Bounded public trust key required")
                shutil.copyfile(key, trusted / name)
                if not (combined / name).exists():
                    shutil.copyfile(key, combined / name)
            run([apk, "--keys-dir", str(trusted), "verify", str(path)])
            original = directory / "packages.adb"
            stage(path, original)
            repo_paths[index["file"]] = directory
            trusted_paths[index["file"]] = trusted
            metadata[index["file"]] = dump(apk, original)
        for binding in bindings:
            matches = [item for item in metadata[binding["indexFile"]]["packages"]
                       if (item.get("name"), item.get("version"), item.get("arch")) == identity(binding)]
            if len(matches) != 1 or matches[0].get("hashes") != binding["packageIdentity"]:
                raise ValueError("Package identity differs from the original signed entry")
            record = next(item for item in packages if item["file"] == binding["file"])
            if (matches[0].get("file-size") != record["archiveBytes"] or
                    matches[0].get("installed-size") != record["installedBytes"]):
                raise ValueError("Package sizes differ from the signed index")
            source = asset(root, binding["file"])
            raw_name = binding["name"] + "-" + binding["version"] + ".apk"
            stage(source, repo_paths[binding["indexFile"]] / raw_name)
            if binding["name"] in owned:
                run([apk, "--keys-dir", str(trusted_paths[binding["indexFile"]]), "verify", str(source)])
        repositories.write_text("".join(str(path / "packages.adb") + "\n" for path in repo_paths.values()))
        database = work / "database"
        database.mkdir()
        cache = work / "cache"
        cache.mkdir()
        common = [apk, "--root", str(database), "--arch", architecture, "--no-network", "--no-cache",
                  "--repositories-file", str(repositories), "--keys-dir", str(combined), "--cache-dir", str(cache)]
        usermode = ["--usermode"] if os.geteuid() != 0 else []
        run(common + ["add", "--initdb", *usermode])
        by_name = {item["name"]: item for item in packages}
        if len(by_name) != len(packages):
            raise ValueError("Duplicate package names in closure")
        requests = [name + "=" + by_name[name]["version"] for name in sorted(roots)]
        selected = json.loads(run(common + ["query", "--format", "json", "--recursive", *requests]))
        expected = {(item["name"], item["version"], item["arch"]) for item in packages}
        if (not isinstance(selected, list) or len(selected) != len(expected) or
                {(item.get("name"), item.get("version"), item.get("arch")) for item in selected} != expected):
            raise ValueError("Indexed solver closure differs from the complete payload")
        # Existing files and --link skip native identity checks.
        fetched = work / "verified-fetch"
        fetched.mkdir()
        run(common + ["fetch", "--recursive", "--output", str(fetched), *requests], timeout=600)
        expected_files = {item["name"] + "-" + item["version"] + ".apk": item for item in packages}
        if {path.name for path in fetched.iterdir()} != set(expected_files):
            raise ValueError("Native authenticated fetch is incomplete")
        for name, record in expected_files.items():
            if digest(fetched / name) != record["sha256"]:
                raise ValueError("Fetched APK differs from the anchored archive")
        run(common + ["add", "--simulate", *usermode, *requests])
    return {"signatureModel": MODEL, "signatures": True,
            "factorySourceSha256": value["verification"]["factorySourceSha256"],
            "resolver": "apk add --simulate --no-network"}
