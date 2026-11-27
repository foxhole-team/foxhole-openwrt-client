#!/usr/bin/env python3
"""Inspect selected installed package files in an authenticated OpenWrt factory image."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PRIMARY = "8A8BC12F46B836C0F9CDB36F1D53D1877742E911"
SIGNING = "92C561DE55AE6552F3C736B82B0151090606D1D9"
KEY_HASH = "334d8760642bf986e87ffa4eef3860df11941c38241956a9ebc6d90f8ab6f9a3"
BOARDS = {"25.12.5": "cudy,wr3000-v1", "25.12.6": "cudy,wr3000s-v1"}
DATA_MARKER = b"\n#\n# START OF DATA - DO NOT MODIFY\n#\n"
PACKAGE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}")
SHA = re.compile(r"[a-f0-9]{64}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(data):
    def object_from_pairs(rows):
        out = {}
        for key, value in rows:
            require(key not in out, "Duplicate JSON field")
            out[key] = value
        return out
    return json.loads(data, object_pairs_hook=object_from_pairs)


def raw(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                not before.st_mode & 0o022 and 0 < before.st_size <= limit,
                "A bounded, protected regular input is required")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require((before.st_size, before.st_ctime_ns, before.st_mtime_ns) ==
            (len(data), after.st_ctime_ns, after.st_mtime_ns), "Input changed during review")
    return data


def image_hash(sums, filename):
    matches = []
    for line in sums.decode("ascii").splitlines():
        row = re.fullmatch(r"([a-f0-9]{64}) [ *](.+)", line)
        if row and row[2] == filename:
            matches.append(row[1])
    require(len(matches) == 1, "Expected exactly one signed checksum for this release and board")
    return matches[0]


def bundle_selection(directory, anchor, release, board, mode):
    sums = raw(directory / "SHA256SUMS", 1048576)
    require(SHA.fullmatch(anchor) and sha(sums) == anchor, "Bundle manifest digest differs")
    entries = {}
    for line in sums.decode("ascii").splitlines():
        row = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,159})", line)
        require(row and row[2] not in entries, "Invalid native bundle manifest")
        entries[row[2]] = row[1]

    def document(name, digest):
        require(name in entries and digest == entries[name], "Unbound installation metadata")
        data = raw(directory / name, 2097152)
        require(sha(data) == digest, "Installation metadata digest differs")
        return strict_json(data)

    catalog = document("package-catalog.json", entries.get("package-catalog.json"))
    require(catalog.get("schema") == 2 and catalog.get("kind") == "compact-client-engines-v1" and
            catalog.get("development") is False, "A release compact catalog is required")
    choices = [row for row in catalog["platforms"] if row.get("supportedOpenWrt") == [release] and
               row.get("supportedTargets") == ["mediatek/filogic"] and row.get("architecture") == "aarch64_cortex-a53"
               and row.get("freshInstallBoard") == {"boardName": board, "storageMode": mode}]
    require(len(choices) == 1, "Expected one catalog entry for the exact factory model")
    platform = choices[0]
    clients = [c for c in platform["clients"] if c["id"] == "hysteria2" and c["storage"] == mode]
    require(len(clients) == 1 and clients[0]["entry"]["id"] == "hysteria2" and
            clients[0]["entry"]["storage"] == mode.upper(), "Expected a single Hysteria2 module")
    uni = platform["packageUniverse"]
    universe = document(uni["file"], uni["sha256"])
    require(universe.get("architecture") == platform["architecture"] and universe.get("supportedOpenWrt") == [release]
            and universe.get("supportedTargets") == ["mediatek/filogic"], "Package universe platform differs")
    package_rows = {r["name"]: r for r in universe["packages"]}
    auth = {r["name"]: r for r in universe["packageAuthentications"]}
    require(0 < len(package_rows) == len(universe["packages"]) == len(auth) == len(universe["packageAuthentications"])
            <= 512, "Ambiguous package universe")
    roots = [platform["basePackage"]["name"], clients[0]["entry"]["packageName"]]
    require(roots[0] == "foxhole-openwrt-client", "Unexpected BASE identity")
    selected, pending = {}, roots.copy()
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        row, binding = package_rows[name], auth[name]
        require(PACKAGE.fullmatch(name) and SHA.fullmatch(binding["packageIdentity"]) and
                row["file"] == binding["file"] and row["version"] == binding["version"] and row["arch"] == binding["architecture"]
                and entries.get(row["file"]) == row["sha256"] == universe["filesSha256"].get(row["file"]),
                "Incomplete selected package identity")
        selected[name] = dict(version=row["version"], architecture=row["arch"], archive=row["file"],
                              archiveSha256=row["sha256"], signedIndexIdentity=binding["packageIdentity"])
        dependencies = universe["requires"][name]
        require(isinstance(dependencies, list) and len(dependencies) == len(set(dependencies)), "Invalid closure")
        pending.extend(dependencies)
    return dict(bundleManifestSha256=anchor, catalogSha256=entries["package-catalog.json"],
                universeSha256=uni["sha256"], protocol="hysteria2", roots=roots, packages=selected)


def verify_sums(sums, signature, work):
    key = raw(ROOT / "config/openwrt-firmware-signer.asc", 16384)
    require(sha(key) == KEY_HASH, "The OpenWrt firmware signing key changed")
    ring = work / "firmware.gpg"
    for name, data in [("checksums", sums), ("signature", signature)]:
        (work / name).write_bytes(data)
    subprocess.run(["gpg", "--no-options", "--homedir", str(work), "--batch", "--dearmor",
                    "--output", str(ring)], input=key, check=True, capture_output=True, timeout=20)
    check = subprocess.run(["gpgv", "--homedir", str(work), "--keyring", str(ring),
                            "--status-fd", "1", str(work / "signature"), str(work / "checksums")],
                           check=True, capture_output=True, timeout=30)
    events = [line.split() for line in check.stdout.decode("ascii").splitlines()]
    valid = [row for row in events if row[:2] == ["[GNUPG:]", "VALIDSIG"]]
    require(len(valid) == 1 and len(valid[0]) == 12 and valid[0][2] == SIGNING and
            valid[0][8:11] == ["22", "8", "00"] and valid[0][11] == PRIMARY,
            "The checksums require the expected OpenWrt firmware signature")
    forbidden = {"REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG", "NO_PUBKEY"}
    require(not any(len(row) > 1 and row[1] in forbidden for row in events),
            "The firmware signature is expired, revoked or invalid")


def relative(name):
    require(0 < len(name) <= 1024 and all(0x20 < ord(c) < 0x7f and c != "\\" for c in name)
            and all(part not in ("", ".", "..") for part in name.split("/")),
            "Unexpected path in stock filesystem")
    return name


def squash_offset(image):
    candidates = []
    pos = image.find(b"hsqs")
    while pos >= 0:
        if pos + 96 <= len(image) and image[pos+28:pos+32] == b"\x04\0\0\0":
            size = struct.unpack_from("<Q", image, pos + 40)[0]
            if 96 <= size <= len(image) - pos:
                candidates.append(pos)
        pos = image.find(b"hsqs", pos + 4)
    require(len(candidates) == 1, "Expected one complete SquashFS v4 filesystem")
    return candidates[0]


def parse_pseudo(data):
    prefix, sep, body = data.partition(DATA_MARKER)
    require(sep and len(prefix) < 4 * 1024 * 1024, "Unsupported SquashFS metadata")
    result, ranges = {}, []
    for line in prefix.decode("ascii").splitlines():
        row = line.split(" ")
        require(len(row) >= 6, "Incomplete SquashFS entry")
        path, kind, stamp, mode, uid, gid = row[:6]
        path = "/" if path == "/" else relative(path)
        require(path not in result and re.fullmatch(r"[0-7]{1,4}", mode)
                and all(x.isdecimal() for x in [stamp, uid, gid]), "Invalid SquashFS ownership")
        entry = dict(type=kind, mode=int(mode, 8), uid=int(uid), gid=int(gid))
        if kind == "R":
            require(len(row) == 9 and row[6].isdecimal() and row[7].isdecimal() and row[8] == "0",
                    "Unsupported regular file in SquashFS")
            size, offset = int(row[6]), int(row[7])
            require(offset + size <= len(body), "Signed filesystem data is truncated")
            entry.update(bytes=size, offset=offset)
            if size:
                ranges.append((offset, size))
        elif kind == "S":
            require(len(row) == 7 and row[6], "Invalid SquashFS symlink")
            entry["target"] = row[6]
        elif kind == "C":
            require(path == "dev/console" and row[6:] == ["5", "1"], "Unexpected device node")
        else:
            require(kind == "D" and len(row) == 6, "Unsupported SquashFS metadata or extended attribute")
        result[path] = entry
    cursor = 0
    for offset, size in sorted(ranges):
        require(offset == cursor, "Ambiguous SquashFS data ranges")
        cursor += size
    require(cursor == len(body) and result.get("/", {}).get("type") == "D", "Incomplete SquashFS")
    return result, body


def file_bytes(entry, body):
    require(entry["type"] == "R", "A regular factory file is required")
    return body[entry["offset"]:entry["offset"] + entry["bytes"]]


def owned_files(db, factory=True):
    require(0 < len(db) < 1048576 and db.endswith(b"\n\n"), "Incomplete factory APK database")
    packages, owners = {}, {}
    for block in db.decode().removesuffix("\n\n").split("\n\n"):
        fields, paths, directory = {}, [], None
        for line in block.splitlines():
            require(len(line) >= 2 and line[1] == ":", "Malformed APK field")
            field, value = line[0], line[2:]
            if field in "PCVAf":
                require(field not in fields, "Duplicate APK identity field")
                fields[field] = value
            elif field == "F":
                directory = relative(value) if value else ""
            elif field == "R":
                require(directory is not None and "/" not in value, "Invalid APK file ownership")
                paths.append(relative("/".join(x for x in (directory, value) if x)))
        require(all(fields.get(k) for k in "PCVA") and PACKAGE.fullmatch(fields["P"]) and
                (not factory or fields.get("f") == "S") and re.fullmatch(r"Q1[A-Za-z0-9+/]{27}=", fields["C"]),
                "Invalid signed factory package identity")
        name = fields["P"]
        require(name not in packages, "Duplicate package in factory database")
        for path in paths:
            require(path not in owners, "A factory file has multiple package owners")
            owners[path] = name
        packages[name] = dict(version=fields["V"], architecture=fields["A"], flags=fields.get("f", ""),
                              databaseRecordSha256=sha(block.encode()),
                              cid=base64.b64decode(fields["C"][2:], validate=True).hex(), files=paths)
    return packages


def inventory(entries, body, selected):
    db = file_bytes(entries["lib/apk/db/installed"], body)
    packages = owned_files(db)
    records = {}
    for name in sorted(selected):
        require(name in packages and PACKAGE.fullmatch(name), "Package is absent from factory image")
        item = packages[name]
        config_path = "lib/apk/packages/" + name + ".conffiles"
        mutable, directories = set(), set()
        if config_path in entries:
            for path in file_bytes(entries[config_path], body).decode("ascii").splitlines():
                require(path.startswith("/etc/"), "Unsupported factory configuration location")
                clean = relative(path[1:].removesuffix("/"))
                if path.endswith("/") or entries.get(clean, {}).get("type") == "D":
                    directories.add(clean)
                else:
                    require(clean in item["files"] or clean not in entries, "Unowned configuration file")
                    mutable.add(clean)
        files = {}
        for path in sorted(item["files"]):
            entry = entries[path]
            require(entry["type"] in ("R", "S"), "Unsupported factory package entry")
            record = {k: v for k, v in entry.items() if k != "offset"}
            if entry["type"] == "R":
                record["sha256"] = sha(file_bytes(entry, body))
            if path in mutable or any(path.startswith(parent + "/") for parent in directories):
                record["policy"] = "configuration"
            elif path.startswith("etc/uci-defaults/"):
                record["policy"] = "first-boot-script"
            else:
                record["policy"] = "immutable"
            files[path] = record
        records[name] = {**item, "files": files, "configurationFiles": sorted(mutable),
                         "configurationDirectories": sorted(directories)}
    paths = {path for record in records.values() for path in record["files"]}
    for record in records.values():
        for path, facts in record["files"].items():
            if facts["type"] == "S":
                target, chain = path, set()
                while entries[target]["type"] == "S":
                    require(target not in chain and len(chain) < 16, "Cycle in factory symlinks")
                    chain.add(target)
                    target = posixpath.normpath(posixpath.join("/" + posixpath.dirname(target),
                                                               entries[target]["target"])).lstrip("/")
                    require(target in paths, "Select the package owning the immutable symlink target")
                require(entries[target]["type"] == "R", "Unqualified factory symlink endpoint")
    roots = {"etc/openwrt_release", "etc/board.json", "lib/apk/db/installed"} | paths
    directories = {}
    for path in roots:
        for ancestor in Path(path).parents:
            if str(ancestor) == ".":
                continue
            entry = entries[str(ancestor)]
            require(entry["type"] == "D", "A selected path has a non-directory parent")
            directories[str(ancestor)] = dict(entry)
    return {"installedDatabaseSha256": sha(db), "packages": records, "directories": directories,
            "openWrtReleaseSha256": sha(file_bytes(entries["etc/openwrt_release"], body))}


def match_entry(path, expected, actual):
    policy = expected.get("policy", "immutable")
    if actual is None:
        require(policy == "first-boot-script", "Missing factory file: " + path)
        return
    require(all(actual.get(k) == expected.get(k) for k in ("type", "uid", "gid")),
            "File type or ownership differs: " + path)
    if policy == "configuration" and expected["type"] == "R":
        require(actual["mode"] & ~expected["mode"] == 0, "Configuration permissions expanded: " + path)
    else:
        require(all(actual.get(k) == expected.get(k) for k in ("mode", "bytes", "target", "sha256")),
                "Immutable stock file differs: " + path)


def compare_snapshot(profile, snapshot):
    selected = profile["packages"]
    expected = {path: member for pkg in selected.values() for path, member in pkg["files"].items()}
    expected.update(profile["directories"])
    configs = {path for pkg in selected.values() for path in pkg["configurationFiles"]}
    config_dirs = {path for pkg in selected.values() for path in pkg["configurationDirectories"]}
    metadata = {"lib/apk/db/installed", "etc/board.json", "etc/openwrt_release"}
    actual, config_state, contents, visited = {}, {}, {}, set()
    with tarfile.open(fileobj=io.BytesIO(raw(snapshot, 128 * 1024 * 1024)), mode="r:") as archive:
        for member in archive:
            path = member.name.removeprefix("./")
            if path in ("", ".") and member.isdir():
                continue
            path = relative(path)
            require(path not in visited and len(visited) < 16384, "Ambiguous or excessive snapshot entries")
            visited.add(path)
            config = path in configs or path in config_dirs or any(path.startswith(x + "/") for x in config_dirs)
            if path not in expected and path not in metadata and not config:
                continue
            require(not any("xattr" in k.lower() or "acl" in k.lower() for k in member.pax_headers),
                    "Unqualified extended file metadata: " + path)
            kind = "R" if member.isfile() else "S" if member.issym() else "D" if member.isdir() else None
            require(kind and 0 <= member.size <= 16 * 1024 * 1024, "Unqualified snapshot entry: " + path)
            facts = dict(type=kind, mode=member.mode & 0o7777, uid=member.uid, gid=member.gid)
            if kind == "R":
                data = archive.extractfile(member).read()
                require(len(data) == member.size, "Truncated snapshot file")
                facts.update(bytes=member.size, sha256=sha(data))
                if path in metadata:
                    require(len(data) <= 1048576 and member.uid == 0 and member.gid == 0 and
                            not member.mode & 0o022, "Unsafe device identity metadata")
                    contents[path] = data
            elif kind == "S":
                facts["target"] = member.linkname
            if config:
                require(kind in ("R", "D") and member.uid == 0 and not member.mode & 0o022,
                        "Cannot preserve configuration safely: " + path)
                config_state[path] = facts
            actual[path] = facts
    require(set(contents) == metadata and sha(contents["etc/openwrt_release"]) == profile["openWrtReleaseSha256"]
            and strict_json(contents["etc/board.json"]).get("model", {}).get("id") == profile["board"],
            "Observed board or firmware differs")
    installed = owned_files(contents["lib/apk/db/installed"], factory=False)
    for name, package in selected.items():
        observed = installed.get(name, {})
        require(all(observed.get(k) == package[k] for k in ("version", "architecture", "flags", "cid", "databaseRecordSha256"))
                and set(observed.get("files", [])) == set(package["files"]),
                "Installed package identity or ownership differs: " + name)
    for path, member in expected.items():
        match_entry(path, member, actual.get(path))
    return dict(immutableAndConfigurationPaths=len(expected), selectedPackages=sorted(selected),
                configurationEntries=len(config_state),
                configurationSha256=sha(json.dumps(config_state, sort_keys=True, separators=(",", ":")).encode()),
                liveInstalledDatabaseSha256=sha(contents["lib/apk/db/installed"]),
                scope="Offline selected package verification. No installation or rollback admission.")


def inspect(args):
    board = BOARDS[args.release]
    mode = "ram" if args.release == "25.12.5" else "flash"
    require(args.board == board, "Board and firmware pair is outside the stock qualification set")
    name = f"openwrt-{args.release}-mediatek-filogic-{board.replace(',', '_')}-squashfs-sysupgrade.bin"
    sums = raw(args.checksums, 1048576)
    signature = raw(args.signature, 16384)
    with tempfile.TemporaryDirectory(prefix="foxhole-stock-") as temp:
        work = Path(temp).resolve()
        verify_sums(sums, signature, work)
        expected = image_hash(sums, name)
        image = raw(args.image, 32 * 1024 * 1024)
        require(sha(image) == expected, "Firmware image differs from the verified signed checksums")
        offset = squash_offset(image)
        (work / "verified.bin").write_bytes(image)
        subprocess.run([args.unsquashfs, "-processors", "1", "-no-progress", "-pf", str(work / "image.pf"),
                        "-o", str(offset), str(work / "verified.bin")], check=True,
                       capture_output=True, timeout=60)
        entries, body = parse_pseudo(raw(work / "image.pf", 64 * 1024 * 1024))
    release = file_bytes(entries["etc/openwrt_release"], body).decode("ascii").splitlines()
    require(f"DISTRIB_RELEASE='{args.release}'" in release and "DISTRIB_TARGET='mediatek/filogic'" in release
            and "DISTRIB_ARCH='aarch64_cortex-a53'" in release, "Signed factory release identity differs")
    selection = None
    if args.bundle:
        selection = bundle_selection(args.bundle, args.manifest_sha256, args.release, board, mode)
        installed = owned_files(file_bytes(entries["lib/apk/db/installed"], body))
        selected = set(selection["packages"]).intersection(installed)
        selection["factoryPackagesInClosure"] = sorted(selected)
        if "dnsmasq-full" in selection["packages"] and "dnsmasq" in installed:
            selected.add("dnsmasq")
    else:
        selected = set(args.package)
    result = dict(schema=1, kind="stock-factory-package-inventory", board=board, release=args.release, storageMode=mode,
                target="mediatek/filogic", architecture="aarch64_cortex-a53", firmwareFile=name,
                imageSha256=expected, checksumsSha256=sha(sums), signatureSha256=sha(signature),
                signingFingerprint=SIGNING, primaryFingerprint=PRIMARY,
                **inventory(entries, body, selected))
    if selection is not None:
        result["selection"] = selection
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, choices=BOARDS)
    parser.add_argument("--board", required=True)
    parser.add_argument("--checksums", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--package", action="append", help="Inspect a named subset for diagnostics")
    options.add_argument("--bundle", type=Path, help="Resolve every stock package in the Hysteria2 closure")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--observation-tar", type=Path,
                        help="Compare a bounded uncompressed lab filesystem snapshot to this verified factory image")
    parser.add_argument("--unsquashfs", default="unsquashfs")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--witness-output", type=Path,
                        help="Emit the stock package witness for the authenticated installer catalog")
    args = parser.parse_args()
    if bool(args.bundle) != bool(args.manifest_sha256):
        parser.error("--bundle and its trusted --manifest-sha256 must be supplied together")
    if args.witness_output and not args.bundle:
        parser.error("A witness requires the full selected bundle closure")
    report = inspect(args)
    if args.observation_tar:
        report["observation"] = compare_snapshot(report, args.observation_tar)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    if args.witness_output:
        witness = {key: report[key] for key in
                   ("schema", "board", "release", "storageMode", "target", "architecture", "firmwareFile",
                    "imageSha256", "checksumsSha256", "signatureSha256", "signingFingerprint",
                    "primaryFingerprint", "packages", "directories", "openWrtReleaseSha256")}
        witness.update(kind="stock-installed-files-v1", protocol="hysteria2",
                       closurePackages=sorted(report["selection"]["packages"]))
        with args.witness_output.open("x", encoding="utf-8") as output:
            json.dump(witness, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")


if __name__ == "__main__":
    main()
