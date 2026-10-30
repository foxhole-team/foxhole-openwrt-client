#!/usr/bin/env python3
"""Read real APK metadata and refuse incomplete installation closures."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

DEPENDENCY = re.compile(r"^(!?)([A-Za-z0-9_.+:/,\[\]-]+)(?:([<>~]=?|=)(.+))?$")
MAX_BYTES = 2**53 - 1
spec = importlib.util.spec_from_file_location("indexed_auth", Path(__file__).with_name("indexed-auth.py"))
indexed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(indexed)
spec = importlib.util.spec_from_file_location("hysteria_provenance", Path(__file__).with_name("hysteria_provenance.py"))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


def file_hash(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Regular artifact required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_core_payload(apk: str, paths: list[Path], packages: list[dict], producer: dict,
                        producer_path: Path, mode: str, keys: Path | None,
                        development: bool, volatile: Path | None = None) -> dict:
    expected = "foxcore-cli" if mode == "flash" else "foxcore-cli-ram"
    core = [item for item in packages if item["name"] in ("foxcore-cli", "foxcore-cli-ram")]
    if len(core) != 1 or core[0]["name"] != expected:
        raise ValueError("Exactly one matching Core storage package required")
    package = next(path for path in paths if path.name == core[0]["file"])
    with tempfile.TemporaryDirectory(prefix="foxhole-core-payload-") as temporary:
        root = Path(temporary)
        command = [apk]
        command += ["--allow-untrusted"] if development else ["--keys-dir", str(keys)]
        command += ["extract", "--no-chown", "--destination", str(root), str(package)]
        subprocess.run(command, capture_output=True, check=True, timeout=60)
        def safe(relative: str) -> Path:
            path = root
            for part in Path(relative).parts:
                path = path / part
                if path.is_symlink():
                    raise ValueError("Core payload contains a symlink")
            if not path.is_file():
                raise ValueError("Core payload file is absent")
            return path
        receipt = safe("usr/share/foxhole/core-producer.json")
        if file_hash(receipt) != file_hash(producer_path):
            raise ValueError("Core APK contains a different native producer")
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            if file_hash(safe("usr/share/licenses/foxcore-cli/" + name)) != producer["filesSha256"][name]:
                raise ValueError("Core APK license digest mismatch")
        if mode == "flash":
            digest = file_hash(safe("usr/bin/foxcore-cli"))
        else:
            if volatile is None:
                raise ValueError("Core RAM payload required")
            lines = safe("usr/share/foxhole/core-download.txt").read_text().splitlines()
            if len(lines) != 4 or lines[1] != producer["binarySha256"] or lines[2] != str(volatile.stat().st_size):
                raise ValueError("Core RAM wrapper does not bind the volatile producer")
            if not lines[3].isdigit() or int(lines[3]) < 1:
                raise ValueError("Core RAM wrapper runtime reserve is missing")
            digest = file_hash(volatile)
        if digest != producer["binarySha256"]:
            raise ValueError("Installed Core binary differs from the native producer")
    return {"file": package.name, "sha256": file_hash(package),
            "binarySha256": digest, "producerSha256": file_hash(producer_path),
            "payloadVerified": True}


def verify_server_payload(apk: str, paths: list[Path], packages: list[dict], producer_path: Path,
                          mode: str, keys: Path | None, development: bool,
                          volatile: Path | None = None) -> dict:
    producer = json.loads(producer_path.read_text())
    expected = "hysteria" if mode == "flash" else "hysteria-server-ram"
    found = [item for item in packages if item["name"] in ("hysteria", "hysteria-server-ram", "hysteria-ram")]
    if len(found) != 1 or found[0]["name"] != expected:
        raise ValueError("Exactly one separate incoming server package required")
    if (type(producer.get("schema")) is not int or producer["schema"] != 1 or
            type(producer.get("exitCode")) is not int or producer["exitCode"] != 0 or
            producer.get("name") != "hysteria" or producer.get("version") != "2.12.2" or
            producer.get("sourceSha256") != "8db04a112e73685a1e5916d5d4d3df3ed897dbabc3e639fda4880b7ca9a7d18e"):
        raise ValueError("Actual incoming server source producer required")
    provenance.verify(producer, producer_path.parent)
    required_legal = set(provenance.LICENSES + provenance.PROVENANCE_FILES)
    if (set(producer.get("filesSha256", {})) != required_legal or
            not re.fullmatch(r"[a-f0-9]{40}", producer.get("sourceCommit", "")) or
            sorted(producer.get("features", [])) != ["incoming-hysteria2", "legacy-outgoing-hysteria2"]):
        raise ValueError("Complete incoming server provenance required")
    architecture = found[0]["arch"]
    target, machine = (("linux-amd64", 62) if architecture == "x86_64" else
                       ("linux-arm64", 183) if architecture in ("aarch64_generic", "aarch64_cortex-a53") else (None, None))
    if target is None or producer.get("target") != target:
        raise ValueError("Incoming server architecture differs")
    package = next(path for path in paths if path.name == found[0]["file"])
    with tempfile.TemporaryDirectory(prefix="foxhole-server-payload-") as temporary:
        root = Path(temporary)
        command = [apk] + (["--allow-untrusted"] if development else ["--keys-dir", str(keys)])
        command += ["extract", "--no-chown", "--destination", str(root), str(package)]
        subprocess.run(command, capture_output=True, check=True, timeout=60)
        def safe(relative):
            path = root
            for part in Path(relative).parts:
                path = path / part
                if path.is_symlink():
                    raise ValueError("Server payload contains a symlink")
            if not path.is_file():
                raise ValueError("Server payload file is absent")
            return path
        if file_hash(safe("usr/share/foxhole/hysteria-producer.json")) != file_hash(producer_path):
            raise ValueError("Server APK contains a different source producer")
        for name, digest in producer["filesSha256"].items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or file_hash(safe("usr/share/licenses/hysteria/" + name)) != digest:
                raise ValueError("Server license producer digest mismatch")
        if mode == "flash":
            binary = safe("usr/bin/hysteria")
            digest = file_hash(binary)
        else:
            if volatile is None:
                raise ValueError("Exact volatile server binary required")
            lines = safe("usr/share/foxhole/hysteria-server-download.txt").read_text().splitlines()
            if (len(lines) != 4 or lines[1] != producer["binarySha256"] or
                    lines[2] != str(volatile.stat().st_size) or not lines[3].isdigit() or int(lines[3]) < 1):
                raise ValueError("Server RAM wrapper producer binding mismatch")
            digest = file_hash(volatile)
            binary = volatile
        if digest != producer["binarySha256"]:
            raise ValueError("Server binary differs from the actual producer")
        if number(producer.get("binaryBytes")) != binary.stat().st_size:
            raise ValueError("Server producer byte count differs")
        with binary.open("rb") as stream:
            header = stream.read(64)
            if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or
                    struct.unpack_from("<H", header, 18)[0] != machine):
                raise ValueError("Expected server ELF required")
            offset = struct.unpack_from("<Q", header, 32)[0]
            size, count = struct.unpack_from("<HH", header, 54)
            if size < 56 or count > 128:
                raise ValueError("Invalid server ELF program headers")
            for index in range(count):
                stream.seek(offset + index * size)
                data = stream.read(size)
                if len(data) != size or struct.unpack_from("<I", data)[0] == 3:
                    raise ValueError("Static server producer required")
    return {"file": package.name, "sha256": file_hash(package), "binarySha256": digest,
            "producerSha256": file_hash(producer_path), "payloadVerified": True}


def number(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_BYTES:
        raise ValueError("Invalid package size")
    return value


def dependency(raw: str) -> tuple[str, str, str | None, str | None]:
    match = DEPENDENCY.fullmatch(raw)
    if not match:
        raise ValueError("Unsupported dependency expression")
    return match.groups()


def metadata(apk: str, path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError("APK must be a regular file")
    command = subprocess.run([apk, "adbdump", "--format", "json", str(path)],
                             capture_output=True, check=True, timeout=30)
    if len(command.stdout) > 8 * 1024 * 1024:
        raise ValueError("APK metadata exceeds limit")
    value = json.loads(command.stdout)["info"]
    for key in ("name", "version", "arch"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise ValueError("APK identity is missing")
    installed = number(value.get("installed-size"))
    for key in ("depends", "provides"):
        value[key] = value.get(key, [])
        if not isinstance(value[key], list) or not all(isinstance(item, str) for item in value[key]):
            raise ValueError("APK dependencies are missing")
    return {"name": value["name"], "version": value["version"], "arch": value["arch"],
            "installedBytes": installed, "archiveBytes": number(path.stat().st_size),
            "file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "depends": value["depends"], "provides": value["provides"]}


def closure(apk: str, packages: list[dict], roots: list[str], paths: list[Path],
            architecture: str, keys: Path | None, development: bool,
            authentication: dict | None = None, bundle: Path | None = None,
            factory_keys: Path | None = None) -> dict | None:
    names = {item["name"] for item in packages}
    if not packages or not roots or len(paths) != len(packages) or len(names) != len(packages) or not set(roots) <= names:
        raise ValueError("Duplicate packages or missing roots")
    for item in packages:
        for raw in item["provides"] + item["depends"]:
            dependency(raw)
    if authentication is not None:
        if bundle is None:
            raise ValueError("Original indexed repository authority required")
        if factory_keys is None:
            if keys is None or keys.is_symlink() or not keys.is_dir():
                raise ValueError("Original firmware trust keys required")
            with tempfile.TemporaryDirectory(prefix="foxhole-factory-keys-") as temporary:
                original = Path(temporary)
                for path in keys.iterdir():
                    if path.is_file() and not path.is_symlink() and file_hash(path) != indexed.CANONICAL_PUBLIC_SHA:
                        shutil.copyfile(path, original / path.name)
                return indexed.verify(apk, bundle, authentication, packages, roots, architecture, original)
        return indexed.verify(apk, bundle, authentication, packages, roots, architecture, factory_keys)
    if not development:
        raise ValueError("Original signed repository indexes are required")
    with tempfile.TemporaryDirectory(prefix="foxhole-apk-budget-") as temporary:
        cache = Path(temporary) / "cache"
        cache.mkdir()
        command = [apk, "--root", temporary, "--arch", architecture,
                   "--cache-dir", str(cache), "--no-network", "--repositories-file", "/dev/null"]
        command += ["--allow-untrusted"] if development else ["--keys-dir", str(keys)]
        mode = ["--usermode"] if os.geteuid() != 0 else []
        subprocess.run(command + ["add", "--initdb", *mode],
                       capture_output=True, check=True, timeout=60)
        subprocess.run(command + ["add", "--simulate", *mode, *map(str, paths)],
                       capture_output=True, check=True, timeout=60)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root-package", action="append", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--openwrt", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", choices=("flash", "ram"), required=True)
    parser.add_argument("--volatile-binary", type=Path)
    parser.add_argument("--volatile-sha256")
    parser.add_argument("--core-producer", type=Path, required=True)
    parser.add_argument("--server-producer", type=Path, required=True)
    parser.add_argument("--server-volatile-binary", type=Path)
    parser.add_argument("--capabilities", type=Path, required=True)
    parser.add_argument("--keys-dir", type=Path)
    parser.add_argument("--repository-auth", type=Path, required=True)
    parser.add_argument("--factory-keys-dir", type=Path, required=True)
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--flash-reserve-bytes", type=int, required=True)
    parser.add_argument("--ram-reserve-bytes", type=int, required=True)
    parser.add_argument("--runtime-memory-bytes", type=int, required=True)
    parser.add_argument("--memory-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = json.loads(args.memory_evidence.read_text())
    runtime_memory = number(args.runtime_memory_bytes)
    if (type(evidence.get("schema")) is not int or evidence["schema"] != 1 or evidence.get("type") not in ("measured", "conservative")
            or not isinstance(evidence.get("description"), str) or not evidence["description"]
            or number(evidence.get("runtimeMemoryBytes")) != runtime_memory or not runtime_memory):
        raise ValueError("Explicit runtime memory evidence or conservative policy required")
    if args.target not in ("armsr/armv8", "x86/64", "mediatek/filogic"):
        raise ValueError("Actual SDK target required")
    producer = json.loads(args.core_producer.read_text())
    capabilities = json.loads(args.capabilities.read_text())
    protocols = producer.get("protocols")
    if (type(producer.get("schema")) is not int or producer["schema"] != 1 or
            type(producer.get("exitCode")) is not int or producer["exitCode"] != 0 or
            type(capabilities.get("schema_version")) is not int or capabilities["schema_version"] != 1 or
            type(capabilities.get("router_contract_version")) is not int or capabilities["router_contract_version"] != 1 or
            capabilities.get("platform") != "linux" or capabilities.get("core_version") != producer.get("coreVersion") or not isinstance(protocols, list) or
            not protocols or sorted(capabilities.get("protocols", [])) != sorted(protocols)):
        raise ValueError("Actual native producer and capability receipts required")
    paths = sorted(args.bundle.glob("*.apk"))
    if not paths or len(paths) > 256:
        raise ValueError("Bounded complete APK closure is required")
    packages = [metadata(args.apk, path) for path in paths]
    if any(item["arch"] not in (args.architecture, "all", "noarch") for item in packages):
        raise ValueError("APK architecture mismatch")
    authentication = json.loads(args.repository_auth.read_text())
    verification = closure(args.apk, packages, args.root_package, paths, args.architecture,
                           args.keys_dir, args.development, authentication, args.bundle,
                           args.factory_keys_dir)
    core_package = verify_core_payload(args.apk, paths, packages, producer, args.core_producer,
                                      args.mode, args.keys_dir, False, args.volatile_binary)
    server_package = verify_server_payload(args.apk, paths, packages, args.server_producer,
                                          args.mode, args.keys_dir, False, args.server_volatile_binary)
    if not number(args.flash_reserve_bytes) or not number(args.ram_reserve_bytes):
        raise ValueError("Positive safety reserves required")
    volatile = 0
    if args.mode == "ram":
        path = args.volatile_binary
        if path is None or not path.is_file() or path.is_symlink():
            raise ValueError("Verified volatile binary is required")
        if hashlib.sha256(path.read_bytes()).hexdigest() != args.volatile_sha256:
            raise ValueError("Volatile binary producer hash mismatch")
        volatile = number(path.stat().st_size)
        server_bytes = number(args.server_volatile_binary.stat().st_size)
        volatile += server_bytes
    elif args.volatile_binary is not None or args.volatile_sha256 is not None or args.server_volatile_binary is not None:
        raise ValueError("Flash mode cannot claim volatile storage")
    compressed = sum(item["archiveBytes"] for item in packages)
    installed = sum(item["installedBytes"] for item in packages)
    dependency_bytes = sum(item["installedBytes"] for item in packages
                           if item["name"] not in args.root_package)
    kernel = [item for item in packages if item["name"] == "kernel"]
    if len(kernel) != 1:
        raise ValueError("Exact existing firmware kernel ABI is required")
    index_bytes = number(authentication["repositoryIndexBytes"])
    key_bytes = number(authentication["trustKeyBytes"])
    staging = 2 * compressed + installed + volatile + 2 * index_bytes + key_bytes
    value = {"schema": 1, "architecture": args.architecture,
             "supportedOpenWrt": [args.openwrt], "mode": args.mode,
             "supportedTargets": [args.target],
             "protocols": sorted(protocols),
             "rootPackages": sorted(args.root_package), "corePackage": core_package,
             "serverPackage": server_package,
             "serverProducerSha256": file_hash(args.server_producer),
             "platformPackages": {"kernel": kernel[0]["version"]},
             "coreProducerSha256": hashlib.sha256(args.core_producer.read_bytes()).hexdigest(),
             "capabilitiesSha256": hashlib.sha256(args.capabilities.read_bytes()).hexdigest(),
             "compressedBytes": number(compressed), "installedFlashBytes": number(installed),
             "installedRamBytes": volatile, "dependencyInstalledBytes": number(dependency_bytes),
             "stagingBytes": number(staging),
             "flashReserveBytes": number(args.flash_reserve_bytes),
             "ramReserveBytes": number(args.ram_reserve_bytes), "packages": packages,
             "runtimeMemoryBytes": runtime_memory, "memoryEvidence": evidence,
             "requiredFlashBytes": number(installed + args.flash_reserve_bytes),
             "requiredRamBytes": number(staging + runtime_memory + args.ram_reserve_bytes),
             "repositoryIndexes": authentication["repositoryIndexes"],
             "trustKeys": authentication["trustKeys"],
             "packageAuthentications": authentication["packageAuthentications"],
             "repositoryIndexBytes": index_bytes, "trustKeyBytes": key_bytes,
             "filesSha256": authentication["filesSha256"], "verification": verification}
    if volatile:
        value["volatileBinary"] = {"file": args.volatile_binary.name,
                                   "bytes": args.volatile_binary.stat().st_size, "sha256": args.volatile_sha256}
        value["volatileDependencies"] = [{"file": args.server_volatile_binary.name,
                                          "bytes": server_bytes, "sha256": file_hash(args.server_volatile_binary),
                                          "producerFile": args.server_producer.name,
                                          "producerSha256": file_hash(args.server_producer)}]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(value, output, separators=(",", ":"), sort_keys=True)
        output.write("\n")
    print("Complete package metadata budget generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
