#!/usr/bin/env python3
"""Bind real package budgets to exact native protocol producers."""
from __future__ import annotations

import argparse
import hashlib
import json
import importlib.util
from pathlib import Path
import re

PROTOCOLS = sorted({"vless", "vmess", "hysteria2", "tuic", "trojan", "shadowsocks",
                    "wireguard", "naive", "anytls", "shadowtls", "socks", "http"})
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}")
SHA = re.compile(r"[a-f0-9]{64}")
spec = importlib.util.spec_from_file_location("package_budget", Path(__file__).with_name("package-budget.py"))
budgets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budgets)


def asset(root: Path, name: str) -> tuple[Path, str]:
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise ValueError("Unsafe release asset name")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("Regular release asset required")
    with path.open("rb") as stream:
        return path, hashlib.file_digest(stream, "sha256").hexdigest()


def document(root: Path, name: str, schema_key: str = "schema", limit: int = 131072) -> tuple[dict, str]:
    path, digest = asset(root, name)
    if path.stat().st_size > limit:
        raise ValueError("Release metadata exceeds limit")
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or type(value.get(schema_key)) is not int or value[schema_key] != 1:
        raise ValueError("Unsupported release metadata")
    return value, digest


def memory_policy(evidence: object, runtime_bytes: int, development: bool) -> None:
    if (not isinstance(evidence, dict) or type(evidence.get("schema")) is not int or evidence["schema"] != 1 or
            evidence.get("type") not in ("measured", "conservative") or
            not isinstance(evidence.get("description"), str) or not 1 <= len(evidence["description"]) <= 4096 or
            budgets.number(evidence.get("runtimeMemoryBytes")) != runtime_bytes):
        raise ValueError("Actual memory evidence or explicit conservative policy required")
    for key in ("provisional", "acceptedForRelease", "measured"):
        if key in evidence and type(evidence[key]) is not bool:
            raise ValueError("Invalid memory policy qualification")
    if not development and (evidence.get("provisional") is True or evidence.get("acceptedForRelease") is False):
        raise ValueError("Provisional laboratory memory policy cannot become a release catalog")


def variants(root: Path, descriptions: list[Path], development: bool, apk: str,
             keys: Path | None) -> list[dict]:
    result = []
    identities = set()
    coverage = set()
    if not descriptions or len(descriptions) > 256:
        raise ValueError("Bounded release variant catalog required")
    for description in descriptions:
        value = json.loads(description.read_text())
        architecture = value["architecture"]
        if architecture not in ("aarch64_generic", "aarch64_cortex-a53", "x86_64"):
            raise ValueError("No verified package target for this architecture")
        ident = value["id"]
        if not isinstance(ident, str) or len(ident) > 96 or NAME.fullmatch(ident) is None or ident in identities:
            raise ValueError("Unique variant identity required")
        identities.add(ident)
        targets = value["supportedTargets"]
        expected_target = {"aarch64_generic":"armsr/armv8", "aarch64_cortex-a53":"mediatek/filogic", "x86_64":"x86/64"}[architecture]
        if targets != [expected_target]:
            raise ValueError("Exact verified SDK target required")
        producer_name = value["coreProducerFile"]
        producer, producer_hash = document(root, producer_name)
        target = "aarch64" if architecture in ("aarch64_generic", "aarch64_cortex-a53") else architecture
        if (type(producer.get("exitCode")) is not int or producer["exitCode"] != 0 or producer.get("target") != target + "-unknown-linux-musl"
                or not SHA.fullmatch(producer.get("binarySha256", ""))
                or not SHA.fullmatch(producer.get("sourceSha256", ""))):
            raise ValueError("Verified native producer required")
        protocols = producer.get("protocols")
        if (not isinstance(protocols, list) or not protocols or
                len(set(protocols)) != len(protocols) or not set(protocols) <= set(PROTOCOLS)):
            raise ValueError("Exact compiled protocol set required")
        capability_name = value["capabilitiesFile"]
        capabilities, capability_hash = document(root, capability_name, "schema_version")
        if (type(capabilities.get("router_contract_version")) is not int or capabilities["router_contract_version"] != 1 or capabilities.get("platform") != "linux"
                or capabilities.get("core_version") != producer.get("coreVersion")
                or sorted(capabilities.get("protocols", [])) != sorted(protocols)):
            raise ValueError("Actual native capabilities differ from the producer")
        server_producer_name = value["serverProducerFile"]
        server_producer, server_producer_hash = document(root, server_producer_name)
        if server_producer.get("target") != ("linux-arm64" if target == "aarch64" else "linux-amd64"):
            raise ValueError("Incoming server architecture differs")
        modes = {}
        releases = None
        for mode, budget_name in value["budgets"].items():
            if mode not in ("flash", "ram"):
                raise ValueError("Unknown storage mode")
            budget, budget_hash = document(root, budget_name, limit=1048576)
            if (budget.get("architecture") != architecture or budget.get("mode") != mode
                    or budget.get("coreProducerSha256") != producer_hash
                    or budget.get("capabilitiesSha256") != capability_hash
                    or budget.get("supportedTargets") != targets
                    or sorted(budget.get("protocols", [])) != sorted(protocols)
                    or budget.get("verification", {}).get("resolver") != "apk add --simulate --no-network"
                    or budget.get("verification", {}).get("signatureModel") != budgets.indexed.MODEL
                    or budget.get("verification", {}).get("signatures") is not True):
                raise ValueError("Budget is not bound to this verified native producer")
            versions = budget.get("supportedOpenWrt")
            if (not isinstance(versions, list) or not versions or
                    any(not isinstance(version, str) or re.fullmatch(r"25\.12\.[0-9]+", version) is None
                        for version in versions) or (releases is not None and releases != versions)):
                raise ValueError("Exact tested firmware versions required")
            releases = versions
            records = budget.get("packages")
            if not isinstance(records, list) or not records or len(records) > 256:
                raise ValueError("Nonempty complete package budget required")
            paths = [asset(root, item["file"])[0] for item in records]
            actual = [budgets.metadata(apk, path) for path in paths]
            if actual != records:
                raise ValueError("Budget does not describe the real APK files")
            roots = budget["rootPackages"]
            verification = budgets.closure(apk, actual, roots, paths, architecture, keys, development,
                                          budget, root)
            if verification != budget["verification"]:
                raise ValueError("Budget differs from actual indexed authentication")
            compressed = sum(item["archiveBytes"] for item in actual)
            installed = sum(item["installedBytes"] for item in actual)
            if compressed != budget["compressedBytes"] or installed != budget["installedFlashBytes"]:
                raise ValueError("Budget totals differ from real package metadata")
            for name, digest in budget["filesSha256"].items():
                if asset(root, name)[1] != digest:
                    raise ValueError("Budget package digest mismatch")
            volatile_path = None
            server_volatile_path = None
            if mode == "ram":
                volatile = budget["volatileBinary"]
                path, digest = asset(root, volatile["file"])
                if digest != producer["binarySha256"] or digest != volatile["sha256"] or path.stat().st_size != volatile["bytes"]:
                    raise ValueError("RAM payload does not match the exact native producer")
                volatile_path = path
                dependencies = budget.get("volatileDependencies")
                if not isinstance(dependencies, list) or len(dependencies) != 1:
                    raise ValueError("One complete incoming server volatile receipt required")
                dependency = dependencies[0]
                server_volatile_path, server_digest = asset(root, dependency["file"])
                if (dependency["producerFile"] != server_producer_name or
                        dependency["producerSha256"] != server_producer_hash or
                        dependency["sha256"] != server_digest or server_digest != server_producer["binarySha256"] or
                        budgets.number(dependency["bytes"]) != server_volatile_path.stat().st_size):
                    raise ValueError("Incoming server volatile producer binding mismatch")
            core = budgets.verify_core_payload(apk, paths, actual, producer, root / producer_name,
                                              mode, keys, False, volatile_path)
            server = budgets.verify_server_payload(apk, paths, actual, root / server_producer_name,
                                                   mode, keys, False, server_volatile_path)
            if server != budget.get("serverPackage") or budget.get("serverProducerSha256") != server_producer_hash:
                raise ValueError("Incoming server APK extraction receipt mismatch")
            if core != budget.get("corePackage"):
                raise ValueError("Core APK extraction receipt mismatch")
            for key in ("compressedBytes", "installedFlashBytes", "installedRamBytes", "stagingBytes",
                        "flashReserveBytes", "ramReserveBytes", "runtimeMemoryBytes", "requiredFlashBytes", "requiredRamBytes",
                        "repositoryIndexBytes", "trustKeyBytes"):
                budgets.number(budget[key])
            if not budget["flashReserveBytes"] or not budget["ramReserveBytes"] or not budget["runtimeMemoryBytes"]:
                raise ValueError("Positive working memory and safety reserves required")
            memory_policy(budget.get("memoryEvidence"), budget["runtimeMemoryBytes"], development)
            volatile_bytes = 0 if volatile_path is None else volatile_path.stat().st_size + server_volatile_path.stat().st_size
            if (budget["stagingBytes"] < 2 * compressed + installed + volatile_bytes +
                    2 * budget["repositoryIndexBytes"] + budget["trustKeyBytes"] or
                    budget["requiredFlashBytes"] != installed + budget["flashReserveBytes"] or
                    budget["requiredRamBytes"] != budget["stagingBytes"] + budget["runtimeMemoryBytes"] + budget["ramReserveBytes"]):
                raise ValueError("Complete memory and flash budgets required")
            modes[mode] = {"budgetFile": budget_name, "budgetSha256": budget_hash}
        if not modes:
            raise ValueError("At least one real installation budget required")
        for target_name in targets:
            for version in releases:
                point = (architecture, target_name, version, tuple(sorted(protocols)))
                if point in coverage:
                    raise ValueError("Overlapping exact variant coverage is ambiguous")
                coverage.add(point)
        result.append({"id": ident, "architecture": architecture, "supportedOpenWrt": releases,
                       "supportedTargets": targets,
                       "protocols": sorted(protocols), "coreProducerFile": producer_name,
                       "coreProducerSha256": producer_hash, "coreBinarySha256": producer["binarySha256"],
                       "coreSourceSha256": producer["sourceSha256"], "capabilitiesFile": capability_name,
                       "capabilitiesSha256": capability_hash, "serverProducerFile": server_producer_name,
                       "serverProducerSha256": server_producer_hash, "modes": modes})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--variant", type=Path, action="append", required=True)
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--apk", required=True)
    parser.add_argument("--keys-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = {"schema": 1, "defaultProtocols": ["hysteria2"], "allProtocols": PROTOCOLS,
             "development": args.development,
             "variants": variants(args.bundle, args.variant, args.development, args.apk, args.keys_dir)}
    if not value["variants"]:
        raise ValueError("Empty catalogs cannot be released")
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    if len(serialized.encode()) > 131072:
        raise ValueError("Catalog exceeds the consumer limit")
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(serialized)
    print("Exact producer, capabilities, budget and package catalog generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
