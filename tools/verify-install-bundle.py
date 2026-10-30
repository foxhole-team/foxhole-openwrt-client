#!/usr/bin/env python3
"""Recheck actual signed installation variants before review or publication."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

spec = importlib.util.spec_from_file_location("package_catalog", Path(__file__).with_name("package-catalog.py"))
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
PUBLIC_KEY_SHA = "fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--keys-dir", type=Path, required=True)
    parser.add_argument("--development", action="store_true")
    args = parser.parse_args()
    root = args.bundle
    manifest, digest = catalog.asset(root, "SHA256SUMS")
    if not re.fullmatch(r"[a-f0-9]{64}", args.manifest_sha256) or digest != args.manifest_sha256:
        raise ValueError("Independent manifest anchor differs")
    if manifest.stat().st_size > 1048576:
        raise ValueError("Bounded release manifest required")
    entries = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,159})", line)
        if not match or match[2] in entries or match[2] == "SHA256SUMS":
            raise ValueError("Invalid release manifest entry")
        path, actual = catalog.asset(root, match[2])
        if actual != match[1]:
            raise ValueError("Release asset digest differs")
        entries[match[2]] = actual
    if not entries or len(entries) > 4096:
        raise ValueError("Bounded complete release manifest required")
    value, unused = catalog.document(root, "package-catalog.json")
    if value.get("development") is not args.development:
        raise ValueError("Release trust mode differs")
    key = args.keys_dir / "foxhole-openwrt-apk.pem"
    if not args.development and catalog.budgets.file_hash(key) != PUBLIC_KEY_SHA:
        raise ValueError("Canonical signing key differs")
    descriptions = []
    with tempfile.TemporaryDirectory(prefix="foxhole-catalog-recheck-") as temporary:
        for index, variant in enumerate(value.get("variants", [])):
            description = {"id": variant["id"], "architecture": variant["architecture"],
                           "supportedTargets": variant["supportedTargets"],
                           "coreProducerFile": variant["coreProducerFile"],
                           "capabilitiesFile": variant["capabilitiesFile"],
                           "serverProducerFile": variant["serverProducerFile"],
                           "budgets": {mode: entry["budgetFile"] for mode, entry in variant["modes"].items()}}
            for name in (description["coreProducerFile"], description["capabilitiesFile"],
                         description["serverProducerFile"], *description["budgets"].values()):
                if name not in entries:
                    raise ValueError("Metadata is absent from anchored manifest")
            for name in description["budgets"].values():
                budget, unused = catalog.document(root, name, limit=1048576)
                required = list(budget["filesSha256"])
                if budget.get("volatileBinary"):
                    required.append(budget["volatileBinary"]["file"])
                required.extend(item["file"] for item in budget.get("volatileDependencies", []))
                if any(asset not in entries for asset in required):
                    raise ValueError("Installation payload is absent from anchored manifest")
            path = Path(temporary) / f"variant-{index}.json"
            path.write_text(json.dumps(description))
            descriptions.append(path)
        actual = catalog.variants(root, descriptions, args.development, args.apk, args.keys_dir)
        if actual != value["variants"]:
            raise ValueError("Catalog differs from actual signed payloads and budgets")
    print("Actual installation catalog, native payloads and complete budgets verified")


if __name__ == "__main__":
    main()
