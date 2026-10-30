#!/usr/bin/env python3
"""Give genuine signed APKs bounded, collision-free release asset names."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil

spec = importlib.util.spec_from_file_location("package_budget", Path(__file__).with_name("package-budget.py"))
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant-id", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", args.variant_id) is None:
        raise ValueError("Safe variant identity required")
    paths = sorted(args.input.glob("*.apk"))
    if not paths or len(paths) > 256:
        raise ValueError("Bounded real APK input required")
    records = [budget.metadata(args.apk, path) for path in paths]
    if len({record["name"] for record in records}) != len(records):
        raise ValueError("One package version per exact variant required")
    args.output.mkdir()
    result = []
    for path, record in zip(paths, records):
        asset = f"apk-{record['sha256']}.apk"
        destination = args.output / asset
        if destination.exists():
            raise ValueError("Release asset collision")
        shutil.copyfile(path, destination)
        if budget.file_hash(destination) != record["sha256"]:
            raise ValueError("APK changed during asset staging")
        result.append({"sourceFile": path.name, "releaseFile": asset,
                       "name": record["name"], "version": record["version"],
                       "architecture": record["arch"], "sha256": record["sha256"]})
    (args.output / "apk-assets.json").write_text(json.dumps({"schema": 1, "packages": result},
                                                          sort_keys=True, separators=(",", ":")) + "\n")
    print("Real APK assets staged without changing package content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
