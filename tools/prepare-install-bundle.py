#!/usr/bin/env python3
"""Assemble and recheck a complete signed installation bundle for review."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("package_catalog", ROOT / "tools/package-catalog.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)

INSTALLER_FILES = {
    "install.sh": ROOT / "install.sh",
    "install-core.sh": ROOT / "tools/install-core.sh",
    "install-plan.uc": ROOT / "tools/install-plan.uc",
    "install-plan-model.uc": ROOT / "tools/install-plan-model.uc",
    "indexed-install.uc": ROOT / "tools/indexed-install.uc",
}


def selected_assets(source, development):
    value, unused = catalog.document(source, "package-catalog.json")
    variants = value.get("variants")
    if value.get("development") is not development or not isinstance(variants, list) or not 1 <= len(variants) <= 256:
        raise ValueError("Bounded catalog with matching trust mode required")
    names = {"package-catalog.json", "foxhole-openwrt-apk.pem"}
    for variant in variants:
        for key in ("coreProducerFile", "capabilitiesFile", "serverProducerFile"):
            names.add(variant[key])
        server, unused = catalog.document(source, variant["serverProducerFile"])
        catalog.budgets.provenance.verify(server, source)
        names.update(server["filesSha256"])
        for mode in variant["modes"].values():
            name = mode["budgetFile"]
            names.add(name)
            budget, unused = catalog.document(source, name, limit=1048576)
            evidence = budget.get("memoryEvidence", {})
            if not development and (evidence.get("provisional") is True or evidence.get("acceptedForRelease") is False):
                raise ValueError("Provisional laboratory memory policy cannot become a release bundle")
            names.update(budget["filesSha256"])
            if budget.get("volatileBinary"):
                names.add(budget["volatileBinary"]["file"])
            for dependency in budget.get("volatileDependencies", []):
                names.add(dependency["file"])
                names.add(dependency["producerFile"])
    if len(names) + len(INSTALLER_FILES) > 4096:
        raise ValueError("Too many installation assets")
    return names


def assemble(source, output, apk, keys, development):
    source, output = source.resolve(), output.absolute()
    if output.exists() or output.is_symlink() or output == source or source in output.parents:
        raise ValueError("New output directory outside the input bundle required")
    names = selected_assets(source, development)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="foxhole-install-review-", dir=output.parent) as temporary:
        prepared = Path(temporary) / "bundle"
        prepared.mkdir()
        for name in sorted(names):
            path, unused = catalog.asset(source, name)
            if path.stat().st_size > 536870912:
                raise ValueError("Installation asset exceeds bound")
            shutil.copyfile(path, prepared / name)
        for name, original in INSTALLER_FILES.items():
            if original.is_symlink() or not original.is_file():
                raise ValueError("Regular checked-out installer sources required")
            shutil.copyfile(original, prepared / name)
        manifest = "".join(catalog.budgets.file_hash(path) + "  " + path.name + "\n"
                           for path in sorted(prepared.iterdir()))
        if len(manifest.encode()) > 1048576:
            raise ValueError("Installation manifest exceeds bound")
        (prepared / "SHA256SUMS").write_text(manifest)
        anchor = catalog.budgets.file_hash(prepared / "SHA256SUMS")
        command = ["python3", str(ROOT / "tools/verify-install-bundle.py"), "--bundle", str(prepared),
                   "--manifest-sha256", anchor, "--apk", apk, "--keys-dir", str(keys)]
        if development:
            command.append("--development")
        subprocess.run(command, check=True, capture_output=True, timeout=600)
        prepared.rename(output)
    print("Verified installation review bundle; no publication performed")
    print("Independent manifest SHA-256:", anchor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--keys-dir", type=Path, required=True)
    parser.add_argument("--development", action="store_true")
    args = parser.parse_args()
    assemble(args.input, args.output, args.apk, args.keys_dir, args.development)


if __name__ == "__main__":
    main()
