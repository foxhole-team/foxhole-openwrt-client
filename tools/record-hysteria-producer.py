#!/usr/bin/env python3
"""Record the actual upstream Go server binary and its source licenses."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import hysteria_provenance as provenance

LICENSES = {"LICENSE.md": "LICENSE.md", "app.LICENSE.md": "app/LICENSE.md",
            "core.LICENSE.md": "core/LICENSE.md", "extras.LICENSE.md": "extras/LICENSE.md"}
LEGAL = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "NOTICE", "NOTICE.txt", "COPYING")


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Regular producer file required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def documents(raw):
    decoder = json.JSONDecoder()
    text = raw.decode()
    values = []
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        values.append(value)
        text = text[end:]
        if len(values) > 4096:
            raise ValueError("Go dependency inventory exceeds limit")
    return values


def notices(go, source):
    raw = subprocess.run([go, "list", "-mod=readonly", "-deps", "-json", "./app"], cwd=source,
                         capture_output=True, check=True, timeout=120).stdout
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("Go package graph exceeds limit")
    modules = {}
    for package in documents(raw):
        module = package.get("Module")
        if module is not None and not module.get("Main"):
            modules[module["Path"]] = module
    sections = []
    for name, module in sorted(modules.items()):
        selected = module.get("Replace", module)
        directory = Path(selected["Dir"])
        legal = [directory / name for name in LEGAL if (directory / name).is_file()]
        if not legal:
            raise ValueError("Compiled Go dependency has no legal file: " + name)
        sections.append(name + " " + selected.get("Version", "local") + "\n")
        for path in legal:
            if path.is_symlink() or path.stat().st_size > 262144:
                raise ValueError("Bounded regular Go legal file required")
            sections.append(path.name + "\n" + path.read_text() + "\n")
    goroot = Path(subprocess.check_output([go, "env", "GOROOT"], text=True).strip())
    sections.append("Go runtime\n" + (goroot / "LICENSE").read_text() + "\n")
    text = "\n".join(sections)
    if len(text.encode()) > 8 * 1024 * 1024:
        raise ValueError("Go legal inventory exceeds limit")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--test-suite", type=Path, required=True,
                        help="Actual fresh complete suite receipt for the corrected source")
    parser.add_argument("--compiler-qualification", type=Path, required=True,
                        help="Bound actual compiler and reused ordinary chain-control metadata")
    args = parser.parse_args()
    compiler_raw = args.compiler_qualification.read_bytes()
    if args.compiler_qualification.is_symlink() or not 0 < len(compiler_raw) <= 131072:
        raise ValueError("Bounded compiler qualification input required")
    compiler = provenance.compiler_qualification(json.loads(compiler_raw))
    suite_raw = args.test_suite.read_bytes()
    if args.test_suite.is_symlink() or len(suite_raw) > 131072:
        raise ValueError("Bounded regular actual test suite receipt required")
    suite = json.loads(suite_raw)
    if (type(suite.get("actualSuiteExitCode")) is not int or suite["actualSuiteExitCode"] != 0 or
            suite.get("sourceModified") is not True or suite.get("oldCasesRetained") != 0):
        raise ValueError("Actual complete corrected-source suite required")
    test_suite = provenance.test_suite({
        "schema": 1, "sourceReceiptSha256": suite.get("sourceReceiptSha256"),
        "freshCompleteReceiptSha256": hashlib.sha256(suite_raw).hexdigest(),
        "casePass": suite.get("casePass"), "caseFail": 0, "caseSkip": 0,
        "packagePass": suite.get("packagePass"), "packageSkip": suite.get("packageSkip"),
        "oldCasesRetained": suite.get("oldCasesRetained"), "actualSuiteExitCode": suite.get("actualSuiteExitCode")})
    source_patch, patch_hashes = provenance.record_source(args.source, args.output.parent)
    license_hashes = {}
    for name, relative in LICENSES.items():
        path = args.source / relative
        license_hashes[name] = digest(path)
        (args.output.parent / name).write_bytes(path.read_bytes())
    modules = subprocess.run([args.go, "list", "-mod=readonly", "-m", "-json", "all"], cwd=args.source,
                             capture_output=True, check=True, timeout=60).stdout
    if len(modules) > 4 * 1024 * 1024:
        raise ValueError("Go dependency inventory exceeds limit")
    (args.output.parent / "go-modules.json").write_bytes(modules)
    license_hashes["go-modules.json"] = digest(args.output.parent / "go-modules.json")
    legal = args.output.parent / "GO-THIRD-PARTY-NOTICES.txt"
    legal.write_text(notices(args.go, args.source))
    license_hashes[legal.name] = digest(legal)
    build_output = subprocess.check_output([args.go, "version", "-m", str(args.binary)], text=True).splitlines()
    if not build_output or not build_output[0].endswith(": go1.26.10"):
        raise ValueError("Actual binary Go1.26.10 runtime identity required")
    build = build_output[1:]
    if (not any(line.strip() == "build\tGOOS=linux" for line in build) or
            not any(line.strip() == "build\tGOARCH=" + args.architecture for line in build)):
        raise ValueError("Actual binary target identity differs")
    if not any(line.strip() == "build\tCGO_ENABLED=0" for line in build):
        raise ValueError("Actual static Go producer setting is absent")
    record = {"schema": 1, "exitCode": 0, "name": "hysteria", "version": args.version,
              "target": "linux-" + args.architecture, "sourceSha256": args.source_sha256,
              "sourceCommit": args.source_commit, "binarySha256": digest(args.binary),
              "binaryBytes": args.binary.stat().st_size, "buildInfo": [line.strip() for line in build],
              "binaryRuntimeVersion": "go1.26.10",
              "toolchain": subprocess.check_output([args.go, "version"], text=True).strip(),
              "features": ["incoming-hysteria2", "legacy-outgoing-hysteria2"],
              "sourcePatch": source_patch, "testSuite": test_suite, "filesSha256": {**license_hashes, **patch_hashes}}
    record["sourceTestScope"] = {
        "kind": "retained-exact-source-tests", "compilerVersion": "go1.26.9",
        "currentCompilerTestsExecuted": False,
        "freshCompleteReceiptSha256": "f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e"}
    record["currentCompilerQualification"] = compiler
    provenance.verify(record, args.output.parent)
    args.output.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
