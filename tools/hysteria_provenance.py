"""Bind the corrected Hysteria source, retained source tests and current compiler evidence."""
from pathlib import Path
import hashlib
import json
import re

SOURCE_SHA = "8db04a112e73685a1e5916d5d4d3df3ed897dbabc3e639fda4880b7ca9a7d18e"
SOURCE_COMMIT = "619a6f856b69fb7ee6a7a379e810e68b84004605"
PATCH_SHA = "13741cc70614625da775b9ae049c74a27cc5a1a92410aebd7d1649bb58f6cf01"
RECEIPT_SHA = "9c78d87d33ace6e323a3590ce78263f809a5a87083964cf85f0c9dc2589f4c52"
SOURCE_PATCH_FILE = "combined-source.patch"
SUITE_SOURCE_SHA = "4384fa5b283cde9a33ac2147756a4ce61e31708b9b1271e8c0929a330296181b"
PROVENANCE_FILES = ("HYSTERIA-SOURCE-PATCH.patch", "HYSTERIA-PATCH-SOURCE.json")
LICENSES = ("LICENSE.md", "app.LICENSE.md", "core.LICENSE.md", "extras.LICENSE.md",
            "go-modules.json", "GO-THIRD-PARTY-NOTICES.txt")


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Regular Hysteria provenance input required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_evidence(patch, receipt):
    if digest(patch) != PATCH_SHA or digest(receipt) != RECEIPT_SHA:
        raise ValueError("Exact Hysteria security repair evidence required")
    return json.loads(receipt.read_text())


def patch_record(evidence):
    return {"schema": 1, "patchSha256": PATCH_SHA, "patchFile": PROVENANCE_FILES[0],
            "receiptFile": PROVENANCE_FILES[1], "receiptSha256": RECEIPT_SHA,
            "changedFiles": evidence["changedFiles"], "sourceUnmodified": False}


def test_suite(value):
    fields = {"schema", "sourceReceiptSha256", "freshCompleteReceiptSha256", "casePass",
              "caseFail", "caseSkip", "packagePass", "packageSkip", "oldCasesRetained", "actualSuiteExitCode"}
    numbers = ("schema", "casePass", "caseFail", "caseSkip", "packagePass", "packageSkip",
               "oldCasesRetained", "actualSuiteExitCode")
    if (not isinstance(value, dict) or set(value) != fields or
            any(type(value.get(name)) is not int for name in numbers) or
            value["schema"] != 1 or value["sourceReceiptSha256"] != SUITE_SOURCE_SHA or
            not isinstance(value["freshCompleteReceiptSha256"], str) or
            re.fullmatch(r"[a-f0-9]{64}", value["freshCompleteReceiptSha256"]) is None or
            value["casePass"] < 5 or value["packagePass"] <= 0 or value["packageSkip"] < 0 or
            value["packagePass"] + value["packageSkip"] != 44 or
            any(value[name] != 0 for name in ("caseFail", "caseSkip", "oldCasesRetained", "actualSuiteExitCode"))):
        raise ValueError("Complete fresh modified-source upstream test proof required")
    return value


def compiler_qualification(value):
    fields = {"schema", "runtimeReceiptSha256", "archiveSha256", "ordinaryTlsControlReceiptSha256",
              "ordinaryTlsControlScope", "ordinaryTlsControlReused", "currentTargetRuntimeAcceptance"}
    if (not isinstance(value, dict) or set(value) != fields or type(value.get("schema")) is not int or value.get("schema") != 1 or
            value.get("runtimeReceiptSha256") != "3b39d555cb1fedecefcde92f72da72abdd0a26abbf769b0e220992a88c6bf2fd" or
            value.get("archiveSha256") != "ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5" or
            re.fullmatch(r"[a-f0-9]{64}", str(value.get("ordinaryTlsControlReceiptSha256"))) is None or
            value.get("ordinaryTlsControlScope") != "Linux/amd64 existing TestGoVerify ordinary chain control; not Hysteria target runtime or denylist regression" or
            value.get("ordinaryTlsControlReused") is not True or value.get("currentTargetRuntimeAcceptance") is not None):
        raise ValueError("Current Go1.26.10 compiler with separately scoped ordinary control required")
    return value


def verify(record, payload):
    test_suite(record.get("testSuite"))
    if record.get("sourceTestScope") != {
            "kind": "retained-exact-source-tests", "compilerVersion": "go1.26.9",
            "currentCompilerTestsExecuted": False,
            "freshCompleteReceiptSha256": "f66db45fa33d2895c9ca8945ef6c668d0db8910748a063bbed638788004a506e"}:
        raise ValueError("Explicit retained Go1.26.9 source-test scope required")
    if record["testSuite"]["freshCompleteReceiptSha256"] != record["sourceTestScope"]["freshCompleteReceiptSha256"]:
        raise ValueError("Retained source suite identity differs")
    compiler_qualification(record.get("currentCompilerQualification"))
    evidence = source_evidence(payload / PROVENANCE_FILES[0], payload / PROVENANCE_FILES[1])
    selected = record.get("sourcePatch")
    if (record.get("sourceSha256") != SOURCE_SHA or record.get("sourceCommit") != SOURCE_COMMIT or
            not isinstance(selected, dict) or type(selected.get("schema")) is not int or
            selected.get("sourceUnmodified") is not False or selected != patch_record(evidence) or
            record.get("toolchain") != "go version go1.26.10 linux/amd64" or
            record.get("binaryRuntimeVersion") != "go1.26.10" or
            set(record.get("filesSha256", {})) != set(LICENSES + PROVENANCE_FILES) or
            not any(line.startswith("dep\tgolang.org/x/net\tv0.60.0\t")
                    for line in record.get("buildInfo", []) if isinstance(line, str))):
        raise ValueError("Patched Go1.26.10/xnet0.60 Hysteria producer required")
    for name in LICENSES + PROVENANCE_FILES:
        if digest(payload / name) != record["filesSha256"][name]:
            raise ValueError("Hysteria legal or repair provenance digest differs")


def record_source(source, output):
    package = Path(__file__).resolve().parents[1] / "package/hysteria"
    patch, receipt = package / SOURCE_PATCH_FILE, package / "security-source.json"
    evidence = source_evidence(patch, receipt)
    expected = evidence["effectiveSourceFilesSha256"]
    for relative, expected_hash in expected.items():
        if digest(source / relative) != expected_hash:
            raise ValueError("Hysteria compiled source differs from the repaired source")
    for path in source.rglob("*.go"):
        relative = path.relative_to(source)
        if ".pc" not in relative.parts and str(relative) not in expected:
            raise ValueError("Unexpected Hysteria Go source input")
    for original, name in ((patch, PROVENANCE_FILES[0]), (receipt, PROVENANCE_FILES[1])):
        (output / name).write_bytes(original.read_bytes())
    return patch_record(evidence), {name: digest(output / name) for name in PROVENANCE_FILES}
