"""Bind Hysteria source, fresh source tests and the exact compiler."""
from pathlib import Path
import hashlib
import json
import re

SOURCE_SHA = "8db04a112e73685a1e5916d5d4d3df3ed897dbabc3e639fda4880b7ca9a7d18e"
SOURCE_COMMIT = "619a6f856b69fb7ee6a7a379e810e68b84004605"
PATCH_SHA = "9356841dfca7add5755c91bb5ddd8398588d04b6c23430bf2f01067e8b763bcd"
RECEIPT_SHA = "db872fa2964b2f4ebce109fb49bc336cceac6a13756530550fbf219fc3dfbd21"
SOURCE_PATCH_FILE = "combined-source.patch"
SUITE_SOURCE_SHA = "6e3995f198b93654ea2b6cb5f780191ab22c10acc496447c419e7d44bd7cc7f0"
RUNTIME_VERSION = "go1.26.11"
REQUIRED_MODULES = {
    "golang.org/x/net": "v0.62.0",
    "golang.org/x/crypto": "v0.59.0",
    "golang.org/x/sys": "v0.50.0",
    "github.com/andybalholm/brotli": "v1.2.7",
    "github.com/klauspost/compress": "v1.20.2",
}
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
            value["casePass"] < 510 or value["packagePass"] <= 0 or value["packageSkip"] < 0 or
            value["packagePass"] + value["packageSkip"] != 44 or
            any(value[name] != 0 for name in ("caseFail", "caseSkip", "oldCasesRetained", "actualSuiteExitCode"))):
        raise ValueError("Complete fresh modified-source upstream test proof required")
    return value


def compiler_qualification(value):
    expected = {
        "schema": 2, "origin": "source-built-Go-toolchain",
        "version": RUNTIME_VERSION,
        "sourceCommit": "26b4433366fce47e480679e0b5a30222b63996e0",
        "sourceArchiveSha256": "d44101b0ff27ed2a4c75ad46c17b9c74359209e2eb2ca7c9df6cb4fdb68e1969",
        "binGoSha256": "26ee101a4b1aa25cc4fcf0f7d1934779eedffe6297b721284167723693852b06",
        "binGoBytes": 15548742,
        "compilerComponentReceiptSha256": "289bce83337162a9e7d0e8825a8329c4789d8d28f2c4781408e8417f12925dfd",
        "runtimeManifestSha256": "c4b52158ad3392089146c65ec2ce01240e97632f93591c2c15e391b1af0513c7",
        "runtimeFileCount": 15048,
        "sourceCompilerBuildReplayedInGo8Job": False,
        "runtimeFencesPassed": True,
        "currentTargetRuntimeAcceptance": None,
    }
    if (not isinstance(value, dict) or value != expected or
            any(type(value.get(name)) is not type(wanted)
                for name, wanted in expected.items())):
        raise ValueError("Exact fenced source-built Go1.26.11 compiler required")
    return value


def verify(record, payload):
    test_suite(record.get("testSuite"))
    if record.get("sourceTestScope") != {
            "kind": "fresh-current-compiler-tests", "compilerVersion": RUNTIME_VERSION,
            "currentCompilerTestsExecuted": True,
            "freshCompleteReceiptSha256": record["testSuite"]["freshCompleteReceiptSha256"]}:
        raise ValueError("Fresh current-compiler source-test scope required")
    if record["sourceTestScope"]["currentCompilerTestsExecuted"] is not True:
        raise ValueError("Actual current-compiler tests required")
    compiler_qualification(record.get("currentCompilerQualification"))
    evidence = source_evidence(payload / PROVENANCE_FILES[0], payload / PROVENANCE_FILES[1])
    selected = record.get("sourcePatch")
    if (record.get("sourceSha256") != SOURCE_SHA or record.get("sourceCommit") != SOURCE_COMMIT or
            not isinstance(selected, dict) or type(selected.get("schema")) is not int or
            selected.get("sourceUnmodified") is not False or selected != patch_record(evidence) or
            record.get("toolchain") != "go version " + RUNTIME_VERSION + " linux/amd64" or
            record.get("binaryRuntimeVersion") != RUNTIME_VERSION or
            set(record.get("filesSha256", {})) != set(LICENSES + PROVENANCE_FILES) or
            not all(any(line.startswith("dep\t" + module + "\t" + version + "\t")
                        for line in record.get("buildInfo", []) if isinstance(line, str))
                    for module, version in REQUIRED_MODULES.items())):
        raise ValueError("Patched Go1.26.11 Hysteria producer required")
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
