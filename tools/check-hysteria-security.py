"""Admit exact non-imported advisory exceptions from physical evidence."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import re

HEX = re.compile(r"[a-f0-9]{64}")
SOURCE_FIELDS = ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles",
                 "HFiles", "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles",
                 "SysoFiles", "EmbedFiles")


def require(value, message):
    if not value:
        raise ValueError(message)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "Duplicate evidence JSON member")
        result[key] = value
    return result


def read(path, maximum=131072):
    require(not path.is_symlink() and path.is_file(),
            "Regular security evidence file required")
    require(path.stat().st_size <= maximum, "Security evidence exceeds limit")
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def document(path, maximum=131072):
    return json.loads(read(path, maximum), object_pairs_hook=pairs)


def checked(path, expected, maximum=131072):
    require(isinstance(expected, str) and HEX.fullmatch(expected),
            "Exact security evidence digest required")
    raw = read(path, maximum)
    require(digest(raw) == expected, "Security evidence digest differs")
    return raw


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def stream(raw):
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=pairs)
    values = []
    position = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        value, position = decoder.raw_decode(text, position)
        require(isinstance(value, dict), "Package evidence object required")
        values.append(value)
        require(len(values) <= 4096, "Selected package count exceeds limit")
    return values


def check_evidence(policy, evidence, shipping, scan, now):
    require(type(policy.get("schema")) is int and policy["schema"] == 1,
            "Security policy schema differs")
    require(now.tzinfo is not None, "UTC-aware observation time required")
    require(integer(policy.get("queryCount"), 1, 4096) and
            integer(policy.get("maxScanAgeHours"), 1, 24),
            "Bounded scan freshness and coordinate count required")
    entries = policy.get("exceptions")
    require(isinstance(entries, list) and len(entries) == 2,
            "Exactly reviewed Hysteria exceptions required")
    coordinates = {}
    advisory_documents = {}
    forbidden = set()
    for entry in entries:
        require(isinstance(entry, dict) and entry.get("ecosystem") == "Go",
                "Exact Go exception coordinate required")
        coordinate = (entry.get("package"), entry.get("version"))
        require(all(isinstance(v, str) and v for v in coordinate),
                "Exact exception version required")
        require(coordinate not in coordinates, "Duplicate exception coordinate")
        require(datetime.date.fromisoformat(entry["expires"]) >= now.date(),
                "Security exception expired")
        advisory = json.loads(checked(scan / (entry["advisory"] + ".json"),
                                      entry["advisorySha256"]),
                              object_pairs_hook=pairs)
        require(advisory.get("id") == entry["advisory"],
                "Advisory identity differs")
        advisory_documents[entry["advisory"]] = advisory
        paths = set()
        for affected in advisory.get("affected", []):
            if affected.get("package") != {"name": coordinate[0],
                                          "ecosystem": "Go"}:
                package = affected.get("package", {})
                if package.get("name") != coordinate[0] or package.get("ecosystem") != "Go":
                    continue
            paths.update(i["path"] for i in affected.get("ecosystem_specific", {}).get("imports", []))
        require(paths and paths == set(entry["affectedPackages"]),
                "Affected package scope differs from primary advisory")
        forbidden.update(paths)
        coordinates[coordinate] = entry["advisory"]
    require(set(coordinates.values()) == {"GO-2026-5841", "GO-2026-5932"},
            "Unreviewed advisory exception")
    aliases = policy.get("advisoryAliasPairs", [])
    require(isinstance(aliases, list) and len(aliases) <= 1,
            "Only the exact reviewed duplicate advisory pair is allowed")
    alias_map = {}
    if aliases:
        pair = aliases[0]
        require(set(pair) == {"advisory", "canonical", "advisorySha256"} and
                pair["advisory"] == "GHSA-259r-337f-4rfw" and pair["canonical"] == "GO-2026-5841" and
                coordinates.get(("github.com/klauspost/compress", "v1.17.9")) == pair["canonical"],
                "Exact reviewed alias and coordinate required")
        alias = json.loads(checked(scan / (pair["advisory"] + ".json"), pair["advisorySha256"]),
                           object_pairs_hook=pairs)
        canonical = advisory_documents[pair["canonical"]]
        require(alias.get("id") == pair["advisory"] and
                {pair["advisory"], "CVE-2026-63209"} <= set(canonical.get("aliases", [])) and
                "CVE-2026-63209" in alias.get("aliases", []),
                "Primary canonical and duplicate advisory identity differ")
        affected = alias.get("affected", [])
        require(affected and all(row.get("package", {}).get("name") == "github.com/klauspost/compress" and
                                row.get("package", {}).get("ecosystem") == "Go" for row in affected) and
                any(event.get("fixed") == "1.18.7" for row in affected
                    for affected_range in row.get("ranges", []) for event in affected_range.get("events", [])),
                "Duplicate advisory package or fixed version differs")
        alias_map[pair["advisory"]] = pair["canonical"]
    queries = json.loads(checked(scan / "query-payload.json",
                                policy["queryPayloadSha256"]),
                         object_pairs_hook=pairs)["queries"]
    responses = json.loads(checked(scan / "querybatch-response.json",
                                  policy["responseSha256"], 1048576),
                           object_pairs_hook=pairs)["results"]
    require(len(queries) == len(responses) == policy["queryCount"],
            "Actual query/response count differs")
    request = document(scan / "request-receipt.json")
    require(type(request.get("schema")) is int and request["schema"] == 1 and
            type(request.get("exitCode")) is int and request["exitCode"] == 0 and
            request.get("endpoint") == "https://api.osv.dev/v1/querybatch" and
            request.get("httpMetadata") == "200 https://api.osv.dev/v1/querybatch" and
            type(request.get("publicQueries")) is int and
            request.get("publicQueries") == policy["queryCount"] and
            request.get("queryPayloadSha256") == policy["queryPayloadSha256"] and
            request.get("responseSha256") == policy["responseSha256"],
            "Actual successful public scan binding required")
    finished = datetime.datetime.fromisoformat(request["finished"])
    require(finished.tzinfo is not None and
            datetime.timedelta(minutes=-5) <= now - finished <=
            datetime.timedelta(hours=policy["maxScanAgeHours"]),
            "Public scan is stale or in the future")
    findings = []
    canonical_findings = []
    queried = set()
    for query, response in zip(queries, responses):
        require(set(query) == {"package", "version"} and
                set(query["package"]) == {"ecosystem", "name"} and
                query["package"]["ecosystem"] == "Go",
                "Only exact public Go coordinates admitted")
        coordinate = (query["package"]["name"], query["version"])
        require(coordinate not in queried, "Duplicate scanned coordinate")
        queried.add(coordinate)
        require(set(response) <= {"vulns"}, "Unexpected public scan result")
        for finding in response.get("vulns", []):
            identifier = finding.get("id")
            canonical = alias_map.get(identifier, identifier)
            require(canonical == coordinates.get(coordinate) and identifier not in findings,
                    "Unqualified public vulnerability finding")
            findings.append(identifier)
            canonical_findings.append(canonical)
    require(len(findings) == 2 + len(alias_map) and
            set(findings) == set(coordinates.values()) | set(alias_map) and
            set(canonical_findings) == set(coordinates.values()),
            "Exact raw canonical and reviewed duplicate findings must be retained")
    targets = policy.get("targets")
    require(isinstance(targets, list) and len(targets) == 2 and
            {t.get("architecture") for t in targets} == {"amd64", "arm64"},
            "Both reviewed Linux architectures required")
    for target in targets:
        arch = target["architecture"]
        payload = shipping / ("linux-" + arch)
        producer = json.loads(checked(payload / "hysteria-producer.json",
                                     target["producerSha256"]),
                              object_pairs_hook=pairs)
        require(producer.get("target") == "linux-" + arch and
                producer.get("binaryRuntimeVersion") == policy["runtimeVersion"] and
                producer.get("binarySha256") == target["binarySha256"] and
                producer.get("testSuite", {}).get("sourceReceiptSha256") == policy["sourceReceiptSha256"],
                "Delivered producer source/target/runtime differs")
        checked(payload / "hysteria", target["binarySha256"], 536870912)
        require(producer.get("filesSha256", {}).get("go-modules.json") == policy["moduleManifestSha256"],
                "Delivered dependency manifest differs")
        checked(payload / "go-modules.json", policy["moduleManifestSha256"], 16777216)
        info = producer.get("buildInfo", [])
        require(all("build\t" + item in info for item in
                    ("CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + arch)),
                "Only exact CGO0 Linux build scope admitted")
        for (module, version) in coordinates:
            require(any(line.startswith("dep\t" + module + "\t" + version + "\t")
                        for line in info if isinstance(line, str)),
                    "Delivered module version differs")
        graph = stream(checked(evidence / (arch + "-packages.json"),
                               target["graphSha256"], 16777216))
        require(integer(target.get("packageCount"), 1, 4096) and
                len(graph) == target["packageCount"] and graph[-1].get("Name") == "main",
                "Complete selected application closure required")
        selected = {p["ImportPath"]: p for p in graph}
        require(len(selected) == len(graph) and not forbidden.intersection(selected),
                "Affected advisory package became reachable")
        selected_files = json.loads(checked(evidence / (arch + "-selected-files.json"),
                                           target["selectedFilesSha256"], 16777216),
                                    object_pairs_hook=pairs)
        require(set(selected_files) == set(selected),
                "Selected source file evidence differs")
        versions = {}
        for name, package in selected.items():
            require(not package.get("Incomplete") and "Error" not in package,
                    "Incomplete selected package evidence")
            require(set(package.get("Imports", [])) <= set(selected),
                    "Selected package import closure is incomplete")
            module = package.get("Module", {})
            require("Replace" not in module, "Replacement changes compiled scope")
            if module.get("Path") in {c[0] for c in coordinates}:
                require(module["Path"] not in versions or
                        versions[module["Path"]] == module.get("Version"),
                        "Inconsistent selected module versions")
                versions[module["Path"]] = module.get("Version")
            names = {f for key in SOURCE_FIELDS for f in package.get(key, [])}
            require(names == set(selected_files[name]) and
                    all(isinstance(v, str) and HEX.fullmatch(v)
                        for v in selected_files[name].values()),
                    "Selected source hashes incomplete")
        require(versions == {module: version for module, version in coordinates},
                "Selected package module version differs")
    return {"schema": 1, "findings": len(findings), "qualifiedExceptions": 2,
            "canonicalAdvisories": 2, "reviewedAliasDuplicates": len(alias_map),
            "blockingFindings": 0, "targets": ["amd64", "arm64"],
            "scope": "Exact delivered non-imported packages only; raw findings retained"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--shipping", required=True, type=Path)
    parser.add_argument("--scan", required=True, type=Path)
    args = parser.parse_args()
    result = check_evidence(document(args.policy), args.evidence, args.shipping,
                            args.scan, datetime.datetime.now(datetime.timezone.utc))
    print(json.dumps(result, sort_keys=True))
