#!/usr/bin/env python3
"""Bind a volatile upstream server package to its actual static producer."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import hysteria_provenance as provenance

TARGETS = {"x86_64": ("linux-amd64", 62), "aarch64": ("linux-arm64", 183)}
LICENSES = provenance.LICENSES + provenance.PROVENANCE_FILES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--architecture", choices=TARGETS, required=True)
    parser.add_argument("--download-url")
    parser.add_argument("--ram-reserve-bytes", type=int)
    args = parser.parse_args()
    if args.download_url is not None and (not re.fullmatch(r"https://[A-Za-z0-9_./%+-]+", args.download_url) or
            args.ram_reserve_bytes is None or not 0 < args.ram_reserve_bytes <= 2**53 - 1):
        raise ValueError("Pinned HTTPS server payload and explicit runtime reserve required")
    if args.download_url is None and args.ram_reserve_bytes is not None:
        raise ValueError("A RAM reserve without a download binding is invalid")
    target, machine = TARGETS[args.architecture]
    names = ("hysteria", "hysteria-producer.json", *LICENSES)
    if any((args.input / name).is_symlink() or not (args.input / name).is_file() for name in names):
        raise ValueError("Regular server producer inputs required")
    record = json.loads((args.input / "hysteria-producer.json").read_text())
    provenance.verify(record, args.input)
    if (type(record.get("schema")) is not int or record["schema"] != 1 or
            type(record.get("exitCode")) is not int or record["exitCode"] != 0 or
            record.get("target") != target or record.get("version") != "2.12.2" or
            record.get("sourceSha256") != "8db04a112e73685a1e5916d5d4d3df3ed897dbabc3e639fda4880b7ca9a7d18e"):
        raise ValueError("Exact server source producer required")
    binary = args.input / "hysteria"
    with binary.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != machine:
            raise ValueError("Expected 64-bit server ELF required")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size < 56 or count > 128:
            raise ValueError("Invalid server ELF program headers")
        for index in range(count):
            stream.seek(offset + index * size)
            data = stream.read(size)
            if len(data) != size or struct.unpack_from("<I", data)[0] == 3:
                raise ValueError("Static upstream Go server required")
        stream.seek(0)
        if hashlib.file_digest(stream, "sha256").hexdigest() != record["binarySha256"]:
            raise ValueError("Server producer digest differs")
    for name in LICENSES:
        if hashlib.sha256((args.input / name).read_bytes()).hexdigest() != record["filesSha256"].get(name):
            raise ValueError("Server license producer digest differs")


if __name__ == "__main__":
    main()
