#!/usr/bin/env python3
"""Check the exact native producer inputs before an OpenWrt SDK package."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from urllib.parse import urlsplit

TARGETS = {"aarch64": ("aarch64-unknown-linux-musl", 183),
           "x86_64": ("x86_64-unknown-linux-musl", 62)}
PROTOCOLS = {"vless", "vmess", "hysteria2", "tuic", "trojan", "shadowsocks",
             "wireguard", "naive", "anytls", "shadowtls", "socks", "http"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--architecture", choices=TARGETS, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--download-url")
    parser.add_argument("--ram-reserve-bytes", type=int)
    args = parser.parse_args()
    if args.download_url is not None:
        url = urlsplit(args.download_url)
        if (url.scheme != "https" or not url.hostname or url.username or url.password or
                url.fragment or not re.fullmatch(r"https://[A-Za-z0-9_./%+-]+", args.download_url)):
            raise ValueError("Safe pinned HTTPS Core download URL required")
        if args.ram_reserve_bytes is None or not 0 < args.ram_reserve_bytes <= 2**53 - 1:
            raise ValueError("Explicit RAM runtime reserve required")
    target, machine = TARGETS[args.architecture]
    names = ("foxcore-cli", "core-producer.json", "LICENSE", "THIRD_PARTY_NOTICES.md")
    if any(not (args.input / name).is_file() or (args.input / name).is_symlink() for name in names):
        raise ValueError("Regular producer inputs are required")
    record = json.loads((args.input / "core-producer.json").read_text())
    if (type(record.get("schema")) is not int or record["schema"] != 1 or
            type(record.get("exitCode")) is not int or record["exitCode"] != 0 or
            record.get("target") != target or record.get("coreVersion") != args.version or
            record.get("sourceSha256") != args.source_sha256 or
            re.fullmatch(r"[a-f0-9]{64}", args.source_sha256) is None):
        raise ValueError("Core producer identity does not match the package")
    protocols = record.get("protocols")
    if not isinstance(protocols, list) or not protocols or len(set(protocols)) != len(protocols):
        raise ValueError("Compiled protocols are required")
    if not set(protocols) <= PROTOCOLS:
        raise ValueError("Unknown compiled protocol")
    path = args.input / "foxcore-cli"
    with path.open("rb") as binary:
        header = binary.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
            raise ValueError("64-bit little-endian Core ELF is required")
        offset = struct.unpack_from("<Q", header, 32)[0]
        entry_size, count = struct.unpack_from("<HH", header, 54)
        if entry_size < 56 or count > 128:
            raise ValueError("Invalid Core ELF program headers")
        for index in range(count):
            binary.seek(offset + index * entry_size)
            program = binary.read(entry_size)
            if len(program) != entry_size or struct.unpack_from("<I", program)[0] == 3:
                raise ValueError("Core package must use the static musl producer")
        binary.seek(0)
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or
            struct.unpack_from("<H", header, 18)[0] != machine or
            digest != record.get("binarySha256")):
        raise ValueError("Core ELF or producer digest mismatch")
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        if hashlib.sha256((args.input / name).read_bytes()).hexdigest() != record.get("filesSha256", {}).get(name):
            raise ValueError("Core license producer digest mismatch")
    print("Exact Core producer input verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
