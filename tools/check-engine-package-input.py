#!/usr/bin/env python3
"""Bind one protocol/ABI/slot to a genuine native producer and capability receipt."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

PROTOCOLS = {'vless', 'vmess', 'hysteria2', 'tuic', 'trojan', 'shadowsocks',
             'wireguard', 'naive', 'anytls', 'shadowtls', 'socks', 'http'}
SHA = re.compile(r'[a-f0-9]{64}')


def sha(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError('Regular engine producer input required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--id', choices=sorted(PROTOCOLS), required=True)
    parser.add_argument('--storage', choices=('FLASH', 'RAM'), required=True)
    parser.add_argument('--architecture', choices=('aarch64', 'x86_64'), required=True)
    parser.add_argument('--package-architecture', choices=('aarch64_generic', 'aarch64_cortex-a53', 'x86_64'), required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--memory-bytes', type=int, required=True)
    parser.add_argument('--reserve-bytes', type=int, required=True)
    parser.add_argument('--launcher', type=Path)
    parser.add_argument('--legal-input', type=Path, required=True)
    parser.add_argument('--legal-provenance-sha256', required=True)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if ((args.architecture == 'x86_64') != (args.package_architecture == 'x86_64') or
            not 0 < args.memory_bytes <= 2**31 or not 16777216 <= args.reserve_bytes <= 2**31):
        raise ValueError('Exact target and explicit conservative memory budget required')
    check = Path(__file__).with_name('check-core-package-input.py')
    subprocess.run([sys.executable, str(check), '--input', str(args.input),
                    '--architecture', args.architecture, '--version', args.version,
                    '--source-sha256', args.source_sha256], check=True, timeout=30)
    producer_file = args.input / 'core-producer.json'
    producer = json.loads(producer_file.read_text())
    caps_file = args.input / 'capabilities.json'
    sha(caps_file)
    caps = json.loads(caps_file.read_text())
    if (producer.get('protocols') != [args.id] or caps.get('protocols') != [args.id] or
            caps.get('platform') != 'linux' or caps.get('router_contract_version') != 1 or
            caps.get('core_version') != args.version or
            re.fullmatch(r'[a-f0-9]{40}', producer.get('sourceCommit', '')) is None):
        raise ValueError('Actual single-protocol capabilities and source commit required')
    # Each ABI requires its own actual producer receipt.
    if producer.get('target') != args.architecture + '-unknown-linux-musl':
        raise ValueError('Producer target differs')
    binary = args.input / 'foxcore-cli'
    size = binary.stat().st_size
    if not 0 < size <= 67108864:
        raise ValueError('Bounded engine ELF required')
    legal_file = Path(__file__).with_name('engine-legal.py')
    spec = importlib.util.spec_from_file_location('engine_legal', legal_file)
    legal = importlib.util.module_from_spec(spec); spec.loader.exec_module(legal)
    if {p.name for p in args.legal_input.iterdir()} != {'LEGAL-PROVENANCE.json', *legal.TEXTS}:
        raise ValueError('Exactly three original legal delivery files required')
    legal.validate(args.legal_input, args.legal_provenance_sha256, producer, sha(producer_file), args.id)
    executable_sha = sha(binary)
    if args.storage == 'RAM':
        if args.launcher is None:
            raise ValueError('Pinned RAM launcher required')
        executable_sha = sha(args.launcher)
    manifest = {'schema': 1, 'id': args.id, 'storage': args.storage, 'version': args.version,
                'architecture': args.package_architecture, 'binarySha256': sha(binary),
                'executableSha256': executable_sha, 'producerSha256': sha(producer_file),
                'capabilitiesSha256': sha(caps_file), 'legalProvenanceSha256': args.legal_provenance_sha256,
                'sourceCommit': producer['sourceCommit'],
                'binaryBytes': size, 'runtimeMemoryBytes': args.memory_bytes,
                'reserveBytes': args.reserve_bytes}
    raw = (json.dumps(manifest, separators=(',', ':')) + '\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    if args.manifest_sha256 is not None and (SHA.fullmatch(args.manifest_sha256) is None or
                                             digest != args.manifest_sha256):
        raise ValueError('Immutable slot identity differs from the SDK package name')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Fresh manifest output required')
    args.output.write_bytes(raw)
    print(digest)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
