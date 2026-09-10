#!/usr/bin/env python3
"""Create a deterministic source archive without including local state."""
from __future__ import annotations
import hashlib
import argparse
import json
import os
import pathlib
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path,
                        default=ROOT / 'dist' / 'foxhole-openwrt-client-source.zip')
    output = parser.parse_args().output
    if not output.is_absolute():
        output = ROOT / output
    entries = json.loads(subprocess.check_output(
        ['node', 'tools/public-export.mjs', '--list'], cwd=ROOT))
    if output.resolve() in [(ROOT / entry['path']).resolve() for entry in entries]:
        raise ValueError('Output must not overwrite source files')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for entry in entries:
            name = entry['path']
            path = ROOT / name
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | entry['mode']) << 16
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
                archive.writestr(info, source.read())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(
        f'{digest}  {output.name}\n', encoding='ascii')
    print(f'Built {output.name}\nSHA-256 {digest}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
