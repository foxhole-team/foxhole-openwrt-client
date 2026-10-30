"""Run actual registry public-file and architecture functions in native ucode."""
import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1]
        / 'package/foxhole-openwrt-client/root/usr/share/foxhole/engine-registry.uc')
    args = parser.parse_args()
    source = args.source.read_text()
    public = source[source.index('function fail()'):source.index('function router_certificate()')]
    architecture = source[source.index('export function architecture()'):source.index('export function snapshot_context(')]
    fixture = Path(__file__).with_name('registry-architecture.uc.in').read_text()
    assert fixture.count('/* ACTUAL_PUBLIC_FILE */') == 1
    assert fixture.count('/* ACTUAL_ARCHITECTURE */') == 1
    fixture = fixture.replace('/* ACTUAL_PUBLIC_FILE */', public).replace(
        '/* ACTUAL_ARCHITECTURE */', architecture.replace('export function ', 'function '))
    result = subprocess.run(['ucode', '-'], input=fixture.encode(), capture_output=True,
        timeout=15, check=False)
    assert len(result.stdout) + len(result.stderr) <= 1048576
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
