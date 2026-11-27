"""Exercise the actual public snapshot with synthetic certificate metadata."""
import argparse
import re
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1]
        / 'package/foxhole-openwrt-client/root/usr/share/foxhole/engine-registry.uc')
    args = parser.parse_args()
    source = args.source.read_text()
    def functions(names):
        result = []
        for name in names:
            pattern = (r'^(?:export )?function ' + re.escape(name) +
                       r'\([^\n]*\) \{(?:[^\n]*\};|.*?^\};)')
            matches = re.findall(pattern, source, re.M | re.S)
            assert len(matches) == 1, name
            result.append(matches[0].removeprefix('export '))
        return '\n'.join(result)
    private = functions(['fail', 'public_file', 'router_certificate'])
    context = functions(['architecture', 'snapshot_context'])
    fixture = Path(__file__).with_name('router-certificate-role.uc.in').read_text()
    assert fixture.count('/* ACTUAL_PRIVATE_PREFIX */') == 1
    assert fixture.count('/* ACTUAL_PUBLIC_CONTEXT */') == 1
    fixture = fixture.replace('/* ACTUAL_PRIVATE_PREFIX */', private).replace(
        '/* ACTUAL_PUBLIC_CONTEXT */', context.replace('export function ', 'function '))
    result = subprocess.run(['ucode', '-'], input=fixture.encode(), capture_output=True,
        timeout=15, check=False)
    assert len(result.stdout) + len(result.stderr) <= 1048576
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
