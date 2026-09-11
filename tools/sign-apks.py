#!/usr/bin/env python3
"""Sign verified APK candidates without changing their package contents."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

PACKAGES = (
    'foxhole-openwrt-client-0.1.0-r41.apk',
    'hysteria-2.12.2-r2.apk',
    'hysteria-ram-2.12.2-r1.apk',
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def sign(apk, source, output, private, public):
    for path in (private, public, *(source / name for name in PACKAGES)):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Signing inputs must be regular files')
    if private.stat().st_mode & 0o077:
        raise ValueError('Private key permissions must exclude group and other')
    if run(['openssl', 'pkey', '-in', str(private), '-pubout']) != public.read_bytes():
        raise ValueError('Private key does not match the pinned public key')
    output.mkdir()
    records = {}
    with tempfile.TemporaryDirectory(prefix='foxhole-apk-sign-', dir=output.parent) as temporary:
        work = Path(temporary)
        trust = work / 'keys'
        trust.mkdir()
        shutil.copyfile(public, trust / 'foxhole-openwrt-apk.pem')
        for name in PACKAGES:
            original, signed = source / name, output / name
            shutil.copyfile(original, signed)
            # apk-tools 3.0.5 retains signing state between files.
            run([apk, 'adbsign', '--allow-untrusted', '--sign-key', str(private), str(signed)])
            run([apk, '--keys-dir', str(trust), 'verify', str(signed)])
            normalized = []
            for index, path in enumerate((original, signed)):
                copy = work / f'{index}.apk'
                shutil.copyfile(path, copy)
                run([apk, 'adbsign', '--allow-untrusted', '--reset-signatures',
                     '--compression', 'none', str(copy)])
                normalized.append(digest(copy))
            if normalized[0] != normalized[1]:
                raise ValueError('Package content changed during signing')
            records[name] = {
                'unsigned_sha256': digest(original),
                'signed_sha256': digest(signed),
                'content_sha256': normalized[0],
            }
    shutil.copyfile(public, output / 'foxhole-openwrt-apk.pem')
    record = {
        'schema': 1, 'algorithm': 'ECDSA-P256-SHA256',
        'public_key_sha256': digest(public),
        'apk_tools': run([apk, '--version']).decode().strip(),
        'packages': records,
    }
    (output / 'APK-SIGNATURES.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Signed and verified three APKs; package content is unchanged.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', default='apk')
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    args = parser.parse_args()
    try:
        sign(args.apk, args.input.resolve(), args.output.resolve(),
             args.key.absolute(), args.public_key.absolute())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'APK signing failed: {type(error).__name__}; no release was published')


if __name__ == '__main__':
    main()
