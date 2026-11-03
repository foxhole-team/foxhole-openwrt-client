#!/usr/bin/env python3
"""Exercise the real RAM shell launcher offline; registry I/O uses explicit synthetic slots.

The real engine model validates every catalog/registry entry. The fixture verifier
checks slot bytes and launcher hashes, not APK signatures/producer/legal chains;
the later canonical package qualification owns that separate evidence.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path('/workspace')
SHARE = Path('/usr/share/foxhole')
SLOTS = Path('/usr/libexec/foxhole/engines')
TMP = Path('/tmp/engine-launcher-test')
SOURCE = ROOT / 'package/foxhole-openwrt-client/root/usr/share/foxhole'
LAUNCHER = ROOT / 'package/foxcore-engine/files/foxcore-engine-ram'
FIELDS = ['id', 'storage', 'version', 'architecture', 'binarySha256', 'executableSha256',
          'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'sourceCommit',
          'binaryBytes', 'runtimeMemoryBytes', 'reserveBytes']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    assert os.getuid() == 0 and not TMP.exists()
    TMP.mkdir(mode=0o700)
    (TMP / 'bin').mkdir()
    SHARE.mkdir(parents=True, exist_ok=True)
    SLOTS.mkdir(parents=True, exist_ok=True)
    for name in ('engine-model.uc', 'engine-package-layout.uc', 'private-store.uc'):
        shutil.copyfile(SOURCE / name, SHARE / name)
    registry = '''import * as fs from 'fs';
import * as digest from 'digest';
import * as engines from './engine-model.uc';
export function catalog() { return {value: engines.catalog(json(fs.readfile('/tmp/engine-launcher-test/catalog.json',262144)))}; };
export function read() { return engines.registry(json(fs.readfile('/tmp/engine-launcher-test/registry.json',262144))); };
export function executable(value) { return '/usr/libexec/foxhole/engines/'+value.id+'/'+value.manifestSha256+'/foxcore-cli'; };
export function hash_file(path) { return digest.sha256(fs.readfile(path,1048576)); };
export function verify_slot(value) {
 let path=executable(value),folder=fs.dirname(path),raw=fs.readfile(folder+'/slot.json',32768);
 let parsed=json(raw),expected={schema:1};
 for(let field in ['id','storage','version','architecture','binarySha256','executableSha256','producerSha256','capabilitiesSha256','legalProvenanceSha256','sourceCommit','binaryBytes','runtimeMemoryBytes','reserveBytes'])expected[field]=value[field];
 if(digest.sha256(raw)!=value.manifestSha256||sprintf('%J',parsed)!=sprintf('%J',expected)||hash_file(path)!=value.executableSha256)die('fixture_slot_verification_failed');
 fs.writefile('/tmp/engine-launcher-test/verified','yes');return path;
};
'''
    (SHARE / 'engine-registry.uc').write_text(registry)
    fetch = TMP / 'bin/uclient-fetch'
    fetch.write_text('''#!/bin/sh
set -eu
output='';url=''
while [ "$#" -gt 0 ]; do
 case "$1" in
  -T) shift 2 ;;
  -O) output=$2; shift 2 ;;
  *) url=$1; shift ;;
 esac
done
[ -n "$output" ] && [ -n "$url" ]
printf '%s\\n' "$url" >>/tmp/engine-launcher-test/requests
cp /tmp/engine-launcher-test/payload "$output"
''')
    fetch.chmod(0o700)
    template = next(row for row in json.loads((ROOT / 'tests/fixtures/engine-catalog-v1.0.3.json').read_text())['entries']
                    if row['id'] == 'hysteria2' and row['storage'] == 'RAM' and row['architecture'] == 'aarch64_cortex-a53')
    actual = LAUNCHER.read_bytes()
    cases = []

    def install(name, retained=False, mutate=None):
        payload = ('#!/bin/sh\nprintf "%s\\n" "$*" > /tmp/engine-launcher-test/executed\n# ' + name + '\n').encode()
        (TMP / 'payload').write_bytes(payload)
        entry = copy.deepcopy(template)
        entry.update(binarySha256=sha(payload), binaryBytes=len(payload), executableSha256=sha(actual))
        manifest = {'schema': 1, **{field: entry[field] for field in FIELDS}}
        raw = (json.dumps(manifest, separators=(',', ':')) + '\n').encode()
        entry['manifestSha256'] = sha(raw)
        entry['packageName'] = 'foxcore-engine-' + entry['id'] + '-ram-' + entry['manifestSha256']
        base = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.3/'
        entry['packageUrl'] = base + entry['packageName'] + '-' + entry['packageVersion'] + '.apk'
        entry['indexUrl'] = base + 'engines.adb'
        folder = SLOTS / entry['id'] / entry['manifestSha256']
        folder.mkdir(parents=True, exist_ok=True)
        binary = folder / 'foxcore-cli'
        binary.write_bytes(actual)
        binary.chmod(0o755)
        (folder / 'slot.json').write_bytes(raw)
        data = copy.deepcopy(entry)
        if mutate:
            mutate(data)
        (TMP / 'catalog.json').write_text(json.dumps({'schema': 1, 'entries': [] if retained else [data]}))
        (TMP / 'registry.json').write_text(json.dumps({'schema': 1, 'revision': 1 if retained else 0,
            'slots': [data] if retained else [], 'selected': [{'id': data['id'], 'slotId': data['id'] + '-ram-' + data['manifestSha256']}] if retained else []}))
        for file in ('requests', 'executed', 'verified'):
            (TMP / file).unlink(missing_ok=True)
        expected = base + 'engine-' + entry['id'] + '-' + entry['architecture'] + '-' + entry['binarySha256'] + '.bin'
        return binary, expected

    def run(name, binary, expected=None, reject=False):
        env = {**os.environ, 'PATH': str(TMP / 'bin') + ':/usr/local/bin:/usr/bin:/bin'}
        process = subprocess.run([str(binary), 'capabilities', '--synthetic-test'], env=env, capture_output=True, timeout=20)
        requests = (TMP / 'requests').read_text().splitlines() if (TMP / 'requests').exists() else []
        executed = (TMP / 'executed').read_text().strip() if (TMP / 'executed').exists() else None
        if reject:
            passed = process.returncode != 0 and not requests and executed is None
        else:
            passed = process.returncode == 0 and requests == [expected] and executed == 'capabilities --synthetic-test' and (TMP / 'verified').exists()
        row = {'case': name, 'passed': passed, 'exitCode': process.returncode, 'requests': requests,
               'executed': executed, 'stderr': process.stderr.decode('utf8', 'replace')[:4096]}
        cases.append(row)
        return row

    binary, expected = install('current-candidate')
    run('unregistered current catalog slot fetches actual router release URL', binary, expected)
    # Keep the same real RAM cache; another execution must not request the asset again.
    process = subprocess.run([str(binary), 'capabilities', '--synthetic-test'],
        env={**os.environ, 'PATH': str(TMP / 'bin') + ':/usr/local/bin:/usr/bin:/bin'}, capture_output=True, timeout=20)
    requests = (TMP / 'requests').read_text().splitlines() if (TMP / 'requests').exists() else []
    cases.append({'case': 'valid warm RAM cache is reused', 'passed': process.returncode == 0 and requests == [expected], 'exitCode': process.returncode})
    binary, expected = install('retained', retained=True)
    run('retained registered slot works after current catalog removes it', binary, expected)
    for name, mutate in (
        ('mixed-release', lambda value: value.update(indexUrl=value['indexUrl'].replace('/v1.0.3/', '/v1.0.2/'))),
        ('forged-origin', lambda value: value.update(packageUrl=value['packageUrl'].replace('/foxhole-team/foxhole-openwrt-client/', '/foreign/repository/'))),
        ('forged-filename', lambda value: value.update(packageUrl=value['packageUrl'] + '.foreign')),
        ('malformed-hash', lambda value: value.update(binarySha256='g' * 64)),
    ):
        binary, _ = install(name, mutate=mutate)
        run(name + ' is refused before any fetch or exec', binary, reject=True)
    result = {'scope': 'Native ucode + actual complete shell launcher, network intercepted in an owned isolated fixture; no real Core binary, APK signature/legal-chain, target ABI or router runtime proof.',
              'cases': cases, 'passed': sum(row['passed'] for row in cases), 'failed': sum(not row['passed'] for row in cases)}
    print(json.dumps(result))
    return 1 if result['failed'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
