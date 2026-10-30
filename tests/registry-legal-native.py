"""Whole registry legal identities with synthetic metadata and closed I/O."""
from pathlib import Path
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'package/foxhole-openwrt-client/root/usr/share/foxhole/'
H = lambda raw: hashlib.sha256(raw).hexdigest()
STATE = "export const state={files:{},hashes:{},directories:{},calls:[],fault:null};\nexport function copy(v){return json(sprintf('%J',v));};\n"
FS = "import { state,copy } from './state.uc';\nexport function dirname(p){return p=='/'?'/':replace(p,/\\/[^/]+$/,'')||'/';};\nexport function lstat(p){\n let raw=state.files[p],h=state.hashes[p];\n if(raw!=null||h!=null){let info={type:'file',uid:0,gid:0,mode:0o644,nlink:1,inode:2,size:raw!=null?length(raw):h.bytes,mtime:10,ctime:10,dev:{major:1,minor:1}};\n  if(state.fault=='file-owner'&&match(p,/\\/slot.json$/))info.uid=1000;\n  if(state.fault=='file-link'&&match(p,/\\/slot.json$/))info.nlink=2;\n  return info;\n }\n if(state.directories[p])return {type:'directory',uid:0,gid:0,mode:state.fault=='writable-parent'&&p=='/usr'?0o775:0o755,inode:1,nlink:1,size:0,mtime:10};\n return null;\n};\nexport function readfile(p,maximum){if(p=='/dev/urandom'&&maximum==12)return 'abcdefghijkl';if(state.files[p]==null)die('fixture_unknown_read');return substr(state.files[p],0,maximum);};\nexport function unlink(p){if(state.files[p]==null)die('fixture_unknown_unlink');delete state.files[p];return true;};\nexport function rmdir(p){if(!state.directories[p])die('fixture_unknown_rmdir');delete state.directories[p];return true;};\n"
STORE = "import { state } from './state.uc';\nexport function directory(p){if(p!='/tmp/foxhole'&&!match(p,/^\\/tmp\\/foxhole\\/engine-command-[a-f0-9]{24}\\.io$/))die('fixture_unknown_directory');state.directories[p]=true;};\nexport function write(p,raw){if(!match(p,/^\\/tmp\\/foxhole\\/engine-command-[a-f0-9]{24}\\.io\\/(helper|utility\\.uc)$/))die('fixture_unknown_write');state.files[p]=raw;};\nexport function read(p,maximum){if(!match(p,/^\\/tmp\\/foxhole\\/engine-command-[a-f0-9]{24}(\\.err)?$/))die('fixture_unknown_store_read');return state.files[p]??null;};\n"
SYSTEM = "import { state } from './state.uc';\nexport function system(argv,timeout){\n if(type(argv)!='array'||length(argv)!=7||argv[0]!='/bin/sh'||argv[3]!='4096'||argv[4]!='15000'||argv[5]!='/usr/bin/sha256sum'||timeout!=20000)die('fixture_unknown_native_command');\n let output=argv[2],path=argv[6];\n if(!match(output,/^\\/tmp\\/foxhole\\/engine-command-[a-f0-9]{24}$/)||argv[1]!=output+'.io/helper'||state.files[argv[1]]!=state.files['/usr/libexec/foxhole-engine-command-v2']||state.files[output+'.io/utility.uc']!=state.files['/usr/share/foxhole/engine-capture.uc'])die('fixture_generation_mismatch');\n let pin=state.hashes[path];if(!pin)die('fixture_unknown_hash_role');push(state.calls,path);\n state.files[output]=(state.fault=='wrong-native-hash'?'0000000000000000000000000000000000000000000000000000000000000000':pin.sha256)+'  '+path+'\\n';state.files[output+'.err']='';return 0;\n};\n"

def transform(raw,root):
 text=raw.decode();pairs={"from 'fs'":"from '"+str(root/'fs.uc')+"'","from './private-store.uc'":"from '"+str(root/'store.uc')+"'","from './engine-model.uc'":"from '"+str(root/'engine-model.actual.uc')+"'"}
 for before,after in pairs.items():assert text.count(before)==1;text=text.replace(before,after)
 insertion="\nimport { system } from '"+str(root/'system.uc')+"';";anchor="import * as digest from 'digest';";assert text.count(anchor)==1;text=text.replace(anchor,anchor+insertion)
 reverse=text.replace(insertion,'')
 for before,after in pairs.items():reverse=reverse.replace(after,before)
 assert reverse.encode()==raw
 return text

def run_cases(output, ucode):
    # These identities are synthetic and grant no signature trust.
    producer = {'schema': 1, 'exitCode': 0, 'sourceCommit': 'a' * 40,
                'sourceSha256': 'b' * 64, 'target': 'x86_64-unknown-linux-musl',
                'binarySha256': H(b'synthetic binary'), 'protocols': ['hysteria2'],
                'filesSha256': {'LICENSE': H(b'license'),
                               'THIRD_PARTY_NOTICES.md': H(b'notices')}}
    caps = {'platform': 'linux', 'router_contract_version': 1,
            'core_version': '1.0.0', 'protocols': ['hysteria2']}
    texts = {'DEPENDENCY-LICENSES.txt': b'dependency notices',
             'RUNTIME-NOTICES.txt': b'runtime notices'}
    authority_names = ['producerStageReceiptSha256', 'producerSummaryReceiptSha256',
                       'cargoCaptureSha256', 'selectedCargoSbomSha256',
                       'cargoOriginalNoticesReportSha256', 'runtimeOriginalNoticesReportSha256']
    cases = ['schema1', 'schema2', 'content-mismatch', 'manifest-missing',
             'authority-commit', 'extra-file', 'proof-missing', 'native-hash']
    passed = 0
    for case in cases:
        root = output / case
        root.mkdir(mode=0o700)
        doc = {'schema': 2, 'coreCommit': producer['sourceCommit'],
               'sourceContentSha256': producer['sourceSha256'],
               'sourceManifestSha256': 'c' * 64,
               'sourceAuthority': {'commit': producer['sourceCommit'], 'tree': 'd' * 40,
                   'signatureReceiptSha256': 'e' * 64, 'sourceBankReceiptSha256': 'f' * 64},
               'target': producer['target'], 'protocols': ['hysteria2'],
               'producerSha256': '', 'binarySha256': producer['binarySha256'],
               'originalCoreNotices': producer['filesSha256'],
               'files': {n: {'bytes': len(raw), 'sha256': H(raw)} for n, raw in texts.items()},
               'authorities': {n: '1' * 64 for n in authority_names}}
        pr = copy.deepcopy(producer)
        fault = None
        if case == 'schema1':
            del doc['sourceContentSha256'], doc['sourceManifestSha256'], doc['sourceAuthority']
            doc.update(schema=1, sourceArchiveSha256='2' * 64)
            pr['sourceSha256'] = '2' * 64
        elif case == 'content-mismatch':
            doc['sourceContentSha256'] = '3' * 64
        elif case == 'manifest-missing':
            del doc['sourceManifestSha256']
        elif case == 'authority-commit':
            doc['sourceAuthority']['commit'] = '4' * 40
        elif case == 'extra-file':
            doc['files']['EXTRA.txt'] = copy.deepcopy(doc['files']['DEPENDENCY-LICENSES.txt'])
        elif case == 'proof-missing':
            del doc['authorities']['cargoCaptureSha256']
        elif case == 'native-hash':
            fault = 'wrong-native-hash'
        producer_raw = (json.dumps(pr, indent=2) + '\n').encode()
        doc['producerSha256'] = H(producer_raw)
        legal_raw = (json.dumps(doc, indent=2) + '\n').encode()
        caps_raw = (json.dumps(caps, indent=2) + '\n').encode()
        value = {'schema': 1, 'id': 'hysteria2', 'storage': 'FLASH', 'version': '1.0.0',
                 'architecture': 'x86_64', 'binarySha256': pr['binarySha256'],
                 'executableSha256': pr['binarySha256'], 'producerSha256': H(producer_raw),
                 'capabilitiesSha256': H(caps_raw), 'legalProvenanceSha256': H(legal_raw),
                 'sourceCommit': pr['sourceCommit'], 'binaryBytes': 16,
                 'runtimeMemoryBytes': 67108864, 'reserveBytes': 16777216}
        slot_raw = (json.dumps(value, indent=2) + '\n').encode()
        value.update(manifestSha256=H(slot_raw),
                     packageName='foxcore-engine-hysteria2-flash-' + H(slot_raw),
                     packageVersion='1.0.0-r1')
        folder = '/usr/libexec/foxhole/engines/hysteria2/' + value['manifestSha256']
        notices = '/usr/share/licenses/' + value['packageName']
        files = {folder + '/slot.json': slot_raw.decode(),
                 folder + '/core-producer.json': producer_raw.decode(),
                 folder + '/capabilities.json': caps_raw.decode(),
                 notices + '/LEGAL-PROVENANCE.json': legal_raw.decode(),
                 '/usr/libexec/foxhole-engine-command-v2':
                    (ROOT / 'package/foxhole-openwrt-client/root/usr/libexec/foxhole-engine-command-v2').read_text(),
                 '/usr/share/foxhole/engine-capture.uc': (ROOT / MODULE / 'engine-capture.uc').read_text()}
        hashes = {folder + '/foxcore-cli': {'sha256': pr['binarySha256'], 'bytes': 16}}
        hashes.update({notices + '/' + n: {'sha256': h, 'bytes': 1}
                       for n, h in pr['filesSha256'].items()})
        hashes.update({notices + '/' + n: row for n, row in doc['files'].items()})
        directories = {'/': True}
        for name in list(files) + list(hashes):
            directories.update({str(parent): True for parent in Path(name).parents})
        state = (STATE + '\nstate.files=' + json.dumps(files) + ';\nstate.hashes=' +
                 json.dumps(hashes) + ';\nstate.directories=' + json.dumps(directories) +
                 ';\nstate.fault=' + json.dumps(fault) + ';\n')
        for name, text in {'state.uc': state, 'fs.uc': FS, 'store.uc': STORE, 'system.uc': SYSTEM}.items():
            (root / name).write_text(text)
        for original, target in [('engine-model.uc', 'engine-model.actual.uc'),
                                 ('engine-package-layout.uc', 'engine-package-layout.uc')]:
            (root / target).write_bytes((ROOT / MODULE / original).read_bytes())
        original = (ROOT / MODULE / 'engine-registry.uc').read_bytes()
        (root / 'registry.actual.uc').write_text(transform(original, root))
        command = ("import * as r from '" + str(root / 'registry.actual.uc') +
                   "';let v={accepted:false,error:null};try{v.path=r.verify_slot(" +
                   json.dumps(value) + ");v.accepted=true;}catch(e){v.error=type(e)=='string'?e:e.message;}printf('%J',v);")
        result = subprocess.run([ucode, '-e', command], capture_output=True, timeout=10)
        if result.returncode or len(result.stdout) + len(result.stderr) > 1048576:
            sys.stdout.buffer.write(result.stdout)
            sys.stderr.buffer.write(result.stderr)
            raise RuntimeError('Required whole-registry native fixture did not execute')
        observed = json.loads(result.stdout)
        expected = case in ('schema1', 'schema2')
        valid = observed['accepted'] is expected
        valid = valid and (observed['path'] == folder + '/foxcore-cli' if expected else
                           observed['error'] == 'engine_package_verification_failed')
        passed += int(valid)
        print(('ok ' if valid else 'not ok ') + case)
    print('Native registry legal cases: ' + str(passed) + ' passed, ' + str(len(cases) - passed) + ' failed')
    return 0 if passed == len(cases) else 1


def main():
    os.umask(0o077)
    ucode = shutil.which('ucode')
    if ucode is None:
        raise SystemExit('Required native ucode unavailable')
    with tempfile.TemporaryDirectory(prefix='foxhole-registry-legal-native-') as directory:
        return run_cases(Path(directory), ucode)


if __name__ == '__main__':
    raise SystemExit(main())
