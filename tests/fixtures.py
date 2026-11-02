from pathlib import Path
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
root = Path(sys.argv[1])
source = Path(__file__).resolve().parents[1] / 'tools'
root.mkdir(mode=0o700)
flat = root / 'flat'
flat.mkdir(mode=0o700)
for name in ('install-compact.sh', 'bundle-transport-model.uc', 'bundle-transport.uc'):
    (flat / name).write_bytes((source / name).read_bytes())
for body in (b'Synthetic public APK fixture A\x00\xff', b'Synthetic public APK fixture B\x00\xfe'):
    (flat / ('apk-' + hashlib.sha256(body).hexdigest() + '.apk')).write_bytes(body)
(flat / 'package-catalog.json').write_bytes(b'{"synthetic":true}\n')
text = ''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in sorted(flat.iterdir()))
(flat / 'SHA256SUMS').write_text(text)
spec = importlib.util.spec_from_file_location('public_transport_builder', source / 'build-bundle-transport.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
result = builder.build(flat, hashlib.sha256(text.encode()).hexdigest(), root / 'transport')
(root / 'producer.actual.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(dict(files=result['actualFlatAssets'], members=result['archivedMembers'], archiveBytes=result['archive']['bytes'])))
