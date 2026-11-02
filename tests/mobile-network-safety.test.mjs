import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { functionBody, packageRoot, read } from './helpers.mjs';

const moduleSource = await read(`${packageRoot}/root/usr/share/foxhole/mobile-network.uc`);
const helperSource = await read(`${packageRoot}/root/usr/libexec/foxhole-mobile-network`);
const nativeSource = await read(`${packageRoot}/root/usr/share/foxhole/update-native.uc`);
const initSource = await read(`${packageRoot}/root/etc/init.d/foxhole-mobile`);
const path = '/etc/nftables.d/30-foxhole-mobile.nft';
const empty = 'set foxhole_mobile_endpoints { type ifname . ipv4_addr; }\n';
const populated = 'set foxhole_mobile_endpoints { type ifname . ipv4_addr; elements = { "br-lan" . 192.168.8.1 }; }\n';
const metadata = (size = empty.length) => ({ type: 'file', uid: 0, gid: 0, mode: 0o644,
  dev: { major: 0, minor: 1 }, inode: 12, nlink: 1, size, atime: 1, mtime: 1, ctime: 1 });
function model() {
  const context = vm.createContext({
    die: reason => { throw new Error(reason); },
    type: value => Array.isArray(value) ? 'array' : typeof value,
    length: value => value.length, match: (value, expression) => value.match(expression),
    index: (values, value) => values.indexOf(value), push: (values, value) => values.push(value),
    join: (separator, values) => values.join(separator), split: (value, separator) => value.split(separator),
    substr: (value, start, count) => count == null ? value.slice(start) : value.slice(start, start + count),
    sprintf: (_format, value) => JSON.stringify(value),
    iptoarr: value => /^\d+\.\d+\.\d+\.\d+$/.test(value) && value.split('.').every(x => +x <= 255)
      ? value.split('.').map(Number) : null, arrtoip: values => values.join('.')
  });
  vm.runInContext(moduleSource.replaceAll('export function ', 'function '), context);
  return context;
}
function publication(change = {}) {
  let info = { ...metadata(), ...change }, raw = empty, published = null;
  const context = vm.createContext({ network: model(), length: value => value.length,
    sprintf: (_format, value) => JSON.stringify(value), hexenc: () => 'a'.repeat(24),
    die: reason => { throw new Error(reason); },
    fs: {
      lstat: name => structuredClone(name === '/etc/nftables.d' ? { type: 'directory', uid: 0, mode: 0o755 } : info),
      readfile: name => {
        if (name === '/dev/urandom') return 'x'.repeat(12);
        info.atime++; if (change.concurrent) info.mtime++;
        return raw;
      },
      open: () => ({ write: value => { published = value; if (change.concurrentWrite) info.mtime++;
        return value.length; }, flush: () => true, close() {} }),
      rename: () => { raw = published; info = metadata(raw.length); return true; }, unlink: () => true
    }
  });
  const body = helperSource.slice(helperSource.indexOf('function fail()'), helperSource.indexOf('\nif(fs.stat'));
  vm.runInContext(body, context);
  return { context, value: () => raw };
}
test('public set publication tolerates its own atime update and still rejects concurrent mutation', () => {
  const valid = publication(); valid.context.public_set(populated); assert.equal(valid.value(), populated);
  const changed = publication({ concurrent: true });
  assert.throws(() => changed.context.public_set(populated), /unavailable/); assert.equal(changed.value(), empty);
  const raced = publication({ concurrentWrite: true });
  assert.throws(() => raced.context.public_set(populated), /unavailable/); assert.equal(raced.value(), empty);
  for (const change of [{ uid: 1 }, { nlink: 2 }, { type: 'link' }, { mode: 0o666 }])
    assert.throws(() => publication(change).context.public_set(populated), /unavailable/);
});
function installed(raw = populated, patch = {}, immutable = 'SIGNED', extra = null) {
  const hashes = [], network = model(), info = { ...metadata(raw.length), ...patch };
  const context = vm.createContext({ network, length: value => value.length,
    sprintf: (_format, value) => JSON.stringify(value),
    guard: { fail: reason => { throw new Error(reason); } },
    packages: { installed: () => ({ 'foxhole-openwrt-client': { arch: 'noarch', version: '1.0.2-r1' } }) },
    registry: { hash_file: name => { hashes.push(name); return immutable; } },
    fs: { lstat: name => structuredClone(name === path ? info : name === '/etc/nftables.d' && patch.parentUnsafe
      ? { type: 'directory', uid: 0, mode: 0o777 } : name === '/etc/nftables.d' && patch.parentLink
        ? { type: 'link', uid: 0, mode: 0o755 } : { type: 'directory', uid: 0, mode: 0o755 }),
      readfile: () => { if (patch.concurrentOwner) info.uid++; return raw; } }
  });
  for (const [name, args] of [['public_raw', 'path,maximum'], ['mobile_conffile', ''], ['installed_base', 'value']]) {
    const body = functionBody(nativeSource, name)
      .replace("for (let directory in ['/','/etc','/etc/nftables.d'])", "for (let directory of ['/','/etc','/etc/nftables.d'])")
      .replace('for (let folder in value.payload.paths)', 'for (let folder of value.payload.paths)')
      .replace('for (let file in folder.files || [])', 'for (let file of folder.files || [])');
    vm.runInContext(`function ${name}(${args}) ${body}`, context);
  }
  const paths = [{ name: 'etc/nftables.d', files: [{ name: '30-foxhole-mobile.nft', hash: 'SIGNED' }] },
    { name: 'usr/share/foxhole', files: [{ name: 'mobile-network.uc', hash: 'SIGNED' }] }];
  if (extra) paths[0].files.push({ name: extra, hash: 'OTHER' });
  return { run: () => context.installed_base({ version: '1.0.2-r1', payload: { paths } }), hashes };
}
test('installed BASE admits only the exact typed mutable mobile set and still hashes immutable files', () => {
  const fixture = installed(); assert.equal(fixture.run(), true);
  assert.deepEqual(fixture.hashes, ['/usr/share/foxhole/mobile-network.uc']);
  assert.equal(installed(empty).run(), true);
  assert.throws(() => installed(populated, {}, 'CHANGED').run(), /VERSION_IDENTITY_CONFLICT/);
  assert.throws(() => installed(populated, {}, 'SIGNED', '31-foxhole-inbound.nft').run(), /VERSION_IDENTITY_CONFLICT/);
});
test('mutable conffile rejects unsafe metadata, oversized content and noncanonical nft statements', () => {
  for (const patch of [{ uid: 1 }, { nlink: 2 }, { type: 'link' }, { mode: 0o666 }, { size: 0 }, { size: 4097 },
    { parentUnsafe: true }, { parentLink: true }])
    assert.throws(() => installed(populated, patch).run(), /PACKAGE_VERIFICATION_FAILED/);
  assert.throws(() => installed(populated, { concurrentOwner: true }).run(), /PACKAGE_VERIFICATION_FAILED/);
  for (const raw of [populated.replace('192.168.8.1', '1.1.1.1'), populated + 'flush ruleset\n', populated + '\n'])
    assert.throws(() => installed(raw).run(), /PACKAGE_VERIFICATION_FAILED/);
});

function apiEnsure({ initial = { nftables: [] }, apply = true, queryCode = 0, checkCode = 0, unsafe = false } = {}) {
  const files = new Map(), guarded = new Set(), commands = [];
  let document = structuredClone(initial), inode = 20;
  const context = vm.createContext({ network: model(), json: JSON.parse, length: value => value.length,
    die: reason => { throw new Error(reason); },
    store: {
      write: (name, raw) => { files.set(name, raw); inode++; },
      target: name => { if (unsafe) throw new Error('unsafe target'); guarded.add(name); },
      read: name => files.get(name), file_metadata: info => info?.type === 'file' && info.mode === 0o600
    },
    fs: { lstat: name => ({ ...metadata((files.get(name) || '').length), inode, mode: 0o600 }) },
    system: (argv, timeout) => {
      commands.push({ argv, timeout }); assert.equal(timeout, 5000);
      if (argv[0] === '/bin/sh') {
        assert.ok(guarded.has('/tmp/foxhole/mobile-fw4-input.json'));
        assert.equal(argv[2], 'umask 077; ulimit -f 1024 || exit 1; exec /usr/sbin/nft -j list chain inet fw4 input > /tmp/foxhole/mobile-fw4-input.json 2>/dev/null');
        files.set('/tmp/foxhole/mobile-fw4-input.json', JSON.stringify(document)); return queryCode;
      }
      assert.equal(argv[0], '/usr/sbin/nft');
      assert.equal(argv.at(-1), '/tmp/foxhole/mobile-fw4-accept.nft');
      assert.ok(guarded.has(argv.at(-1)));
      assert.equal(files.get(argv.at(-1)), 'insert rule inet fw4 input ' + context.network.api_accept_rule());
      if (argv[1] === '-c') return checkCode;
      assert.equal(argv[1], '-f');
      if (apply) document.nftables.push({ rule: { family: 'inet', table: 'fw4', chain: 'input',
        comment: 'FoxHole mobile API', expr: [
          { match: { op: '==', left: { concat: [{ meta: { key: 'iifname' } }, { payload: { protocol: 'ip', field: 'daddr' } }] }, right: '@foxhole_mobile_endpoints' } },
          { match: { op: '==', left: { payload: { protocol: 'tcp', field: 'dport' } }, right: 8443 } }, { accept: null }
        ] } });
      return 0;
    }
  });
  context.network.keys = Object.keys;
  vm.runInContext(helperSource.slice(helperSource.indexOf('function fail()'), helperSource.indexOf('\nif(fs.stat')), context);
  return { run: () => context.ensure_api_accept(), commands, files, document: () => document };
}
test('prepare restores only one missing exact API accept and repeat prepare is idempotent', () => {
  const foreign = { rule: { comment: 'another owner', expr: [{ drop: null }] } };
  const fixture = apiEnsure({ initial: { nftables: [foreign] } });
  fixture.run(); fixture.run();
  assert.equal(fixture.commands.filter(c => c.argv[0] === '/bin/sh').length, 3);
  assert.equal(fixture.commands.filter(c => c.argv[0] === '/usr/sbin/nft' && c.argv[1] === '-c').length, 1);
  assert.equal(fixture.commands.filter(c => c.argv[0] === '/usr/sbin/nft' && c.argv[1] === '-f').length, 1);
  assert.deepEqual(fixture.document().nftables[0], foreign);
});
test('query, target, check and post-insert verification failures stop without global firewall actions', () => {
  for (const options of [{ queryCode: 1 }, { unsafe: true }, { checkCode: 1 }, { apply: false }]) {
    const fixture = apiEnsure(options);
    assert.throws(() => fixture.run());
    assert.ok(fixture.commands.every(c => !c.argv.includes('delete') && !c.argv.includes('reload')));
  }
  assert.match(helperSource, /if\(ARGV\[0\]=='prepare'\)ensure_api_accept\(\);/);
  assert.ok(helperSource.indexOf("if(ARGV[0]=='prepare')ensure_api_accept();") < helperSource.indexOf("store.write('/tmp/foxhole/mobile-listeners.json'"));
  assert.equal((helperSource.match(/ulimit -f/g) || []).length, 1);
  assert.doesNotMatch(helperSource, /fw4 reload|uhttpd|delete rule|flush chain|flush ruleset/);
});
function stop(clearCode, nftCode) {
  const body = initSource.slice(initSource.indexOf('stop_service()'), initSource.indexOf('reload_service()')); assert.ok(body);
  const adapted = body.replaceAll('/usr/libexec/foxhole-mobile-network', 'mock_clear')
    .replaceAll('/usr/sbin/nft', 'mock_nft').replaceAll('/usr/libexec/foxhole-private-file', 'mock_private');
  return spawnSync('sh', ['-c', `mock_clear() { return ${clearCode}; }\n` +
    `mock_nft() { [ "$*" = '-f -' ] || { echo UNSAFE_NFT; return 97; }; cat; return ${nftCode}; }\n` +
    'mock_private() { echo UNSAFE_CLEANUP; return 0; }\n' + adapted + '\nstop_service\n'], { encoding: 'utf8', timeout: 3000 });
}
test('stop retains the empty deny policy before procd kills listeners', () => {
  const result = stop(0, 0); assert.equal(result.status, 0); assert.equal(result.stdout, '');
  assert.doesNotMatch(initSource, /\/usr\/sbin\/nft delete table/);
});
test('failed clear installs only a static atomic drop-all fallback and propagates nft failure', () => {
  const recovered = stop(1, 0); assert.equal(recovered.status, 0);
  assert.match(recovered.stdout, /add table inet foxhole_mobile\ndelete table inet foxhole_mobile\ntable inet foxhole_mobile/);
  assert.match(recovered.stdout, /tcp dport 8443 counter drop/); assert.doesNotMatch(recovered.stdout, /UNSAFE|accept[^;]*8443/);
  assert.equal(stop(1, 1).status, 1);
});
