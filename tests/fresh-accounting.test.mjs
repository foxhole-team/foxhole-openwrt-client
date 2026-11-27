import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

// Run production pure functions with ucode array semantics.
// Native APK, locks, signals and filesystems need separate QA.
const tools = new URL('../tools/', import.meta.url);
const sha = s => createHash('sha256').update(s).digest('hex');
const normalize = x => JSON.parse(JSON.stringify(x));
function load(file, extra = {}, cut = null) {
  let source = readFileSync(new URL(file, tools), 'utf8');
  if (cut) source = source.slice(0, source.indexOf(cut));
  source = source.replace(/^import .*;\s*$/gm, '').replace(/export function /g, 'function ')
    .replace(/for\s*\(let ([A-Za-z_]+) in ([^\n)]+)\)/g, 'for (let $1 of iterate($2))');
  const context = vm.createContext({
    fs: {}, digest: { sha256: sha }, ...extra,
    die: message => { throw new Error(message); },
    iterate: x => Array.isArray(x) ? x : Object.keys(x),
    type: x => x === null || x === undefined ? 'null' : Array.isArray(x) ? 'array' : typeof x === 'boolean' ? 'bool' : typeof x === 'number' ?
      Number.isInteger(x) ? 'int' : 'double' : typeof x,
    length: x => x == null ? 0 : x.length ?? Object.keys(x).length,
    keys: Object.keys, join: (s, x) => x.join(s), sort: (x, f) => x.sort(f),
    match: (s, r) => s.match(r), split: (s, d) => s.split(d), substr: (s, start, n) => s.substr(start, n),
    index: (a, x) => a.indexOf(x), trim: s => s.trim(), replace: (s, a, b) => s.replace(a, b),
    filter: (a, f) => a.filter(f), push: (a, x) => a.push(x), slice: (a, start, end) => a.slice(start, end),
    int: x => Number.parseInt(x, 10), json: JSON.parse,
    b64enc: s => Buffer.from(s, 'binary').toString('base64'),
    b64dec: s => Buffer.from(s, 'base64').toString('binary'),
    hexenc: s => Buffer.from(s, 'binary').toString('hex'),
    sprintf: (format, value) => { assert.match(format, /^%J\n?$/); return JSON.stringify(value) + (format.endsWith('\n') ? '\n' : ''); }
  });
  vm.runInContext(source, context, { filename: file });
  return context;
}
const m = load('fresh-install-accounting.uc');
const cid = '01'.repeat(32), other = '02'.repeat(32);
const record = (name = 'libc', id = cid, version = '1-r1', arch = 'aarch64_cortex-a53', flags = 'S') =>
  `C:Q1${Buffer.from(id.slice(0, 40), 'hex').toString('base64')}\nP:${name}\nV:${version}\nA:${arch}\nI:999999\nf:${flags}\n\n`;
const packages = [{ name: 'libc', version: '1-r1', arch: 'aarch64_cortex-a53', file: 'libc.apk', installedBytes: 123, archiveBytes: 10 }];
const auth = [{ name: 'libc', version: '1-r1', architecture: 'aarch64_cortex-a53', file: 'libc.apk', packageIdentity: cid }];
const asset = { file: 'fresh-install-accounting.json', sha256: 'a'.repeat(64) };
const profile = () => ({ schema: 1, kind: 'fresh-flash-installed-delta-v1', requiredMode: 'flash',
  databaseFormat: 'apk-v3-q1-sha256-160', nativeApkVersion: '3.0.5', nativeApkPath: '/sbin/apk', nativeApkSha256: 'b'.repeat(64),
  guardStagingBytes: 6291456, configs: ['/etc/apk/config', '/lib/apk/config'].map(path => ({ path, sha256: null })),
  hookDirectories: ['/etc/apk/commit_hooks.d', '/lib/apk/commit_hooks.d'].map(path => ({ path, present: false, files: [] })) });
function budget() { return { schema: 2, kind: 'compact-selected-budget-v1', mode: 'flash', packages, packageAuthentications: auth,
  installedFlashBytes: 123, compressedBytes: 10, installedRamBytes: 0, repositoryIndexBytes: 20, trustKeyBytes: 5,
  runtimeMemoryBytes: 128 * 1024 ** 2, flashReserveBytes: 32 * 1024 ** 2, ramReserveBytes: 32 * 1024 ** 2 }; }

test('exact native Q1/S credits signed metadata size and hashes exact raw bytes', () => {
  const raw = record(), state = m.snapshot(raw), a = m.accounting(state, packages, auth, 'flash', asset, 6291456);
  assert.equal(state.sha256, sha(raw)); assert.equal(a.fullInstalledBytes, 123);
  assert.equal(a.retainedInstalledBytes, 123); assert.equal(a.additionalInstalledBytes, 0);
  assert.equal(a.retainedPackages[0].nativeCid160, cid.slice(0, 40));
});
for (const [label, raw] of [ ['CID', record('libc', other)], ['version', record('libc', cid, '2-r1')],
  ['arch', record('libc', cid, '1-r1', 'x86_64')], ['missing', record('unrelated', other)] ]) {
  test('different ' + label + ' receives full extraction cost', () => {
    assert.equal(m.accounting(m.snapshot(raw), packages, auth, 'flash', asset, 6291456).additionalInstalledBytes, 123);
  });
}
for (const [label, raw] of [ ['duplicate package', record() + record()], ['duplicate P', record().replace('P:libc', 'P:libc\nP:other')],
  ['unsupported digest', record().replace('Q1', 'Q2')], ['unknown flag', record().replace('f:S', 'f:Z')],
  ['unknown field', record().replace('f:S', '?:unknown')], ['truncated terminator', record().slice(0, -1)],
  ['NUL', record() + '\x00'], ['CR', record().replace('P:libc', 'P:libc\r')],
  ['CID collision', record() + record('libgcc')], ['unsafe name', record('../libc')] ]) {
  test('snapshot rejects ' + label, () => assert.throws(() => m.snapshot(raw)));
}
for (const flags of ['', 'Sf', 'Ss', 'Sx']) test('dirty or untyped selected package refuses: ' + flags, () => {
  assert.throws(() => m.accounting(m.snapshot(record('libc', cid, '1-r1', 'aarch64_cortex-a53', flags)), packages, auth, 'flash', asset, 6291456));
});
test('new budget keeps all package/archive metadata and policy values, explicit FLASH only', () => {
  const input = budget(), before = JSON.stringify(input.packages), runtime = input.runtimeMemoryBytes;
  const value = m.apply(input, m.snapshot(record()), asset, profile());
  assert.equal(value.schema, 3); assert.equal(JSON.stringify(value.packages), before);
  assert.equal(value.compressedBytes, 10); assert.equal(value.installedFlashBytes, 123);
  assert.equal(value.flashReserveBytes, 32 * 1024 ** 2); assert.equal(value.ramReserveBytes, 32 * 1024 ** 2);
  assert.equal(value.runtimeMemoryBytes, runtime); assert.equal(value.requiredFlashBytes, value.flashReserveBytes);
  assert.equal(value.stagingBytes, 2 * 10 + 2 * 20 + 5 + 6291456);
  assert.throws(() => m.apply({ ...budget(), mode: 'ram' }, m.snapshot(record()), asset, profile()));
});
for (const mutate of [ v => v.installAccounting.retainedPackages.push(v.installAccounting.retainedPackages[0]),
  v => v.installAccounting.retainedPackages[0].packageIdentity = other,
  v => v.installAccounting.additionalInstalledBytes = -1, v => v.requiredFlashBytes--,
  v => v.stagingBytes--, v => v.requiredRamBytes--, v => v.mode = 'ram', v => v.schema = 2,
  v => v.installAccounting.installedDb.bytes = 0 ]) test('tampered dynamic budget rejects', () => {
  const value = normalize(m.apply(budget(), m.snapshot(record()), asset, profile())); mutate(value);
  assert.throws(() => m.validate_budget(value));
});
test('factory profile refuses duplicate/unknown paths and disabled capability shape', () => {
  assert.equal(m.profile(profile()).requiredMode, 'flash');
  for (const mutate of [ p => p.configs[0].path = '/tmp/config', p => p.hookDirectories[0].path = p.hookDirectories[1].path,
    p => p.nativeApkVersion = '3.1', p => p.requiredMode = 'auto', p => p.extra = true,
    p => p.hookDirectories[0].files.push({ name: 'zzzz-foxhole-collision', sha256: 'a'.repeat(64), mode: 493 }) ]) {
    const p = profile(); mutate(p); assert.throws(() => m.profile(p));
  }
});

const g = load('fresh-install-guard.uc', { fresh: m }, 'let action=ARGV[0];');
const temporary = '.foxhole-exact-0123456789abcdef';
const owner = { budget: { packageAuthentications: auth }, temporaryConstraint: temporary };
const state = raw => m.snapshot(raw);
test('world transitions preserve unrelated roots and change only the owned phase footprint', () => {
  const owned = { budget: { rootPackages: ['foxhole-base', 'foxcore-engine-hy'] }, temporaryConstraint: temporary };
  const initial = g.world_snapshot('base-files\nlibc=1-r1\n');
  const installed = g.world_snapshot(`base-files\nlibc=1-r1\n${temporary}=20261114.120000\n`);
  const durable = g.world_snapshot(`${temporary}=20261114.120000\nbase-files\nlibc=1-r1\nfoxcore-engine-hy\nfoxhole-base\n`);
  const final = g.world_snapshot('base-files\nlibc=1-r1\nfoxcore-engine-hy\nfoxhole-base\n');
  assert.doesNotThrow(() => g.after_world(owned, { phase: 1 }, initial, installed));
  assert.doesNotThrow(() => g.after_world(owned, { phase: 2 }, installed, durable));
  assert.doesNotThrow(() => g.after_world(owned, { phase: 3 }, durable, final));
  for (const value of [installed.raw + 'unrelated-new\n', installed.raw.replace('libc=1-r1', 'libc=2-r1'),
    installed.raw.replace('base-files\n', ''), installed.raw.replace(temporary, '.foreign')]) {
    assert.throws(() => g.after_world(owned, { phase: 1 }, initial, g.world_snapshot(value)));
  }
  assert.throws(() => g.after_world(owned, { phase: 2 }, installed, installed));
  assert.throws(() => g.after_world(owned, { phase: 3 }, durable, durable));
  assert.throws(() => g.world_snapshot('libc\nlibc=1-r1\n'));
});
test('pre-commit rejects a world-only race even with the exact installed DB hash', () => {
  const world = g.world_snapshot('base-files\n');
  const call = { expectedDbSha256: 'a'.repeat(64), expectedWorldSha256: world.sha256 };
  assert.doesNotThrow(() => g.before_state(call, { sha256: call.expectedDbSha256 }, world));
  assert.throws(() => g.before_state(call, { sha256: call.expectedDbSha256 }, g.world_snapshot('base-files\nnew-root\n')));
  assert.throws(() => g.before_state(call, { sha256: 'b'.repeat(64) }, world));
});
test('post-lock observation permits only selected exact closure and owned temporary constraint', () => {
  const before = state(record('unrelated', other));
  const after = state(record('unrelated', other) + record() + record(temporary, '03'.repeat(32), '20261114.120000', 'noarch', ''));
  assert.doesNotThrow(() => g.after_database(owner, { phase: 1 }, before, after));
  assert.doesNotThrow(() => g.after_database(owner, { phase: 2 }, after, after));
  const final = state(record('unrelated', other) + record());
  assert.doesNotThrow(() => g.after_database(owner, { phase: 3 }, after, final));
  for (const bad of [ state(record()), state(record('unrelated', '04'.repeat(32)) + record()),
    state(record('unrelated', other) + record() + record('unexpected', '05'.repeat(32))),
    state(record('unrelated', other) + record('libc', '06'.repeat(32))) ]) {
    assert.throws(() => g.after_database(owner, { phase: 1 }, before, bad));
  }
});
test('held identity compares device components and inode explicitly; replacement cannot refresh identity', () => {
  const file = { type: 'file', dev: { major: 0, minor: 19 }, inode: 423, uid: 0, mode: 448, nlink: 1, size: 100 };
  assert.doesNotThrow(() => g.require_same(file, { ...file, dev: { minor: 19, major: 0 } }, false));
  for (const replacement of [ { ...file, inode: 467 }, { ...file, nlink: 2 }, { ...file, uid: 1 },
    { ...file, mode: 493 }, { ...file, dev: { major: 1, minor: 19 } } ]) {
    assert.throws(() => g.require_same(file, replacement, false));
  }
});

test('simulation refuses unselected extraction, purge, reinstall and retained-package extraction before mutation', () => {
  const value = m.apply(budget(), m.snapshot(record()), asset, profile());
  assert.doesNotThrow(() => g.simulation('OK: 1 MiB in 1 packages\n', value, 1));
  assert.doesNotThrow(() => g.simulation('(1/1) Updating pinning libc (1-r1)\n', value, 2));
  for (const log of ['(1/1) Installing libc (1-r1)\n', '(1/1) Reinstalling libc (1-r1)\n',
    '(1/1) Purging unrelated (1-r1)\n', '(1/1) Installing unrelated (1-r1)\n',
    '(1/1) Installing libc (2-r1)\n', '(1/1) Unknown future action libc (1-r1)\n']) {
    assert.throws(() => g.simulation(log, value, 1));
  }
  const pending = m.apply(budget(), m.snapshot(record('unrelated', other)), asset, profile());
  assert.doesNotThrow(() => g.simulation('(1/1) Installing libc (1-r1)\n', pending, 1));
  assert.throws(() => g.simulation('(1/1) Installing libc (1-r1)\n', pending, 2));
});

test('fresh FLASH checks the APK simulation before reporting success or changing router state', () => {
  const installer = readFileSync(new URL('install-compact.sh', tools), 'utf8');
  const simulate = installer.indexOf('offline add --simulate --virtual');
  const preflight = installer.indexOf('ucode "$stage/fresh-install-guard.uc" preflight "$stage" "$temporary_constraint"');
  const success = installer.indexOf("echo 'Exact compact modules and complete package budgets verified'");
  const lock = installer.indexOf('\nacquire_transaction_lock\n');
  assert.ok(simulate >= 0 && simulate < preflight && preflight < success && success < lock);
  assert.doesNotMatch(installer.slice(simulate, preflight), /if \[ -n "\$accounting_profile" \]/);
});

test('fresh plans with and without accounting preserve the installed versions of system packages', () => {
  for (const value of [budget(), m.apply(budget(), m.snapshot(record('unrelated', other)), asset, profile())]) {
    assert.doesNotThrow(() => g.simulation('(1/1) Installing libc (1-r1)\n', value, 1));
    for (const line of ['Upgrading libc (0-r1 -> 1-r1)', 'Downgrading libc (2-r1 -> 1-r1)',
      'Replacing libc (1-r1 -> 1-r1)', 'Purging dnsmasq (2.93-r1)']) {
      assert.throws(() => g.simulation(`(1/1) ${line}\n`, value, 1));
    }
  }
});

test('fresh Cudy installs require the exact board, firmware and sole permitted storage mode', () => {
  const source = readFileSync(new URL('install-plan-model.uc', tools), 'utf8');
  const start = source.indexOf('export function fresh_board_mode(');
  assert.ok(start >= 0);
  const end = source.indexOf('\n};', start);
  const fn = vm.runInNewContext('(' + source.slice(start + 7, end + 2) + ')', {
    compact_reject: () => { throw Error('unsupported'); },
    compact_exact: (v, names) => { if (!v || Object.keys(v).some(k => !names.includes(k))) throw Error('keys'); },
    index: (s, val) => s.indexOf(val), join: (sep, list) => list.join(sep)
  });
  for (const [firmware, board, mode] of [['25.12.5', 'cudy,wr3000-v1', 'ram'],
                                        ['25.12.6', 'cudy,wr3000s-v1', 'flash']]) {
    const platform = { architecture: 'aarch64_cortex-a53', supportedTargets: ['mediatek/filogic'],
      supportedOpenWrt: [firmware], freshInstallBoard: { boardName: board, storageMode: mode } };
    assert.equal(fn(platform, firmware, board, 'auto'), mode);
    assert.equal(fn(platform, firmware, board, mode), mode);
    assert.throws(() => fn(platform, firmware, board, mode === 'ram' ? 'flash' : 'ram'));
    assert.throws(() => fn(platform, firmware, '', mode));
    assert.throws(() => fn(platform, firmware, 'cudy,other-v1', mode));
    assert.throws(() => fn({ ...platform, freshInstallBoard: null }, firmware, board, mode));
    assert.throws(() => fn(platform, '25.12.7', board, mode));
  }
});

 test('initial simulation admits exactly its owned SHA1 virtual package and padded native counters', () => {
  const value=m.apply(budget(),m.snapshot(record()),asset,profile());
  const log=`( 1/12) Installing ${temporary} (20261114.120000)\nOK: 1 MiB in 2 packages\n`;
  assert.doesNotThrow(()=>g.simulation(log,value,1,temporary));
  for(const bad of ['',log+log,log.replace(temporary,'.foreign-exact')])assert.throws(()=>g.simulation(bad,value,1,temporary));
 });

test('unrelated installed CID cannot impersonate a selected package object',()=>{
 assert.throws(()=>m.accounting(m.snapshot(record('unrelated')),packages,auth,'flash',asset,6291456));
});

test('native caller validates real PID/start/parent, boot, exact command and executable digest', () => {
  const boot = '11111111-2222-3333-4444-555555555555';
  const proc = (id, parent, start, state = 'S') => `${id} (apk test) ${state} ${parent} ${Array(17).fill('0').join(' ')} ${start} 0\n`;
  const args = ['/sbin/apk', '--no-network', 'add', 'libc'];
  const files = { '/proc/9/stat': proc(9, 7, 90), '/proc/9/cmdline': args.join('\x00') + '\x00',
    '/proc/9/exe': 'actual-apk', '/proc/sys/kernel/random/boot_id': boot + '\n' };
  const guard = load('fresh-install-guard.uc', { fs: { readfile: path => files[path] },
    fresh: { protected_bytes: () => 'owner-state' } }, 'let action=ARGV[0];');
  const owner = { stage: '/synthetic', driver: { pid: 7 }, profile: { nativeApkSha256: sha('actual-apk') } };
  const call = { schema: 1, kind: 'fresh-flash-native-call-v1', child: { pid: 9, start: '90' },
    arguments: args, bootId: boot, ownerSha256: sha('owner-state') };
  assert.equal(guard.native_call(owner, call).pid, 9);
  for (const mutate of [ x => x.child.start = '91', x => x.bootId = 'wrong', x => x.arguments.push('--no-scripts'),
    x => x.ownerSha256 = 'f'.repeat(64) ]) {
    const bad = normalize(call); mutate(bad); assert.throws(() => guard.native_call(owner, bad));
  }
  files['/proc/9/stat'] = proc(9, 8, 90); assert.throws(() => guard.native_call(owner, call));
  files['/proc/9/stat'] = proc(9, 7, 90); files['/proc/9/exe'] = 'other-apk';
  assert.throws(() => guard.native_call(owner, call));
});

test('held FD validation refuses replacement and expired/dead owner without accepting a new identity', () => {
  const file = { type: 'file', dev: { major: 0, minor: 19 }, inode: 423, uid: 0, mode: 448, nlink: 1, size: 4 };
  const dir = { type: 'directory', dev: { major: 0, minor: 19 }, inode: 100, uid: 0, mode: 448, nlink: 2, size: 99 };
  const boot = '11111111-2222-3333-4444-555555555555';
  let actual = { ...file }, readHook = 0;
  const fs = { dirname: path => path.slice(0,path.lastIndexOf('/')), stat: path => path.endsWith('/8') ? file : dir,
    lstat: path => path === '/hooks/owned' ? actual : dir,
    readfile: path => path.endsWith('/stat') ? `7 (driver) S 1 ${Array(17).fill('0').join(' ')} 70 0\n` :
      path.endsWith('boot_id') ? boot + '\n' : path.endsWith('uptime') ? '200.00 100.00\n' : (readHook++, 'hook') };
  const guard = load('fresh-install-guard.uc', { fs }, 'let action=ARGV[0];');
  guard.qualified_bytes = () => 'hook';
  const owner = { driver: { pid: 7, start: '70' }, bootId: boot, startedUptime: 100, expiresUptime: 300,
    hook: '/hooks/owned', hookIdentity: file, directoryIdentity: dir, hookSha256: sha('hook') };
  assert.doesNotThrow(() => guard.held(owner));
  readHook = 0; actual = { ...file, inode: 467 };
  assert.throws(() => guard.held(owner)); assert.equal(readHook, 0);
  actual = file; assert.throws(() => guard.held({ ...owner, expiresUptime: 199 }));
  assert.throws(() => guard.held({ ...owner, driver: { pid: 7, start: '71' } }));
});
