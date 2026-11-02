// Execute the actual Ucode transaction source against in-memory filesystem,
// UCI and authorization adapters. Native Ucode/flash durability is separate QA.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const modules = resolve(dirname(fileURLToPath(import.meta.url)), '../package/foxhole-openwrt-client/root/usr/share/foxhole');
const STATE = '/etc/foxhole/state.json', CONFIG = '/etc/config/foxhole', POLICY = '/etc/foxhole/update-policy.json';
const JOURNAL = '/etc/foxhole/backup-restore/journal.json';
const clone = value => JSON.parse(JSON.stringify(value));
const hash = value => createHash('sha256').update(value).digest('hex');
const globals = {
  type: value => value == null ? 'null' : Array.isArray(value) ? 'array' : typeof value === 'boolean' ? 'bool'
    : typeof value === 'number' ? Number.isInteger(value) ? 'int' : 'double' : typeof value === 'object' ? 'object' : typeof value,
  length: value => typeof value === 'string' ? Buffer.byteLength(value) : Array.isArray(value) ? value.length : Object.keys(value).length,
  keys: Object.keys, sort: value => [...value].sort(), map: (value, fn) => value.map(fn), filter: (value, fn) => value.filter(fn),
  index: (value, item) => value.indexOf(item), json: JSON.parse, sprintf: (format, value) => {
    assert.equal(format, '%J'); return JSON.stringify(value) ?? 'null';
  },
  match: (value, pattern) => String(value).match(pattern), hexenc: value => Buffer.from(value).toString('hex'),
  time: () => 1700000000, die: error => { throw error instanceof Error ? error : new Error(String(error)); }
};

function load(name, dependencies) {
  let source = readFileSync(resolve(modules, name), 'utf8');
  const exported = [...source.matchAll(/^export (?:function|const) (\w+)/gm)].map(match => match[1]);
  source = source.replace(/^import .*;\n/gm, '').replace(/^export /gm, '')
    .replace(/\bfor\(let (\w+) in /g, 'for(let $1 of ')
    .replaceAll('[[:cntrl:]]', '[\\u0000-\\u001f\\u007f]');
  const bindings = { ...globals, ...dependencies };
  return new Function(...Object.keys(bindings), `${source}\nreturn {${exported.join(',')}};`)(...Object.values(bindings));
}

class MemoryFS {
  entries = new Map(); locks = new Map(); sequence = 10; hook = null; calls = []; afterStateUnlock = null; availableBlocks = 100000;
  info(path) { return this.entries.get(path) ?? null; }
  directory(path, mode = 0o700) {
    if (path !== '/' && !this.info(dirname(path))) this.directory(dirname(path));
    this.entries.set(path, { type: 'directory', uid: 0, gid: 0, mode, inode: ++this.sequence,
      nlink: 1, size: 0, dev: { major: 0, minor: 1 }, mtime: this.sequence, ctime: this.sequence });
  }
  put(path, raw, mode = 0o600) {
    const previous = this.raw(path);
    if (!this.info(dirname(path))) this.directory(dirname(path));
    this.entries.set(path, { type: 'file', uid: 0, gid: 0, mode, inode: ++this.sequence,
      nlink: 1, size: Buffer.byteLength(raw), raw, dev: { major: 0, minor: 1 }, mtime: this.sequence, ctime: this.sequence });
    this.calls.push(path); this.hook?.(path, raw, previous);
  }
  raw(path) { return this.info(path)?.raw ?? null; }
  json(path) { const raw = this.raw(path); return raw == null ? null : JSON.parse(raw); }
  unlink(path) { return this.entries.delete(path); }
  open(path, flags, mode = 0o600) {
    if (flags.includes('x') && this.info(path)) return null;
    if (!this.info(path)) this.put(path, '', mode);
    const owner = Symbol(path); let closed = false;
    return {
      write: raw => { this.put(path, this.raw(path) + raw, mode); return Buffer.byteLength(raw); },
      flush: () => true,
      lock: action => {
        if (action === 'u') {
          if (this.locks.get(path) === owner) this.locks.delete(path);
          if (path === '/etc/foxhole/state.lock' && this.afterStateUnlock) {
            const action = this.afterStateUnlock; this.afterStateUnlock = null; action();
          }
          return true;
        }
        if (this.locks.has(path) && this.locks.get(path) !== owner) return false;
        this.locks.set(path, owner); return true;
      },
      close: () => { if (!closed && this.locks.get(path) === owner) this.locks.delete(path); closed = true; }
    };
  }
  glob(pattern) {
    const parent = dirname(pattern), hidden = pattern.endsWith('/.*');
    return [...this.entries.keys()].filter(path => dirname(path) === parent && path !== parent &&
      (hidden ? path.slice(parent.length + 1).startsWith('.') : !path.slice(parent.length + 1).startsWith('.')));
  }
  api() {
    return {
      lstat: path => this.info(path) && clone(this.info(path)),
      stat: path => path === '/proc/self' ? { uid: 0 } : this.info(path),
      readfile: (path, limit) => path === '/dev/urandom' ? Buffer.alloc(limit, 3) : this.raw(path)?.slice(0, limit) ?? null,
      open: (...args) => this.open(...args), dirname, mkdir: (path, mode) => { if (this.info(path)) return false; this.directory(path, mode); return true; },
      unlink: path => this.unlink(path), chmod: (path, mode) => { if (!this.info(path)) return false; this.info(path).mode = mode; return true; },
      rename: (from, to) => {
        if (!this.info(from)) return false;
        this.entries.set(to, this.info(from)); this.unlink(from); this.calls.push(to); this.hook?.(to, this.raw(to)); return true;
      },
      statvfs: () => ({ frsize: 4096, bavail: this.availableBlocks }), glob: pattern => this.glob(pattern),
      rmdir: path => { if (this.glob(`${path}/*`).length || this.glob(`${path}/.*`).length) return false; return this.unlink(path); }
    };
  }
  store() {
    return {
      read: (path, maximum) => { const raw = this.raw(path); if (raw != null && Buffer.byteLength(raw) > maximum) throw new Error('storage_error'); return raw; },
      write: (path, raw) => this.put(path, raw), target: () => {},
      directory: path => { if (!this.info(path)) this.directory(path); },
      file_metadata: info => info?.type === 'file' && info.uid === 0 && info.nlink === 1 && (info.mode & 0o077) === 0
    };
  }
  uci() {
    return { cursor: (configDirectory = '/etc/config') => {
      const path = `${configDirectory}/foxhole`; let current = this.json(path);
      return {
        changes: () => ({}), unload: () => true,
        get: (config, section, key) => key == null ? current[section]?.type ?? null : current[section]?.[key] ?? null,
        set: (config, section, key, value) => { current[section][key] = clone(value); return true; },
        delete: (config, section, key) => { delete current[section][key]; return true; },
        commit: () => { this.put(path, JSON.stringify(current), 0o644); return true; }
      };
    } };
  }
}

function fixture({ policyAbsent = false, stopped = false } = {}) {
  const memory = new MemoryFS();
  memory.directory('/', 0o755); memory.directory('/etc', 0o755); memory.directory('/etc/config', 0o755); memory.directory('/etc/foxhole');
  const settings = { language: 'ru', standaloneAccess: true, localRules: false, localScope: 'all', clientRules: false,
    killSwitch: false, darkStyle: false, darkCharts: true, plainHeadings: false, hideRouterStatus: false, theme: 'dark' };
  const current = { schema: 1, revision: 5, activeServerId: stopped ? null : 'server-aaaaaaaaaaaa', settings,
    countries: [], devices: [], sites: [], servers: [{ id: 'server-aaaaaaaaaaaa', name: 'Fixture', endpoint: 'fixture.invalid:443', config: 'synthetic' }], clients: [] };
  memory.put(STATE, JSON.stringify(current));
  memory.put(CONFIG, JSON.stringify({ panel: { type: 'foxhole', mode: 'runtime', standalone: '1', telemetry_interval: '5',
    tun_mtu: '1500', bootstrap_pin: 'synthetic-private-setting' } }), 0o644);
  if (!policyAbsent) memory.put(POLICY, JSON.stringify({ schema: 1, revision: 3, enabled: false, lastAttemptAtUnixMs: 1234 }));
  memory.put('/etc/foxhole/auth.json', JSON.stringify({ schema: 1, changed: true, hash: 'a'.repeat(64), salt: 'b'.repeat(32) }));
  memory.put('/etc/foxhole/pairing.json', JSON.stringify({ schema: 1, devices: [] }));
  memory.put('/etc/foxhole/mobile.json', JSON.stringify({ schema: 1, phones: [] }));
  memory.put('/etc/foxhole/mobile.key', 'synthetic-private-key'); memory.put('/etc/foxhole/mobile.crt', 'synthetic-certificate', 0o644);
  const stateModel = { validate_state: value => { assert.equal(value.schema, 1); assert.ok(Number.isInteger(value.revision)); return clone(value); } };
  const mobile = { journal: value => value ?? { schema: 1, phones: [] } };
  const digest = { sha256: hash };
  const model = load('backup-model.uc', { digest, model: stateModel, mobile });
  const service = load('backup-service.uc', { fs: memory.api(), uci: memory.uci(), digest, backup: model,
    state_model: stateModel, policy_model: { policy: value => value ?? { schema: 1, revision: 0, enabled: false, lastAttemptAtUnixMs: null } },
    mobile, store: memory.store(), system: () => 0 });
  const principal = { kind: 'admin', user: 'root', verifier: hash('a'.repeat(64)) };
  const context = { principal, owner: hash(JSON.stringify(principal)), authorize: () => true,
    quiesce: () => true, resume: value => { context.lastResumed = clone(value); return true; } };
  const document = service.export_backup(context);
  document.state.settings.language = 'en'; document.state.servers[0].name = 'Restored';
  document.panel.tun_mtu = '1400'; document.autoUpdate.enabled = true;
  const before = new Map([STATE, CONFIG, POLICY, '/etc/foxhole/auth.json', '/etc/foxhole/pairing.json', '/etc/foxhole/mobile.key', '/etc/foxhole/mobile.crt']
    .map(path => [path, memory.raw(path)]));
  const id = `restore-${'1'.repeat(32)}`;
  const queue = () => service.queue_backup(document, 5, true, id, context);
  const run = () => service.run_backup(id, context);
  return { memory, model, service, context, document, before, id, queue, run };
}

function unchanged(fixture, paths = [STATE, CONFIG, POLICY]) {
  for (const path of paths) assert.equal(fixture.memory.raw(path), fixture.before.get(path), path);
}
function identitiesUnchanged(fixture) { unchanged(fixture, ['/etc/foxhole/auth.json', '/etc/foxhole/pairing.json', '/etc/foxhole/mobile.key', '/etc/foxhole/mobile.crt']); }
function once(fixture, when, action) {
  fixture.memory.hook = (path, raw) => {
    if (when(path, raw)) { fixture.memory.hook = null; action(path, raw); }
  };
}

test('queue leaves live product files and identity untouched', () => {
  const f = fixture(); assert.equal(f.queue().state, 'PREPARED'); unchanged(f); identitiesUnchanged(f);
});
test('commit restores typed settings and preserves private UCI fields, identity and scheduler history', () => {
  const f = fixture(); f.queue(); assert.equal(f.run().state, 'COMMITTED');
  assert.equal(f.memory.json(STATE).settings.language, 'en'); assert.equal(f.memory.json(STATE).revision, 6);
  assert.equal(f.memory.json(CONFIG).panel.tun_mtu, '1400'); assert.equal(f.memory.json(CONFIG).panel.bootstrap_pin, 'synthetic-private-setting');
  assert.equal(f.memory.json(POLICY).enabled, true); assert.equal(f.memory.json(POLICY).lastAttemptAtUnixMs, 1234);
  identitiesUnchanged(f);
});
test('management device selection survives a backup restore without touching authentication', () => {
  const f=fixture();f.document.panel.mobile_devices=['br-lan','br-vpn'];
  f.queue();assert.equal(f.run().state,'COMMITTED');
  assert.deepEqual(f.memory.json(CONFIG).panel.mobile_devices,['br-lan','br-vpn']);
  identitiesUnchanged(f);
});
for (const path of [CONFIG, POLICY]) test(`fault after ${path} publication rolls back only product settings`, () => {
  const f = fixture(); f.queue(); once(f, candidate => candidate === path, () => { throw new Error('injected interruption'); });
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'CANCELLED'); unchanged(f); identitiesUnchanged(f);
});
test('boot recovery cancels an unstarted prepared job', () => {
  const f = fixture(); f.queue(); assert.equal(f.service.recover().state, 'CANCELLED'); unchanged(f); identitiesUnchanged(f);
});
test('lost committed marker is recovered forward, without replaying state write', () => {
  const f = fixture(); f.queue(); let stateWrites = 0;
  f.memory.hook = (path, raw, previous) => {
    if (path === STATE) stateWrites++;
    if (path === JOURNAL && JSON.parse(raw).phase === 'COMMITTED') {
      f.memory.hook = null; f.memory.put(JOURNAL, previous); throw new Error('interrupted marker');
    }
  };
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'COMMITTED'); assert.equal(stateWrites, 1); identitiesUnchanged(f);
});
test('live Stop between files is preserved and cancels before commit', () => {
  const f = fixture(); f.queue(); once(f, path => path === CONFIG, () => {
    assert.equal(f.memory.locks.has('/etc/foxhole/state.lock'), false);
    const current = f.memory.json(STATE); current.activeServerId = null; current.revision++; f.memory.put(STATE, JSON.stringify(current));
    f.memory.put('/etc/foxhole/engine-intent.json', JSON.stringify({ schema: 1, revision: 1 }));
  });
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'CANCELLED');
  assert.equal(f.memory.json(STATE).activeServerId, null); assert.equal(f.memory.json(STATE).settings.language, 'ru');
  unchanged(f, [CONFIG, POLICY]); identitiesUnchanged(f); assert.equal(f.context.lastResumed.activeServerId, null);
});
test('Stop while already disconnected invalidates the queued reconnect intent', () => {
  const f = fixture({ stopped: true }); f.document.state.activeServerId = 'server-aaaaaaaaaaaa'; f.queue();
  f.memory.put('/etc/foxhole/engine-intent.json', JSON.stringify({ schema: 1, revision: 1 }));
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'CANCELLED'); unchanged(f); identitiesUnchanged(f);
});
test('pairing revocation during writes is never restored from stale data', () => {
  const f = fixture(); f.queue(); let revoked;
  once(f, path => path === POLICY, () => { revoked = JSON.stringify({ schema: 1, devices: [], fixtureRevoked: true }); f.memory.put('/etc/foxhole/pairing.json', revoked); });
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'CANCELLED'); unchanged(f);
  assert.equal(f.memory.raw('/etc/foxhole/pairing.json'), revoked);
});
test('unknown independent config edit is retained and enters recovery required', () => {
  const f = fixture(); f.queue(); let independent;
  once(f, path => path === CONFIG, () => { independent = JSON.stringify({ panel: { type: 'foxhole', fixture: 'independent' } }); f.memory.put(CONFIG, independent); });
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'RECOVERY_REQUIRED');
  assert.equal(f.memory.raw(CONFIG), independent); unchanged(f, [STATE]); identitiesUnchanged(f);
});
test('absent original auto-update policy is removed again on rollback', () => {
  const f = fixture({ policyAbsent: true }); f.queue(); once(f, path => path === POLICY, () => { throw new Error('interruption'); });
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'CANCELLED'); unchanged(f); identitiesUnchanged(f);
});
test('revoked principal before worker start cancels its own pending job', () => {
  const f = fixture(); f.queue(); f.context.authorize = () => false;
  assert.throws(f.run); f.context.authorize = () => true;
  assert.equal(f.service.status(f.context).state, 'CANCELLED'); unchanged(f); identitiesUnchanged(f);
});
test('same committed request ID is read back without repeating product mutations', () => {
  const f = fixture(); f.queue(); f.run(); const before = f.memory.calls.length;
  assert.equal(f.service.queue_backup(f.document, 5, true, f.id, f.context).state, 'COMMITTED');
  assert.deepEqual(f.memory.calls.slice(before).filter(path => [STATE, CONFIG, POLICY].includes(path)), []);
});
test('queued native package jobs exclude backup restoration', () => {
  const f = fixture(); f.memory.put('/etc/foxhole/update-job.json', JSON.stringify({ state: 'QUEUED' }));
  assert.throws(f.queue, /backup_busy/); unchanged(f); identitiesUnchanged(f);
});
test('Stop after state commit survives forward recovery of a missing terminal marker', () => {
  const f = fixture(); f.queue();
  f.memory.hook = (path, raw, previous) => {
    if (path !== JOURNAL || JSON.parse(raw).phase !== 'COMMITTED') return;
    f.memory.hook = null; f.memory.put(JOURNAL, previous);
    f.memory.afterStateUnlock = () => {
      const current = f.memory.json(STATE); current.activeServerId = null; current.revision++;
      f.memory.put(STATE, JSON.stringify(current));
      f.memory.put('/etc/foxhole/engine-intent.json', JSON.stringify({ schema: 1, revision: 1 }));
    };
    throw new Error('missing terminal marker');
  };
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'COMMITTED');
  assert.equal(f.memory.json(STATE).activeServerId, null); assert.equal(f.memory.json(STATE).settings.language, 'en');
  assert.equal(f.context.lastResumed.activeServerId, null); identitiesUnchanged(f);
});
test('space refusal precedes any live product file replacement', () => {
  const f = fixture(); f.memory.availableBlocks = 1; assert.throws(f.queue, /backup_no_space/);
  unchanged(f); identitiesUnchanged(f);
});
test('client revocation before the commit marker survives rollback of the restore', () => {
  const f = fixture(), current = f.memory.json(STATE);
  const client = { id: 'client-aaaaaaaaaaaa', name: 'Fixture', deviceType: 'smartphone', serverId: null };
  current.clients = [client]; f.memory.put(STATE, JSON.stringify(current)); f.document.state.clients = [client]; f.queue();
  once(f, path => path === CONFIG, () => {
    const current = f.memory.json(STATE); current.clients = []; current.revision++; f.memory.put(STATE, JSON.stringify(current));
  });
  assert.throws(f.run); assert.equal(f.service.status(f.context).state, 'CANCELLED');
  assert.deepEqual(f.memory.json(STATE).clients, []); assert.equal(f.memory.json(STATE).settings.language, 'ru');
  unchanged(f, [CONFIG, POLICY]); identitiesUnchanged(f);
});
test('revocation revision bridge admits only the proven current restore transition', () => {
  const f = fixture(); f.queue(); f.run();
  assert.equal(f.service.revocation_revision_allowed(5, f.memory.json(STATE)), true);
  assert.equal(f.service.revocation_revision_allowed(4, f.memory.json(STATE)), false);
  const current = f.memory.json(STATE); current.settings.language = 'de'; current.revision++; f.memory.put(STATE, JSON.stringify(current));
  assert.equal(f.service.revocation_revision_allowed(5, f.memory.json(STATE)), false);
});
test('confirmation must be a boolean before journal or product mutation', () => {
  const f = fixture();
  assert.throws(() => f.service.queue_backup(f.document, 5, 'true', f.id, f.context), /backup_invalid/);
  assert.equal(f.memory.raw(JOURNAL), null); unchanged(f); identitiesUnchanged(f);
});
