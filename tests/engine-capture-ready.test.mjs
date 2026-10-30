import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { read } from './helpers.mjs';
import { Script, createContext } from 'node:vm';

const source = await read('package/foxhole-openwrt-client/root/usr/share/foxhole/engine-capture.uc');
const stage = '/tmp/foxhole/engine-command-memory-native.io';
const ownerPid = 101;
const childPid = 42;
const registrarPid = 43;
const generation = '1200';
const ownerCommand = '/fixture/owner\x00';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const owner = ownerPid + ':900:' + hash(ownerCommand);

function functionSource(name) {
  const begin = source.indexOf('function ' + name + '(');
  assert.notEqual(begin, -1);
  const following = source.indexOf('\nfunction ', begin + 1);
  const control = source.indexOf('\nif(mode==', begin + 1);
  const end = Math.min(following < 0 ? source.length : following,
    control < 0 ? source.length : control);
  return source.slice(begin, end);
}

function blockSource(name) {
  const prefix = "if(mode=='" + name + "'){";
  const begin = source.indexOf(prefix);
  const end = source.indexOf('\nif(mode==', begin + prefix.length);
  assert.notEqual(begin, -1);
  assert.notEqual(end, -1);
  const body = source.slice(begin + prefix.length, end);
  assert.match(body, /}\s*$/);
  return body.replace(/}\s*$/, '');
}

const definitions = ['fail', 'process', 'unpack', 'main_live',
  'private_stage', 'read', 'write', 'state', 'prefix', 'initial',
  'pending_marker', 'child'].map(functionSource).join('\n');
const programs = Object.fromEntries(['register', 'ready', 'poll'].map((name) =>
  [name, new Script(definitions + '\n(function(){' + blockSource(name) + '})()')]));

function run(options = {}) {
  const role = options.role ?? 'native';
  const markerPath = stage + '/' + role + '.owner.json';
  const initialCommand = '/bin/sh\x00' + stage + '/helper\x00--owned-child\x00' +
    stage + '\x00' + role + '\x00' + owner + '\x00/fixture/native\x00';
  const files = new Map();
  const processes = new Map([
    [ownerPid, { pid: ownerPid, parent: 1, state: 'S', start: '900', command: ownerCommand, uid: 0 }],
    [childPid, { pid: childPid, parent: ownerPid, state: 'S', start: generation, command: initialCommand, uid: 0 }],
    [registrarPid, { pid: registrarPid, parent: childPid, state: 'S', start: '1201', command: '/fixture/registrar\x00', uid: 0 }],
  ]);
  let phase = 'register';
  let savedMarker;
  let sleeps = 0;
  let markerTransition = false;
  let registrationTransition = false;
  let pollTransition = false;
  let registerExecuted = false;
  const outcome = Symbol('outcome');

  function put(path, raw) {
    files.set(path, { raw, type: 'file', uid: 0, nlink: 1, mode: 0o600 });
  }

  function terminateChild(state) {
    if (state === 'absent') processes.delete(childPid);
    else {
      const value = processes.get(childPid);
      value.state = state;
      if (state === 'Z') value.command = '';
    }
  }

  function statText(value) {
    const fields = Array(20).fill('0');
    fields[0] = value.state;
    fields[1] = String(value.parent);
    fields[19] = value.start;
    return value.pid + ' (memory-fixture) ' + fields.join(' ');
  }

  const fs = {
    dirname(path) { return path.slice(0, path.lastIndexOf('/')); },
    lstat(path) {
      if (path === '/tmp/foxhole' || path === stage)
        return { type: 'directory', uid: 0, mode: 0o700 };
      const value = files.get(path);
      const metadata = value ? { ...value, size: value.raw.length } : null;
      if (phase === 'ready' && path === markerPath &&
          options.terminalAfterMarker && !markerTransition) {
        markerTransition = true;
        terminateChild(options.terminalAfterMarker);
      }
      return metadata;
    },
    stat(path) {
      const found = /^\/proc\/([0-9]+)$/.exec(path);
      if (!found) return null;
      const value = processes.get(Number(found[1]));
      const metadata = value ? { uid: value.uid } : null;
      if (phase === 'poll' && Number(found[1]) === childPid &&
          options.reapAfterFirstPollStat && !pollTransition) {
        pollTransition = true;
        processes.delete(childPid);
      }
      return metadata;
    },
    readfile(path) {
      if (path === '/proc/self/stat') return statText(processes.get(registrarPid));
      const found = /^\/proc\/([0-9]+)\/(stat|cmdline)$/.exec(path);
      if (!found) return files.get(path)?.raw ?? null;
      const pid = Number(found[1]);
      if (phase === 'ready' && pid === childPid && found[2] === 'stat' &&
          options.registerDuringObservation && !registrationTransition) {
        registrationTransition = true;
        files.set(markerPath, { ...savedMarker });
      }
      const value = processes.get(pid);
      if (!value) return null;
      if (found[2] === 'stat') return statText(value);
      return value.missingCommand ? null : value.command;
    },
    open(path, flags, mode) {
      assert.equal(path, markerPath);
      assert.equal(flags, 'wxe');
      assert.equal(mode, 0o600);
      if (files.has(path)) return null;
      put(path, '');
      return {
        write(raw) { files.get(path).raw += raw; return raw.length; },
        flush() { return true; },
        close() { return true; },
      };
    },
  };
  put(stage + '/owner.json', JSON.stringify({ owner }));
  const context = createContext({
    mode: 'register', ARGV: ['register', stage, role, owner, String(childPid)],
    roles: ['stdout', 'stderr', 'timer', 'native'], fs,
    digest: { sha256: hash },
    match(value, expression) { return String(value).match(expression); },
    split(value, separator) { return value.split(separator); },
    trim(value) { return value.trim(); },
    length(value) { return value.length; },
    index(value, wanted) { return value.indexOf(wanted); },
    json(value) { return JSON.parse(value); },
    type(value) {
      if (value === null) return 'null';
      if (Array.isArray(value)) return 'array';
      if (Number.isInteger(value)) return 'int';
      if (typeof value === 'boolean') return 'bool';
      return typeof value;
    },
    sprintf(format, value) { assert.equal(format, '%J'); return JSON.stringify(value); },
    sleep(milliseconds) {
      assert.equal(milliseconds, 50);
      sleeps++;
      if (options.resolveAmbiguity === 'absent') processes.delete(childPid);
      if (options.resolveAmbiguity === 'live') processes.get(childPid).missingCommand = false;
      return !options.sleepFailed;
    },
    exit(status) { throw { outcome, status }; },
  }, { codeGeneration: { strings: false, wasm: false } });

  function execute(name) {
    context.mode = name;
    context.ARGV = [name, stage, role, owner, String(childPid)];
    try {
      programs[name].runInContext(context, { timeout: 1000 });
      assert.fail('predicate must exit explicitly');
    } catch (error) {
      if (error.outcome !== outcome) throw error;
      return error.status;
    }
  }

  assert.equal(execute('register'), 0);
  registerExecuted = true;
  savedMarker = { ...files.get(markerPath) };
  const registered = JSON.parse(savedMarker.raw);
  assert.equal(registered.owner, owner);
  assert.equal(registered.role, role);
  assert.equal(registered.pid, childPid);
  assert.equal(registered.start, generation);
  assert.equal(registered.birthCommandSha256, hash(initialCommand));
  assert.equal(registered.registeredBeforeBlockingOrExec, true);

  phase = 'ready';
  processes.get(childPid).command = options.initialChild ? initialCommand : '/fixture/executed\x00';
  if (options.childState) terminateChild(options.childState);
  if (options.missingCommand) processes.get(childPid).missingCommand = true;
  if (options.start) processes.get(childPid).start = options.start;
  if (options.parent) processes.get(childPid).parent = options.parent;
  if (options.marker === 'absent') files.delete(markerPath);
  if (options.marker === 'pending') put(markerPath, '');
  if (options.recordMutation) {
    const value = JSON.parse(files.get(markerPath).raw);
    options.recordMutation(value);
    put(markerPath, JSON.stringify(value));
  }
  if (options.fileMutation) Object.assign(files.get(markerPath), options.fileMutation);
  if (options.ownerStateWrong) put(stage + '/owner.json', JSON.stringify({ owner: 'invalid' }));
  const status = execute('ready');
  assert.ok(sleeps <= 4);
  const result = { status, sleeps, registerExecuted,
    actualNativeCommandExecuted: false, actualNativeRCObserved: false };
  if (status === 0 && options.modelWaitStatus !== undefined) {
    phase = 'poll';
    if (options.pollChildStart) processes.get(childPid).start = options.pollChildStart;
    if (options.pollMissingCommand) processes.get(childPid).missingCommand = true;
    if (options.pollChildUid !== undefined) processes.get(childPid).uid = options.pollChildUid;
    if (options.pollOwnerMismatch) {
      const marker = JSON.parse(files.get(markerPath).raw);
      marker.owner = 'invalid';
      put(markerPath, JSON.stringify(marker));
    }
    result.pollStatus = execute('poll');
    assert.equal(result.pollStatus, options.pollExpectedStatus ?? 0);
    if (result.pollStatus !== 0) return result;
    const virtualShellWaitMap = new Map([[childPid, options.modelWaitStatus]]);
    result.modeledWaitStatus = virtualShellWaitMap.get(childPid);
    virtualShellWaitMap.delete(childPid);
    assert.equal(virtualShellWaitMap.size, 0);
  }
  return result;
}

const cases = [
  ['native registered live', {}, 0],
  ['native registered Z modeled wait0', { childState: 'Z', modelWaitStatus: 0 }, 0],
  ['native registered Z modeled wait7', { childState: 'Z', modelWaitStatus: 7 }, 0],
  ['native registered absent modeled wait0', { childState: 'absent', modelWaitStatus: 0 }, 0],
  ['native registered absent modeled wait7', { childState: 'absent', modelWaitStatus: 7 }, 0],
  ['native live to Z after marker', { terminalAfterMarker: 'Z', modelWaitStatus: 0 }, 0],
  ['native live to absent after marker', { terminalAfterMarker: 'absent', modelWaitStatus: 7 }, 0],
  ['native ambiguous then confirmed absent', { missingCommand: true, resolveAmbiguity: 'absent', modelWaitStatus: 0 }, 0],
  ['native ambiguous then live', { missingCommand: true, resolveAmbiguity: 'live' }, 0],
  ['registration during snapshot from absent marker', { marker: 'absent', registerDuringObservation: true }, 0],
  ['registration during snapshot from pending marker', { marker: 'pending', registerDuringObservation: true }, 0],
  ['unregistered pending bounded exhaustion', { marker: 'pending', initialChild: true }, 1],
  ['unregistered absent bounded exhaustion', { marker: 'absent', initialChild: true }, 1],
  ['unregistered absent child', { marker: 'absent', childState: 'absent' }, 1],
  ['unregistered zombie child', { marker: 'pending', childState: 'Z' }, 1],
  ['native wrong owner', { recordMutation(value) { value.owner = 'invalid'; } }, 1],
  ['native wrong role', { recordMutation(value) { value.role = 'stdout'; } }, 1],
  ['native wrong PID', { recordMutation(value) { value.pid = 999; } }, 1],
  ['native string PID', { recordMutation(value) { value.pid = String(childPid); } }, 1],
  ['native wrong marker start', { recordMutation(value) { value.start = '999'; } }, 1],
  ['native malformed marker start', { recordMutation(value) { value.start = 'invalid'; } }, 1],
  ['native reparented generation', { parent: 999 }, 1],
  ['native reused live PID', { start: '999' }, 1],
  ['native reused zombie PID', { childState: 'Z', start: '999' }, 1],
  ['native persistent incomplete process snapshot', { missingCommand: true }, 1],
  ['native false registration evidence', { recordMutation(value) { value.registeredBeforeBlockingOrExec = false; } }, 1],
  ['native malformed birth hash', { recordMutation(value) { value.birthCommandSha256 = 'invalid'; } }, 1],
  ['native untrusted marker mode', { fileMutation: { mode: 0o644 } }, 1],
  ['native untrusted marker nlink', { fileMutation: { nlink: 2 } }, 1],
  ['native untrusted marker UID', { fileMutation: { uid: 1 } }, 1],
  ['timer zombie stays refused', { role: 'timer', childState: 'Z' }, 1],
  ['stdout zombie stays refused', { role: 'stdout', childState: 'Z' }, 1],
  ['stderr absent stays refused', { role: 'stderr', childState: 'absent' }, 1],
  ['timer live stays ready', { role: 'timer' }, 0],
  ['stdout live stays ready', { role: 'stdout' }, 0],
  ['stderr live stays ready', { role: 'stderr' }, 0],
  ['failed bounded wait stays refused', { marker: 'pending', initialChild: true, sleepFailed: true }, 1],
  ['wrong stage owner stays refused', { ownerStateWrong: true }, 1],
  ['native empty marker start', { recordMutation(value) { value.start = ''; } }, 1],
  ['native absent registration evidence', { recordMutation(value) { delete value.registeredBeforeBlockingOrExec; } }, 1],
];

assert.equal(cases.length, 40);
for (const [name, options, expected] of cases) {
  test(name, () => {
    const actual = run(options);
    assert.equal(actual.registerExecuted, true);
    assert.equal(actual.status, expected);
    assert.equal(actual.actualNativeCommandExecuted, false);
    assert.equal(actual.actualNativeRCObserved, false);
    if (options.modelWaitStatus !== undefined)
      assert.equal(actual.modeledWaitStatus, options.modelWaitStatus);
    if (name.endsWith('bounded exhaustion')) assert.equal(actual.sleeps, 4);
  });
}

// Native reap ordering is qualified with a real child.
for (const waitStatus of [0, 7]) {
  test('poll confirms reaped generation after first stat, modeled wait' + waitStatus, () => {
    const result = run({ reapAfterFirstPollStat: true, modelWaitStatus: waitStatus });
    assert.equal(result.pollStatus, 0);
    assert.equal(result.modeledWaitStatus, waitStatus);
    assert.equal(result.actualNativeRCObserved, false);
  });
}
for (const [name, options] of [
  ['changed generation', { pollChildStart: '999' }],
  ['changed owner', { pollOwnerMismatch: true }],
  ['present incomplete process', { pollMissingCommand: true }],
  ['changed process UID', { pollChildUid: 1 }],
]) {
  test('poll refuses ' + name + ' after readiness', () => {
    const result = run({ ...options, modelWaitStatus: 0, pollExpectedStatus: 20 });
    assert.equal(result.pollStatus, 20);
    assert.equal(result.modeledWaitStatus, undefined);
    assert.equal(result.actualNativeRCObserved, false);
  });
}
