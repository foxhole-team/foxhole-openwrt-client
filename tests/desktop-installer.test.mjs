import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, delimiter, join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import test from 'node:test';

const installer = new URL('../tools/foxhole-openwrt-install.sh', import.meta.url).pathname;
const hash = value => createHash('sha256').update(value).digest('hex');
const manifest = 'a'.repeat(64);
const options = ['--release', 'v1.0.13', '--manifest-sha256', manifest, '--installer-sha256', 'b'.repeat(64)];

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'foxhole-installer-tests-'));
  t.after(() => rmSync(root, {recursive:true,force:true}));
  const add = (name, body) => writeFileSync(join(root, name), '#!/bin/sh\n' + body + '\n', {mode:0o755});
  const env = { ...process.env, PATH:root + delimiter + process.env.PATH };
  add('uname', 'printf "%s\\n" "$FOXHOLE_TEST_OS"');
  for (const command of ['ip','route','route.exe']) add(command, 'printf "%s\\n" "$FOXHOLE_TEST_ROUTES"');
  add('ssh', 'printf "%s\\000" "$@"; exit "${FOXHOLE_TEST_SSH_EXIT:-0}"');
  return {root,add,env,run:(args,patch={})=>spawnSync('/bin/bash',[installer,...args],{
    env:{...env,...patch},encoding:'utf8',timeout:3000})};
}

function sshArgs(result, exit=0) {
  assert.equal(result.status,exit,result.stderr);
  return result.stdout.split('\0').slice(0,-1);
}

test('Bash wrapper chooses the preferred IPv4 gateway on Mac Linux and Git Bash', t => {
  const {run} = fixture(t);
  for (const [os, routes, host] of [
    ['Darwin','route to: default\n gateway: 192.168.0.1','192.168.0.1'],
    ['Linux','default dev tun0 scope link\ndefault via 192.168.1.1 dev eth0 metric 120\ndefault via 10.0.0.1 dev wlan0 metric 30','10.0.0.1'],
    ['MINGW64_NT-10.0',' 0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.19 255\r\n 0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.8 20\r','10.0.0.1'],
  ]) {
    assert.ok(sshArgs(run(options,{FOXHOLE_TEST_OS:os,FOXHOLE_TEST_ROUTES:routes})).includes('root@'+host));
  }
});

test('wrapper uses interactive, verified SSH and hands both release pins to OpenWrt', t => {
  const {run} = fixture(t);
  const argv = sshArgs(run([...options,'--host=192.168.1.1','--ram','--no-auto-update'],{FOXHOLE_TEST_SSH_EXIT:'37'}),37);
  assert.deepEqual(argv.slice(0,-1),['-tt','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=ask',
    '-o','ClearAllForwardings=yes','--','root@192.168.1.1']);
  const remote = argv.at(-1);
  assert.match(remote, /release_tag='v1\.0\.13'/);
  assert.match(remote, /manifest_hash='a{64}'/);
  assert.match(remote, /installer_hash='b{64}'/);
  assert.match(remote, /storage='--ram'/);
  assert.match(remote, /auto_update='0'/);
  assert.match(remote, /DISTRIB_ID.*OpenWrt/);
  assert.match(remote, /sha256sum -c -[\s\S]*sh "\$installer"/);
  assert.doesNotMatch(remote, /accept-license|allow-untrusted|curl .*\|/);
});

test('wrapper refuses invalid and conflicting values before contacting SSH', t => {
  const {run} = fixture(t);
  for (const extra of [['--host=-obad'],['--host=127.0.0.1'],['--host=01.2.3.4'],['--host=224.0.0.1'],
    ['--release=v1.0.13; id'],['--installer-sha256=0'],['--ram','--auto'],['--accept-license'],['--host']]) {
    const result = run([...options,'--host=192.168.1.1',...extra]);
    assert.equal(result.status,2);
    assert.match(result.stderr,/error:/);
    assert.equal(result.stdout,'');
  }
});

test('router shell refuses tampered download and preserves explicit storage and opt-out', t => {
  const {run,root,add,env} = fixture(t);
  const release = join(root,'openwrt_release');
  writeFileSync(release,'DISTRIB_ID=OpenWrt\n');
  const synthetic = '#!/bin/sh\nprintf "EXECUTED:%s\\n" "$*"\n';
  add('uclient-fetch','test "$1:$2:$3:$4" = "-q:-T:60:-O" || exit 9\nprintf "%s" "$FOXHOLE_TEST_INSTALLER" > "$5"');
  const argv = sshArgs(run(['--host','192.168.1.1','--release','v1.0.13','--manifest-sha256',manifest,
    '--installer-sha256',hash(synthetic),'--auto','--no-auto-update']));
  const remote = argv.at(-1).replaceAll('/etc/openwrt_release',release);
  const apply = value=>spawnSync('/bin/sh',['-c',remote],{env:{...env, FOXHOLE_TEST_INSTALLER:value},encoding:'utf8',timeout:3000});
  const good = apply(synthetic);
  assert.equal(good.status,0,good.stderr);
  assert.match(good.stdout,/EXECUTED:--base-url https:\/\/github\.com\/foxhole-team\/foxhole-openwrt-client\/releases\/download\/v1\.0\.13 --manifest-sha256 a{64} --auto --no-auto-update --apply/);
  const bad=apply(synthetic+'\n');
  assert.notEqual(bad.status,0);
  assert.doesNotMatch(bad.stdout,/EXECUTED:/);
});

test('compact release hashes the desktop asset separately from router helpers', () => {
  const source = readFileSync(join(dirname(installer),'compact-install-bundle.py'),'utf8');
  assert.match(source, /DESKTOP_INSTALLER = ROOT \/ 'tools' \/ 'foxhole-openwrt-install\.sh'/);
  assert.match(source, /copyfile\(DESKTOP_INSTALLER, prepared \/ DESKTOP_INSTALLER\.name\)/);
  assert.match(source, /ram_plan\.validate_inputs\(root, platform, plan_name, plan, INSTALLERS\)/);
  assert.match(source, /sha\(desktop\) != sha\(DESKTOP_INSTALLER\)/);
});
