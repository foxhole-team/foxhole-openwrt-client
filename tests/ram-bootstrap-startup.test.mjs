import assert from 'node:assert/strict';
import test from 'node:test';
import { functionBody, read } from './helpers.mjs';

async function fixture() {
  const body = functionBody(await read('tools/ram-bootstrap.uc'), 'start')
    .replace(/for\(let unit in /g, 'for(let unit of ');
  const commands = [], writes = [];
  const start = new Function('command', 'replace', 'model',
    `return function(journal) ${body};`)(
    args => commands.push(args),
    (...args) => writes.push(args),
    { stage: '/tmp/foxhole-startup-fixture' },
  );
  const journal = { phase: 'ACTIVATED' };
  start(journal);
  return { commands, writes, journal };
}

test('RAM activation reloads the web RPC and firewall before starting VPN', async () => {
  const { commands } = await fixture();
  const vpn = commands.findIndex(args => args[0] === '/etc/init.d/foxhole-runtime');
  for (const [unit, operation] of [['rpcd', 'restart'], ['uhttpd', 'restart'], ['firewall', 'reload']]) {
    const position = commands.findIndex(args => args[0] === `/etc/init.d/${unit}` && args[1] === operation);
    assert.ok(position >= 0 && position < vpn, `${unit} must reload before VPN starts`);
  }
});

test('bootstrap starts saved services without choosing a profile', async () => {
  const { commands, journal, writes } = await fixture();
  assert.equal(journal.starting, true);
  assert.equal(writes.length, 1);
  assert.ok(commands.some(args => args[0] === '/etc/init.d/foxhole-mobile' && args[1] === 'start'));
  assert.ok(commands.every(args => args.length === 2));
  assert.ok(!Object.hasOwn(journal, 'activeServerId'));
});
