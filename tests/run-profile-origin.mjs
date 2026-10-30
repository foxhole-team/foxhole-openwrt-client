import { spawnSync } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { functionBody, read, root, rpcPath } from './helpers.mjs';

const container = process.env.FOXHOLE_TEST_CONTAINER || 'foxhole-public-model-check';
function execute(args, input) {
  const result = spawnSync('docker', args, {
    input, encoding: 'utf8', timeout: 30000, maxBuffer: 1048576,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0) throw new Error('Profile-origin ucode check failed');
  return result.stdout;
}
const mounts = JSON.parse(execute(['inspect', '--format', '{{json .Mounts}}', container]));
const mount = mounts.find(item => item.Destination === '/workspace');
if (!mount || mount.RW || await realpath(mount.Source) !== await realpath(root))
  throw new Error('Profile-origin check requires this exact source mounted read-only');
const rpc = await read(rpcPath);
execute(['exec', '-i', container, 'ucode', '-cdynlink=uci,dynlink=ubus', '-o', '/dev/null', '-'],
  rpc.replaceAll("'/usr/share/foxhole/", "'/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/"));
const body = functionBody(rpc, 'profile_app_metadata');
execute(['exec', '-i', container, 'ucode', '-'], String.raw`
import * as digest from 'digest';
function profile_app_metadata(paired, client_id, uri) ${body};
function truth(value) { if (!value) die('assertion_failed'); };
let pair = { id: 'pair-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' };
let client = 'client-123456abcdef', uri = 'hy2://fixture@router.invalid:443/#Phone';
let data = profile_app_metadata(pair, client, uri);
truth(data.schema == 1 && data.kind == 'foxhole-openwrt-client');
truth(data.pairingId == pair.id && data.clientId == client);
truth(data.uriSha256 == digest.sha256(uri));
truth(length(keys(data)) == 5 && length(sprintf('%J', data)) <= 256);
truth(profile_app_metadata(null, client, uri) == null);
truth(profile_app_metadata({ id: 'pair-foreign' }, client, uri) == null);
truth(profile_app_metadata({ id: pair.id + chr(0) + 'foreign' }, client, uri) == null);
truth(profile_app_metadata(pair, 'server-123456abcdef', uri) == null);
truth(profile_app_metadata(pair, client + chr(0) + 'foreign', uri) == null);
truth(profile_app_metadata(pair, client, '') == null);
truth(profile_app_metadata(pair, client, uri + chr(0)) == null);
truth(profile_app_metadata(pair, client, uri + chr(10)) == null);
truth(profile_app_metadata(pair, client, uri + chr(127)) == null);
truth(profile_app_metadata(pair, client, uri + 'changed').uriSha256 != data.uriSha256);
print('profile-origin native ucode assertions passed\n');
`);
