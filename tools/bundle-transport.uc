'use strict';
import * as fs from 'fs';
import * as model from './bundle-transport-model.uc';

function reject() { die('Invalid private bundle transport operation\n'); };
function stage(path) {
 if (!match(path || '', /^\/tmp\/foxhole-core-install\.[A-Za-z0-9]{6}$/)) reject();
 let info = fs.lstat(path);
 if (!info || info.type != 'directory' || info.uid != 0 || (info.mode & 07777) != 0700) reject();
 return path;
};
function regular(path, maximum, empty) {
 let info = fs.lstat(path);
 if (!info || info.type != 'file' || info.uid != 0 || info.nlink != 1 ||
     (info.mode & 0022) || info.size > maximum || (!empty && !info.size)) reject();
 return info;
};
function raw(path, maximum) { regular(path, maximum, false); let text = fs.readfile(path, maximum + 1); if (text == null || length(text) > maximum) reject(); return text; };
function hash_stream(root) {
 let path = root + '/.bundle-hash';
 if (fs.lstat(path)) reject();
 let pipe = fs.popen('umask 077; sha256sum > ' + path, 'w');
 if (!pipe) reject();
 return {pipe, path};
};
function finish_hash(value, expected) {
 if (value.pipe.close() != 0) reject();
 let text = raw(value.path, 128);
 if (text != expected + '  -\n' || !fs.unlink(value.path)) reject();
};
function member_digest(name) {
 if (!model.logical_name(name)) reject();
 let output = fs.popen('printf %s ' + name + ' | sha256sum', 'r');
 if (!output) reject();
 let text = output.read(129), status = output.close();
 if (status != 0 || type(text) != 'string' || length(text) != 68 ||
     !match(substr(text, 0, 64), /^[a-f0-9]{64}$/) || substr(text, 64) != '  -\n') reject();
 return substr(text, 0, 64);
};
function settings(root) {
 let sums = model.manifest(raw(root + '/SHA256SUMS', 1048576));
 let text = raw(root + '/bundle-transport.json', 1048576), verifier = hash_stream(root);
 if (verifier.pipe.write(text) != length(text)) reject();
 finish_hash(verifier, sums['bundle-transport.json']);
 let parsed = json(text), value = model.descriptor(parsed, sums, member_digest);
 // Producer canonical bytes also exclude duplicate or escaped JSON object keys.
 if (text != model.canonical_descriptor(parsed)) reject();
 return value;
};
function read_exact(input, bytes) {
 let value = input.read(bytes);
 if (value == null || length(value) != bytes) reject();
 return value;
};
function same_identity(before, after) {
 for (let value in [before, after])
  if (type(value?.dev) != 'object' || type(value.dev.major) != 'int' ||
      type(value.dev.minor) != 'int' || value.dev.major < 0 || value.dev.minor < 0) return false;
 if (before.dev.major != after.dev.major || before.dev.minor != after.dev.minor) return false;
 for (let key in ['inode', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtime', 'ctime'])
  if (before[key] != after[key]) return false;
 return true;
};
function extract(root, value) {
 let archive = root + '/native-install.tar';
 let before = regular(archive, 536870912, false);
 if (before.size != value.archive.bytes) reject();
 let input = fs.open(archive, 're'), outer = hash_stream(root), remaining = before.size;
 if (!input) reject();
 while (remaining) {
  let count = min(65536, remaining), bytes = read_exact(input, count);
  if (outer.pipe.write(bytes) != count) reject(); remaining -= count;
 }
 finish_hash(outer, value.archive.sha256);
 if (input.seek(0, 0) != true) reject();
 let selected = model.selection(raw(root + '/plan.list', 1048576), value), seen = {}, written = [], consumed = 0;
 while (true) {
  if (consumed + 512 > before.size) reject();
  let block = read_exact(input, 512); consumed += 512;
  if (model.zeros(block)) {
   if (consumed + 512 > before.size || !model.zeros(read_exact(input, 512))) reject();
   consumed += 512;
   if (before.size - consumed > 10240 || length(keys(seen)) != length(keys(value.members))) reject();
   while (consumed < before.size) {
    let count = min(65536, before.size - consumed);
    if (!model.zeros(read_exact(input, count))) reject(); consumed += count;
   }
   break;
  }
  let row = model.header(block, value.members);
  if (seen[row.member]) reject(); seen[row.member] = true;
  let output = null, destination = root + '/' + row.name;
  if (selected.files[row.name]) {
   if (fs.lstat(destination)) reject();
   output = fs.open(destination, 'wxe', 0600); if (!output) reject();
  }
  let verifier = hash_stream(root), left = row.bytes;
  while (left) {
   let count = min(65536, left), bytes = read_exact(input, count);
   if (verifier.pipe.write(bytes) != count || (output && output.write(bytes) != count)) reject();
   left -= count; consumed += count;
  }
  finish_hash(verifier, row.sha256);
  if (output) { if (output.flush() != true) reject(); output.close(); regular(destination, row.bytes, row.bytes == 0); push(written, row.name); }
  let padding = (512 - row.bytes % 512) % 512;
  if (padding && !model.zeros(read_exact(input, padding))) reject(); consumed += padding;
 }
 input.close();
 let after = regular(archive, 536870912, false);
 if (!same_identity(before, after)) reject();
 if (length(written) != length(keys(selected.files))) reject();
 let output = fs.open(root + '/bundle-materialized.list', 'wxe', 0600);
 if (!output || output.write(join('\n', written) + '\n') != length(join('\n', written)) + 1 || output.flush() != true) reject();
 output.close();
};
let root = stage(ARGV[1]), value = settings(root);
if (ARGV[0] == 'budget') {
 // This additional conservative transport allowance is not a measured RSS claim.
 printf('%d\n', value.archive.bytes + 16777216 + fs.lstat(root + '/bundle-transport.json').size);
} else if (ARGV[0] == 'bytes') printf('%d\n', value.archive.bytes);
else if (ARGV[0] == 'extract') extract(root, value);
else reject();
