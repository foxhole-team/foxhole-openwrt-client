'use strict';

function reject() { die('Invalid authenticated bundle transport\n'); };
function exact(value, fields) {
 if (type(value) != 'object' || length(keys(value)) != length(fields)) reject();
 for (let key in keys(value)) if (index(fields, key) < 0) reject();
};
function number(value, maximum) { return type(value) == 'int' && value >= 0 && value <= maximum; };
function hash(value) { return type(value) == 'string' && match(value, /^[a-f0-9]{64}$/); };
export function logical_name(value) {
 return type(value) == 'string' && match(value, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/);
};
export function manifest(raw) {
 if (type(raw) != 'string' || !length(raw) || length(raw) > 1048576) reject();
 let result = {}, folded = {};
 for (let line in split(raw, '\n')) {
  if (line == '') continue;
  let row = match(line, /^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,159})$/);
  if (!row || result[row[2]] || folded[lc(row[2])]) reject();
  result[row[2]] = row[1]; folded[lc(row[2])] = true;
 }
 if (!length(keys(result))) reject();
 return result;
};
export function descriptor(value, sums, member_digest) {
 if (type(member_digest) != 'function') reject();
 exact(value, ['schema', 'archive', 'entries']);
 exact(value.archive, ['file', 'sha256', 'bytes']);
 if (type(value.schema) != 'int' || value.schema != 1 || value.archive.file != 'native-install.tar' ||
     !hash(value.archive.sha256) || sums[value.archive.file] != value.archive.sha256 ||
     !number(value.archive.bytes, 536870912) || value.archive.bytes < 1024 || value.archive.bytes % 512 ||
     type(value.entries) != 'object' || !length(keys(value.entries)) || length(keys(value.entries)) > 1024) reject();
 let members = {}, folded = {}, total = 0, minimum = 1024;
 for (let name in keys(value.entries)) {
  let row = value.entries[name]; exact(row, ['sha256', 'bytes']);
  if (!logical_name(name) || folded[lc(name)] ||
      index(['sha256sums', 'sha256sums.asc', 'bundle-transport.json', 'native-install.tar'], lc(name)) >= 0 ||
      !hash(row.sha256) || sums[name] != row.sha256 || !number(row.bytes, 134217728)) reject();
  folded[lc(name)] = true; total += row.bytes; minimum += 512 + int((row.bytes + 511) / 512) * 512;
  let member = 'f-' + member_digest(name);
  if (members[member]) reject();
  members[member] = {name, ...row};
 }
 if (total > 2147483648 || value.archive.bytes < minimum || value.archive.bytes > minimum + 10240) reject();
 return {archive: value.archive, members, entries: value.entries, totalBytes: total};
};
export function canonical_descriptor(value) {
 let rows = [];
 for (let name in sort(keys(value.entries))) {
  let row = value.entries[name];
  push(rows, '"' + name + '":{"bytes":' + row.bytes + ',"sha256":"' + row.sha256 + '"}');
 }
 return '{"archive":{"bytes":' + value.archive.bytes + ',"file":"native-install.tar","sha256":"' +
  value.archive.sha256 + '"},"entries":{' + join(',', rows) + '},"schema":1}\n';
};
export function zeros(raw) {
 if (type(raw) != 'string') return false;
 for (let i = 0; i < length(raw); i++) if (ord(raw, i) != 0) return false;
 return true;
};
function nulls(count) { let out = ''; for (let i = 0; i < count; i++) out += chr(0); return out; };
export function header(raw, members) {
 if (type(raw) != 'string' || length(raw) != 512) reject();
 let name = substr(raw, 0, 66), row = members[name];
 if (!row || substr(raw, 66, 34) != nulls(34) ||
     substr(raw, 100, 8) != '0000644' + chr(0) ||
     substr(raw, 108, 16) != '0000000' + chr(0) + '0000000' + chr(0) ||
     substr(raw, 124, 12) != sprintf('%011o', row.bytes) + chr(0) ||
     substr(raw, 136, 12) != '00000000000' + chr(0) ||
     (substr(raw, 156, 1) != '0' && ord(raw, 156) != 0) ||
     !zeros(substr(raw, 157, 100)) || substr(raw, 257, 8) != 'ustar' + chr(0) + '00' ||
     !zeros(substr(raw, 265, 64)) ||
     !zeros(substr(raw, 329, 16)) ||
     !zeros(substr(raw, 345, 167))) reject();
 let sum = 0;
 for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : ord(raw, i);
 if (substr(raw, 148, 8) != sprintf('%06o', sum) + chr(0) + ' ') reject();
 return {member: name, ...row};
};
export function selection(raw, value) {
 if (type(raw) != 'string' || length(raw) > 1048576) reject();
 let selected = {}, total = 0;
 for (let line in split(raw, '\n')) {
  if (!length(line)) continue;
  let fields = split(line, ' '), name = fields[1], row = value.entries[name];
  if (!row) continue;
  if (length(fields) != 4 || fields[2] != row.sha256 || !match(fields[3], /^[0-9]{1,10}$/) ||
      int(fields[3]) != row.bytes || selected[name]) reject();
  selected[name] = row; total += row.bytes;
 }
 return {files: selected, totalBytes: total};
};
