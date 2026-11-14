'use strict';

export const max_bytes = 1048576;
export const max_records = 2048;
export const retention_ms = 2592000000;
const processes = ['foxhole-history', 'hysteria', 'foxcore-cli', 'ucode', 'rpcd', 'uhttpd', 'logd', 'ubusd', 'apk', 'dnsmasq', 'other'];
function fail() { die('invalid_journal'); };
function integer(value) { return type(value) == 'int' && value >= 0 && value <= 9007199254740991; };
function hash_id(value) { return type(value) == 'string' && match(value, /^[a-f0-9]{64}$/) != null; };
function boot_id(value) { return type(value) == 'string' && match(value, /^[a-f0-9-]{36}$/) != null; };

export function budget(total, available, used) {
 if (!integer(total) || !integer(available) || !integer(used) || available > total || used > max_bytes) fail();
 let pool = min(total, available + used), reserve = min(total, max(1048576, int(total / 10)));
 return { limitBytes: min(max_bytes, int(pool * 0.02), max(0, pool - reserve)), reserveBytes: reserve, sharePercent: 2 };
};

function event_copy(source, value) {
 if (type(value) != 'object') fail();
 if (source == 'package') {
  if (value.event != 'tunnel_exited' || index(['core', 'hysteria', 'unknown'], value.engine) < 0 ||
      !integer(value.exitStatus) || value.exitStatus > 255 ||
      value.time != null && (type(value.time) != 'string' || !match(value.time, /^[A-Za-z0-9 :]{1,32}$/))) fail();
  return { event: value.event, time: value.time, engine: value.engine, exitStatus: value.exitStatus };
 }
 if (source != 'kernel' || index(['oom_killed', 'oom_selected', 'oom_invoked'], value.event) < 0 ||
     index(processes, value.process) < 0 || index(['int', 'double'], type(value.uptimeSeconds)) < 0 ||
     value.uptimeSeconds < 0 || value.uptimeSeconds > 9007199254 ||
     value.pid != null && (!integer(value.pid) || value.pid > 9999999)) fail();
 return { event: value.event, uptimeSeconds: value.uptimeSeconds, pid: value.pid, process: value.process };
};

export function empty() {
 return { schema: 1, kind: 'foxhole-journal-v1', nextSequence: 1, updatedAtUnixMs: 0,
  droppedRecords: 0, seen: { package: [], kernel: [] }, records: [] };
};

export function normalize(value) {
 if (value == null) return empty();
 if (value.schema != 1 || value.kind != 'foxhole-journal-v1' ||
     !integer(value.nextSequence) || value.nextSequence < 1 || !integer(value.updatedAtUnixMs) ||
     !integer(value.droppedRecords) || type(value.records) != 'array' || length(value.records) > max_records) fail();
 let result = empty(), previous = 0;
 result.nextSequence = value.nextSequence; result.updatedAtUnixMs = value.updatedAtUnixMs;
 result.droppedRecords = value.droppedRecords;
 for (let i = 0; i < 2; i++) {
  let source = i == 0 ? 'package' : 'kernel', ids = value.seen?.[source];
  if (type(ids) != 'array' || length(ids) > 32) fail();
  for (let j = 0; j < length(ids); j++) { if (!hash_id(ids[j])) fail(); push(result.seen[source], ids[j]); }
 }
 for (let i = 0; i < length(value.records); i++) {
  let row = value.records[i];
  if (!integer(row.sequence) || row.sequence <= previous || row.sequence >= value.nextSequence ||
      !integer(row.observedAtUnixMs) || !boot_id(row.bootId) || !hash_id(row.id)) fail();
  push(result.records, { sequence: row.sequence, observedAtUnixMs: row.observedAtUnixMs,
   bootId: row.bootId, id: row.id, source: row.source, event: event_copy(row.source, row.event) });
  previous = row.sequence;
 }
 return result;
};

export function merge(value, snapshot, now, boot, hash) {
 let result = normalize(value);
 if (!integer(now) || !boot_id(boot)) fail();
 let retained = filter(result.records, row => row.observedAtUnixMs >= now - retention_ms && row.observedAtUnixMs <= now + 60000);
 let changed = length(retained) != length(result.records);
 result.records = retained;
 for (let i = 0; i < 2; i++) {
  let source = i == 0 ? 'package' : 'kernel', current = snapshot[source];
  if (type(current?.available) != 'bool' || type(current.events) != 'array' || length(current.events) > 32) fail();
  if (!current.available) continue;
  let seen = [], before = result.seen[source];
  for (let j = 0; j < length(current.events); j++) {
   let event = event_copy(source, current.events[j]), id = hash(sprintf('%J', [boot, source, event]));
   if (!hash_id(id)) fail();
   if (index(seen, id) < 0) push(seen, id);
   if (index(before, id) >= 0 || length(filter(result.records, row => row.id == id))) continue;
   if (result.nextSequence >= 9007199254740991) fail();
   push(result.records, { sequence: result.nextSequence++, observedAtUnixMs: now,
    bootId: boot, id, source, event });
   changed = true;
  }
  if (sprintf('%J', seen) != sprintf('%J', before)) changed = true;
  result.seen[source] = seen;
 }
 if (changed) result.updatedAtUnixMs = now;
 return result;
};

export function bounded(value, limit) {
 if (!integer(limit) || limit > max_bytes) fail();
 let records = value.records, base = max(0, length(records) - max_records);
 function candidate(start) { return { ...value, records: slice(records, start), droppedRecords: value.droppedRecords + start }; };
 let lowest = base, highest = length(records);
 if (length(sprintf('%J', candidate(highest))) > limit) die('journal_no_space');
 while (lowest < highest) {
  let middle = int((lowest + highest) / 2);
  if (length(sprintf('%J', candidate(middle))) > limit) lowest = middle + 1;
  else highest = middle;
 }
 return candidate(lowest);
};

export function page(value, before, count) {
 let current = normalize(value);
 if (!integer(before) || !integer(count) || count < 1 || count > 128) fail();
 let entries = [], more = false;
 for (let i = length(current.records) - 1; i >= 0; i--) {
  let row = current.records[i];
  if (before && row.sequence >= before) continue;
  if (length(entries) >= count) { more = true; break; }
  push(entries, row);
 }
 return { entries, hasMore: more, beforeSequence: length(entries) ? entries[length(entries) - 1].sequence : 0 };
};
