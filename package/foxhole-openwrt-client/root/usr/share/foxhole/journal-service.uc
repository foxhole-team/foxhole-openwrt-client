'use strict';
import * as fs from 'fs';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as registry from './engine-registry.uc';
import * as model from './journal-model.uc';

const JOURNAL_PATH = '/etc/foxhole/log-journal-v1.json';
const JOURNAL_NEXT = '/etc/foxhole/log-journal-v1.next';
const JOURNAL_LOCK = '/etc/foxhole/log-journal-v1.lock';
function fail() { die('journal_unavailable'); };
function identity(value) {
 return sprintf('%J', [value?.type, value?.uid, value?.nlink, value?.mode,
  value?.inode, value?.dev, value?.size, value?.mtime, value?.ctime]);
};
function read_document() {
 let raw = store.read(JOURNAL_PATH, model.max_bytes);
 if (raw != null && !length(raw)) fail();
 return { raw, value: model.normalize(raw == null ? null : json(raw)) };
};
function disk_space() {
 if (sprintf('%J', fs.lstat('/')?.dev) != sprintf('%J', fs.lstat('/etc/foxhole')?.dev)) fail();
 let lines = split(trim(registry.capture(['/bin/df', '-Pk', '/'], 16384, 3000)), '\n');
 let fields = split(trim(lines[length(lines) - 1]), /[ \t]+/);
 if (length(fields) < 6 || !match(fields[1], /^[0-9]+$/) || !match(fields[3], /^[0-9]+$/)) fail();
 return { total: +fields[1] * 1024, available: +fields[3] * 1024 };
};
function cleanup_next() {
 store.target(JOURNAL_NEXT);
 let info = fs.lstat(JOURNAL_NEXT);
 if (info && (!store.file_metadata(info) || info.size > model.max_bytes ||
     identity(info) != identity(fs.lstat(JOURNAL_NEXT)) || !fs.unlink(JOURNAL_NEXT))) fail();
};
function write_document(raw, before) {
 if (length(raw) > model.max_bytes) fail();
 let file = fs.open(JOURNAL_NEXT, 'wxe', 0o600);
 if (!file) fail();
 let complete = false;
 try {
  if (file.write(raw) != length(raw) || !file.flush()) fail();
  file.close(); file = null;
  store.target(JOURNAL_PATH);
  if (identity(before) != identity(fs.lstat(JOURNAL_PATH)) || !fs.rename(JOURNAL_NEXT, JOURNAL_PATH)) fail();
  complete = true;
 } catch (_) { if (file) try { file.close(); } catch (_) {} }
 if (!complete) { cleanup_next(); fail(); }
};

export function status(snapshot, storage, before) {
 let result = { schema: 2, storage, available: false, reason: null, snapshot,
  retentionSeconds: 2592000, sharePercent: 2, limitBytes: 0, reserveBytes: 0,
  totalRecords: 0, droppedRecords: 0, entries: [], hasMore: false, beforeSequence: 0 };
 if (storage == 'RAM') { result.reason = 'RAM_DISABLED'; return result; }
 if (storage != 'FLASH') fail();
 if (snapshot.memAvailableKiB == null || snapshot.memAvailableKiB < 24576) {
  result.reason = 'LOW_MEMORY'; return result;
 }
 store.target(JOURNAL_LOCK);
 let lock = fs.open(JOURNAL_LOCK, 'a+', 0o600);
 if (!lock || !store.file_metadata(fs.lstat(JOURNAL_LOCK))) fail();
 if (!lock.lock('xn')) { lock.close(); result.reason = 'BUSY'; return result; }
 let run = () => {
  let document = read_document(), current = document.value;
  if (!before && snapshot.memAvailableKiB >= 32768) {
   cleanup_next();
   let boot = trim(fs.readfile('/proc/sys/kernel/random/boot_id', 128) || '');
   let space = disk_space(), info = fs.lstat(JOURNAL_PATH);
   let quota = model.budget(space.total, space.available, info?.size || 0);
   result.limitBytes = quota.limitBytes; result.reserveBytes = quota.reserveBytes;
   current = model.bounded(model.merge(current, snapshot, snapshot.collectedAtUnixMs, boot, digest.sha256), quota.limitBytes);
   let raw = sprintf('%J', current);
   if (raw != document.raw) {
    // Reclaim only this journal when an atomic replacement needs its
    // old allocation.
    if (space.available - length(raw) < quota.reserveBytes && info != null) {
     if (identity(info) != identity(fs.lstat(JOURNAL_PATH)) || !fs.unlink(JOURNAL_PATH)) fail();
     info = null; space = disk_space();
     if (space.available - length(raw) < quota.reserveBytes) fail();
    }
    write_document(raw, info);
   }
  }
  let page = model.page(current, before, 128);
  result.available = true;
  result.entries = map(page.entries, row => ({ sequence: row.sequence,
   observedAtUnixMs: row.observedAtUnixMs, source: row.source, event: row.event }));
  result.hasMore = page.hasMore; result.beforeSequence = page.beforeSequence;
  result.totalRecords = length(current.records); result.droppedRecords = current.droppedRecords;
  if (!result.limitBytes) result.limitBytes = fs.lstat(JOURNAL_PATH)?.size || 0;
  return result;
 };
 let completed = null;
 try { completed = run(); } catch (_) { lock.lock('u'); lock.close(); fail(); }
 lock.lock('u'); lock.close();
 return completed;
};
