'use strict';

import * as fs from 'fs';
import * as store from './private-store.uc';

const PATH = '/tmp/foxhole/pin-attempts.json';
const MAX_TIME = 9007199254440991;

function clock_valid(now, boot) {
 if (type(now) != 'int' || now < 0 || now > MAX_TIME ||
     type(boot) != 'string' || !match(boot, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/))
  die('storage_error');
};

export function initial(now, boot) {
 clock_valid(now, boot);
 return { schema: 1, bootId: boot, failures: 0, tier: 0,
  blockedUntilUptimeMs: 0, lastUptimeMs: now };
};

export function checked(value, now, boot) {
 clock_valid(now, boot);
 if (value == null) return initial(now, boot);
 if (type(value) != 'object' || value.schema != 1 ||
     type(value.bootId) != 'string' || !match(value.bootId, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/) ||
     type(value.failures) != 'int' || value.failures < 0 || value.failures > 5 ||
     type(value.tier) != 'int' || value.tier < 0 || value.tier > 2 ||
     type(value.lastUptimeMs) != 'int' || value.lastUptimeMs < 0 || value.lastUptimeMs > MAX_TIME ||
     type(value.blockedUntilUptimeMs) != 'int' || value.blockedUntilUptimeMs < 0 ||
     value.blockedUntilUptimeMs > value.lastUptimeMs + 300000 ||
     (value.tier == 0 && value.blockedUntilUptimeMs != 0)) die('storage_error');
 for (let key in keys(value))
  if (index(['schema', 'bootId', 'failures', 'tier', 'blockedUntilUptimeMs', 'lastUptimeMs'], key) < 0)
   die('storage_error');
 if (value.bootId != boot) return initial(now, boot);
 if (now < value.lastUptimeMs) die('storage_error');
 return { ...value, lastUptimeMs: now };
};

export function remaining(value, now) {
 let delta = value.blockedUntilUptimeMs - now;
 return delta > 0 ? int((delta + 999) / 1000) : 0;
};

export function failed(value, now, boot) {
 let result = checked(value, now, boot);
 if (remaining(result, now)) return result;
 result.failures++;
 if (result.failures == 6) {
  result.failures = 0;
  result.tier = result.tier == 0 ? 1 : 2;
  result.blockedUntilUptimeMs = now + (result.tier == 1 ? 60000 : 300000);
 }
 return result;
};

export function clock() {
 let uptime = fs.readfile('/proc/uptime', 256);
 let boot = trim(fs.readfile('/proc/sys/kernel/random/boot_id', 128) || '');
 if (!match(uptime || '', /^[0-9]+\.[0-9]+ /)) die('storage_error');
 let now = int(+split(uptime, ' ')[0] * 1000);
 clock_valid(now, boot);
 return { now, boot };
};

function metadata() {
 let parent = store.directory('/tmp/foxhole');
 if (parent.gid != 0 || (parent.mode & 0o777) != 0o700) die('storage_error');
 let info = fs.lstat(PATH);
 if (info && (!store.file_metadata(info) || info.gid != 0 || (info.mode & 0o777) != 0o600 ||
     info.size < 1 || info.size > 1024)) die('storage_error');
 return info;
};

// Callers hold the shared state lock through comparison and record replacement.
export function load(stamp) {
 let before = metadata(), raw = store.read(PATH, 1024), after = metadata();
 if ((before == null) != (after == null) ||
     (before && (before.inode != after.inode || before.size != after.size))) die('storage_error');
 let value = null;
 if (raw != null) try { value = json(raw); } catch (_) { die('storage_error'); }
 return checked(value, stamp.now, stamp.boot);
};

export function write(value) {
 metadata();
 store.write(PATH, sprintf('%J', value));
 metadata();
};

export function reset() {
 let stamp = clock();
 write(initial(stamp.now, stamp.boot));
};
