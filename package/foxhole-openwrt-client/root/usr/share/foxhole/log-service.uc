'use strict';
import * as fs from 'fs';
import * as registry from './engine-registry.uc';
import * as model from './log-model.uc';
let cached = null, cached_at = 0;
const COLLECTOR_MEMORY_FLOOR_KIB = 32768;
function available_memory() {
 let value = match(fs.readfile('/proc/meminfo', 8192) || '', /(^|\n)MemAvailable:[ \t]+([0-9]+) kB/);
 return value ? +value[2] : null;
};
function collectors_admitted(memory) { return memory != null && memory >= COLLECTOR_MEMORY_FLOOR_KIB; };

function read_json(path) {
 let before = fs.lstat(path), parent = fs.lstat('/tmp/foxhole');
 if (parent?.type != 'directory' || parent.uid != 0 || (parent.mode & 0o077) ||
     before?.type != 'file' || before.uid != 0 || before.nlink != 1 || (before.mode & 0o077) ||
     before.size < 1 || before.size > 8192) return null;
 let raw = fs.readfile(path, 8193), after = fs.lstat(path);
 if (raw == null || length(raw) != before.size || after?.inode != before.inode ||
     after.size != before.size || after.mtime != before.mtime || after.ctime != before.ctime) return null;
 try { return json(raw); } catch (_) { return null; }
};
function source(argv, maximum, parse) {
 if (!collectors_admitted(available_memory())) return { available: false, events: [] };
 try { return { available: true, events: parse(registry.capture(argv, maximum, 1000)) }; }
 catch (_) { return { available: false, events: [] }; }
};
export function status() {
 let now = time();
 if (cached && now >= cached_at && now - cached_at < 3 &&
     collectors_admitted(available_memory()) && collectors_admitted(cached.memAvailableKiB)) return cached;
 let packages = source(['/sbin/logread', '-l', '128', '-e', 'foxhole'], 65536, model.package_events);
 let kernel = source(['/bin/dmesg'], 262144, model.kernel_events);
 let core = model.core_status(read_json('/tmp/foxhole/core-state.json'));
 core.events = filter(packages.events, row => row.engine == 'core');
 core.eventsAvailable = packages.available;
 let memory = available_memory();
 let uptime = match(fs.readfile('/proc/uptime', 128) || '', /^([0-9]+)\.[0-9]+ /);
 cached = { schema: 1, collectedAtUnixMs: now * 1000, memAvailableKiB: memory,
  uptimeSeconds: uptime ? +uptime[1] : null, runtime: model.runtime_status(read_json('/tmp/foxhole/runtime.json')),
  package: packages, core, kernel };
 cached_at = now;
 return cached;
};
