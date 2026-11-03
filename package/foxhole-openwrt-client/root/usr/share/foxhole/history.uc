import * as fs from 'fs';
import * as store from './private-store.uc';

export const path = '/tmp/foxhole/history.json';
export const archive = '/etc/foxhole/history.json.gz';
export const preview_path = '/tmp/foxhole/history-preview.json';
export const preview_max_bytes = 240000;
export const preview_max_points = 512;
const MAX = 6000000;
const MONTH = 2592000000;

export function cpu_percent(previous, current) {
	if (!previous || current.total <= previous.total ||
	    current.idle < previous.idle) return null;
	let busy = 100.0 * (1.0 - (current.idle - previous.idle) * 1.0 /
		(current.total - previous.total));
	return +sprintf('%.1f', min(100.0, max(0.0, busy)));
};

export function compact(points, now) {
	let coarse = {}, recent = [], output = [];
	for (let point in points || []) {
		if (type(point?.t) != 'int' || point.t < now - MONTH ||
		    point.t > now + 60000) continue;
		if (point.measurementVersion != 2) point.cpu = null;
		if (point.t >= now - 900000) push(recent, point);
		else coarse['' + int(point.t / 300000)] = point;
	}
	for (let key, value in coarse) push(output, value);
	output = sort([...output, ...recent], (a, b) => a.t - b.t);
	return slice(output, max(0, length(output) - 9000));
};

export function read() {
	let raw = fs.readfile(path, MAX + 1), source = null;
	if (!raw && fs.stat(archive)) {
		try {
			source = fs.popen('gzip -dc ' + archive, 'r');
			raw = source?.read(MAX + 1);
		} catch (_) {}
		try { source?.close(); } catch (_) {}
	}
	if (!raw || length(raw) > MAX) return [];
	try {
		let data = json(raw);
		return type(data) == 'array' ? compact(data, time() * 1000) : [];
	} catch (_) { return []; }
};

export function write(points) {
	let compacted = compact(points, time() * 1000);
	let raw = sprintf('%J', compacted);
	if (length(raw) > MAX) die('history_too_large');
	if (fs.writefile(path + '.new', raw) != length(raw) ||
	    !fs.chmod(path + '.new', 0o600) ||
	    !fs.rename(path + '.new', path)) die('history_write_failed');
	return compacted;
};

export function preview_json(points) {
	if (type(points) != 'array') die('history_preview_invalid');
	let count = min(preview_max_points, length(points));
	while (count > 0) {
		let parts = [], bytes = 2;
		for (let i = 0; i < count; i++) {
			let offset = count == 1 ? 0 : int(i * (length(points) - 1) / (count - 1));
			let part = sprintf('%J', points[offset]);
			bytes += length(part) + (i > 0 ? 1 : 0);
			if (bytes > preview_max_bytes) break;
			push(parts, part);
		}
		if (length(parts) == count) return '[' + join(',', parts) + ']';
		if (count <= 2) break;
		count = max(2, int(count / 2));
	}
	// An unrepresentable endpoint never truncates or replaces the full owner history.
	return '[]';
};

export function write_preview(points) {
	store.write(preview_path, preview_json(points));
};

export function read_preview() {
	try {
		let raw = store.read(preview_path, preview_max_bytes);
		if (!raw) return [];
		let points = json(raw);
		if (type(points) != 'array' || length(points) > preview_max_points) return [];
		let previous = -1;
		for (let point in points) {
			if (type(point) != 'object' || type(point.t) != 'int' || point.t < previous) return [];
			previous = point.t;
		}
		return points;
	} catch (_) { return []; }
};

// Index byte ranges instead of retaining parsed row objects.
export function scan_rows(reader, visit) {
 let state = 0, quoted = false, escaped = false, depth = 0;
 let pending = '', start = -1, offset = 0, rows = 0;
 while (true) {
  let chunk = reader(4096);
  if (chunk == null) die('history_read_failed');
  if (!length(chunk)) break;
  if (offset + length(chunk) > MAX) die('history_too_large');
  let segment = start >= 0 ? 0 : -1;
  for (let i = 0; i < length(chunk); i++) {
   let c = substr(chunk, i, 1);
   if (start >= 0) {
    if (!quoted && depth == 0 && (c == ',' || c == ']')) {
     let raw = pending + substr(chunk, segment, i - segment);
     if (length(raw) > 65536 || ++rows > 18000) die('history_too_large');
     let point = json(raw);
     visit(point, start, length(raw), rows - 1);
     pending = ''; start = -1; segment = -1; state = 2;
    } else {
     if (quoted) {
      if (escaped) escaped = false;
      else if (c == '\\') escaped = true;
      else if (c == '"') quoted = false;
     } else if (c == '"') quoted = true;
     else if (c == '{' || c == '[') depth++;
     else if (c == '}' || c == ']') {
      if (depth <= 0) die('history_invalid');
      depth--;
     }
     continue;
    }
   }
   if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
   if (state == 0) {
    if (c != '[') die('history_invalid');
    state = 1;
   } else if (state == 1 || state == 3) {
    if (c == ']' && state == 1) { state = 4; continue; }
    if (c == ',' || c == ']') die('history_invalid');
    start = offset + i; segment = i;
    quoted = c == '"'; escaped = false;
    depth = c == '{' || c == '[' ? 1 : 0;
   } else if (state == 2) {
    if (c == ',') state = 3;
    else if (c == ']') state = 4;
    else die('history_invalid');
   } else die('history_invalid');
  }
  if (start >= 0) {
   pending += substr(chunk, segment);
   if (length(pending) > 65536) die('history_too_large');
  }
  offset += length(chunk);
 }
 if (state != 4 || start >= 0) die('history_invalid');
 return offset;
};

// Rows written by this sampler use one JSON value per line.
export function scan_rows_fast(reader, visit) {
 let state = 0, rows = 0, offset = 0, pending = '', line_start = 0;
 function line(raw, position) {
  let text = trim(raw);
  if (!length(text)) return;
  position += index(raw, text);
  if (state == 4) die('history_fast_format');
  if (state == 0) {
   if (substr(text, 0, 1) != '[') die('history_fast_format');
   let rest = substr(text, 1); text = trim(rest);
   position += 1 + (length(text) ? index(rest, text) : 0); state = 1;
  }
  if (!length(text)) return;
  let closing = substr(text, -1) == ']';
  if (closing) text = trim(substr(text, 0, length(text) - 1));
  if (!length(text)) {
   if (!closing || (state != 1 && state != 2)) die('history_fast_format');
   state = 4; return;
  }
  if (state == 2) die('history_fast_format');
  let comma = substr(text, -1) == ',';
  if (comma) text = trim(substr(text, 0, length(text) - 1));
  if (!length(text) || closing && comma || length(text) > 65536 || ++rows > 18000)
   die('history_fast_format');
  visit(json(text), position, length(text), rows - 1);
  state = closing ? 4 : comma ? 3 : 2;
 };
 while (true) {
  let chunk = reader(4096);
  if (chunk == null) die('history_read_failed');
  if (!length(chunk)) break;
  offset += length(chunk);
  if (offset > MAX) die('history_too_large');
  let parts = split(chunk, '\n');
  for (let i = 0; i < length(parts) - 1; i++) {
   let raw = pending + parts[i];
   if (length(raw) > 65540) die('history_fast_format');
   line(raw, line_start); line_start += length(raw) + 1; pending = '';
  }
  pending += parts[length(parts) - 1];
  if (length(pending) > 65540) die('history_fast_format');
 }
 line(pending, line_start);
 if (state != 4) die('history_fast_format');
 return offset;
};

export function select_entries(entries, now) {
 let coarse = {}, recent = [], result = [];
 for (let entry in entries) {
  if (entry.t >= now - 900000) push(recent, entry);
  else coarse['' + int(entry.t / 300000)] = entry;
 }
 for (let key, entry in coarse) push(result, entry);
 for (let entry in recent) push(result, entry);
 result = sort(result, (a, b) => a.t - b.t || a.order - b.order);
 return slice(result, max(0, length(result) - 9000));
};

export function stream_index(reader, now, rewind) {
 let entries = [];
 function visit(point, offset, bytes, order) {
  if (type(point?.t) == 'int' && point.t >= now - MONTH && point.t <= now + 60000)
   push(entries, { t: point.t, offset, bytes, order, legacy: point.measurementVersion != 2 });
 };
 if (rewind != null) {
  try { scan_rows_fast(reader, visit); return select_entries(entries, now); }
  catch (_) {
   if (rewind() != true) die('history_read_failed');
   entries = [];
  }
 }
 scan_rows(reader, visit);
 return select_entries(entries, now);
};

function history_identity(info) {
 if (!store.file_metadata(info) || info.size < 1 || info.size > MAX) die('history_read_failed');
 return sprintf('%J', [info.dev?.major, info.dev?.minor, info.inode, info.size, info.mtime, info.ctime, info.mode]);
};

function close_source(context) {
 try { context.source?.close(); } catch (_) {}
 context.source = null;
 if (context.spool) try { fs.unlink(context.spool); } catch (_) {}
};

function history_source() {
 store.target(path);
 let context = { source: null, spool: null, original: null };
 let input = null, output = null;
 try {
  let info = fs.lstat(path);
  if (info) {
   context.original = history_identity(info);
   context.source = fs.open(path, 're');
  } else if (fs.lstat(archive)) {
   store.target(archive);
   let compressed = fs.lstat(archive);
   if (!store.file_metadata(compressed) || compressed.size > MAX) die('history_read_failed');
   context.spool = path + '.restore-' + hexenc(fs.readfile('/dev/urandom', 12));
   output = fs.open(context.spool, 'wxe', 0o600);
   input = fs.popen('gzip -dc ' + archive, 'r');
   if (!output || !input) die('history_read_failed');
   let total = 0;
   while (true) {
    let chunk = input.read(4096);
    if (chunk == null) die('history_read_failed');
    if (!length(chunk)) break;
    total += length(chunk);
    if (total > MAX || output.write(chunk) != length(chunk)) die('history_read_failed');
   }
   let code = input.close(); input = null;
   if (code != 0 || !output.flush()) die('history_read_failed');
   output.close(); output = null;
   context.source = fs.open(context.spool, 're');
  } else return context;
  if (!context.source) die('history_read_failed');
  return context;
 } catch (error) {
  try { input?.close(); } catch (_) {}
  try { output?.close(); } catch (_) {}
  close_source(context); die(error);
 }
};

function entry_raw(context, entry) {
 if (entry.raw != null) return entry.raw;
 if (!context.source || context.source.seek(entry.offset, 0) != true) die('history_read_failed');
 let raw = context.source.read(entry.bytes);
 if (raw == null || length(raw) != entry.bytes) die('history_read_failed');
 if (entry.legacy) { let point = json(raw); point.cpu = null; raw = sprintf('%J', point); }
 return raw;
};

function indexed_preview(context, entries) {
 let count = min(preview_max_points, length(entries));
 while (count > 0) {
  let parts = [], bytes = 2;
  for (let i = 0; i < count; i++) {
   let at = count == 1 ? 0 : int(i * (length(entries) - 1) / (count - 1));
   let raw = entry_raw(context, entries[at]);
   bytes += length(raw) + (i > 0 ? 1 : 0);
   if (bytes > preview_max_bytes) break;
   push(parts, raw);
  }
  if (length(parts) == count) return '[' + join(',', parts) + ']';
  if (count <= 2) break;
  count = max(2, int(count / 2));
 }
 return '[]';
};

export function record(now, force, sample) {
 // Reserve forwarding RAM while another task is under pressure.
 let memory = fs.readfile('/proc/meminfo', 65536) || '';
 let available = match(memory, /(^|\n)MemAvailable:[ \t]+([0-9]+) kB/);
 if (!available || +available[2] < 16384) die('history_memory_low');
 let context = history_source(), file = null, temporary = null;
 try {
  let entries = context.source ? stream_index(n => context.source.read(n), now,
   () => context.source.seek(0, 0)) : [];
  if (!force && length(entries) && now - entries[length(entries) - 1].t < 14000) {
   close_source(context); return false;
  }
  let point = sample();
  if (type(point?.t) != 'int' || point.t != now || point.measurementVersion != 2) die('history_invalid');
  let raw = sprintf('%J', point);
  if (length(raw) > 65536) die('history_too_large');
  push(entries, { t: now, order: 18000, raw });
  entries = select_entries(entries, now);
  temporary = path + '.new-' + hexenc(fs.readfile('/dev/urandom', 12));
  file = fs.open(temporary, 'wxe', 0o600);
  if (!file || file.write('[') != 1) die('history_write_failed');
  let bytes = 2, first = true;
  for (let entry in entries) {
   let data = (first ? '' : ',\n') + entry_raw(context, entry);
   bytes += length(data);
   if (bytes > MAX || file.write(data) != length(data)) die('history_write_failed');
   first = false;
  }
  if (file.write(']') != 1 || !file.flush()) die('history_write_failed');
  file.close(); file = null;
  store.target(path);
  if (context.original != null && history_identity(fs.lstat(path)) != context.original ||
      context.original == null && fs.lstat(path)) die('history_read_failed');
  if (!fs.rename(temporary, path)) die('history_write_failed');
  temporary = null;
  // Preview failure must not discard the persisted full history.
  try { store.write(preview_path, indexed_preview(context, entries)); } catch (_) {}
  close_source(context); return true;
 } catch (error) {
  try { file?.close(); } catch (_) {}
  if (temporary) try { fs.unlink(temporary); } catch (_) {}
  close_source(context); die(error);
 }
};
