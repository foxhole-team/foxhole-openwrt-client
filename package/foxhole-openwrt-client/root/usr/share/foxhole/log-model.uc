'use strict';
const processes = ['foxhole-history', 'hysteria', 'foxcore-cli', 'ucode', 'rpcd', 'uhttpd', 'logd', 'ubusd', 'apk', 'dnsmasq'];
const protocols = ['anytls', 'http', 'hysteria2', 'naive', 'shadowsocks', 'shadowtls', 'socks', 'trojan', 'tuic', 'vless', 'vmess', 'wireguard'];
const runtime_errors = ['storage_error', 'invalid_state', 'server_not_found', 'client_rules_unsupported',
 'site_pattern_unsupported', 'invalid_interface', 'invalid_dns_uid', 'runtime_missing', 'resolve_failed',
 'country_fetch_failed', 'country_data_invalid', 'country_data_too_large', 'dnsmasq_nftset_required',
 'policy_invalid', 'policy_apply_failed', 'route_apply_failed', 'dnsmasq_apply_failed', 'tunnel_missing',
 'tunnel_start_failed', 'tunnel_exited', 'runtime_stopped'];
function bounded(raw, maximum) {
 if (type(raw) != 'string' || length(raw) > maximum) die('invalid_log_data');
 return split(raw, '\n');
};
function append(rows, value) {
 push(rows, value);
 if (length(rows) > 32) shift(rows);
};
function process_name(value) { return index(processes, value) >= 0 ? value : 'other'; };
export function package_events(raw) {
 let lines = bounded(raw, 65536), rows = [];
 for (let i = 0; i < length(lines); i++) {
  let line = lines[i];
  if (length(line) > 2048) continue;
  let event = match(line, / foxhole: tunnel_exited engine=(core|hysteria|unknown) stage=running exit_status=([0-9]{1,3})$/);
  if (!event || +event[2] > 255) continue;
  let stamp = match(line, /^([A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}) /);
  append(rows, { event: 'tunnel_exited', time: stamp ? stamp[1] : null, engine: event[1], exitStatus: +event[2] });
 }
 return rows;
};
export function kernel_events(raw) {
 let lines = bounded(raw, 262144), rows = [];
 for (let i = max(0, length(lines) - 256); i < length(lines); i++) {
  let line = lines[i];
  if (length(line) > 2048) continue;
  let stamp = match(line, /^\[[ \t]*([0-9]{1,10}\.[0-9]{1,6})\]/);
  if (!stamp) continue;
  let killed = match(line, /Killed process ([0-9]{1,7}) \(([^)]{1,32})\)/);
  let selected = match(line, /task=([A-Za-z0-9_.-]{1,32}),pid=([0-9]{1,7})(,|$)/);
  let invoked = match(line, /\] ([A-Za-z0-9_.-]{1,32}) invoked oom-killer:/);
  if (killed) append(rows, { event: 'oom_killed', uptimeSeconds: +stamp[1], pid: +killed[1], process: process_name(killed[2]) });
  else if (selected) append(rows, { event: 'oom_selected', uptimeSeconds: +stamp[1], pid: +selected[2], process: process_name(selected[1]) });
  else if (invoked) append(rows, { event: 'oom_invoked', uptimeSeconds: +stamp[1], pid: null, process: process_name(invoked[1]) });
 }
 return rows;
};
function counter(value) { return type(value) == 'int' && value >= 0 && value <= 9007199254740991 ? value : null; };
export function core_status(value) {
 if (type(value?.schema_version) != 'int' || value.schema_version != 1 || index(['running', 'stopped'], value.phase) < 0) return { available: false };
 return { available: true, phase: value.phase, protocol: index(protocols, value.protocol) >= 0 ? value.protocol : null,
  bytesUp: counter(value.bytes_up), bytesDown: counter(value.bytes_down) };
};
export function runtime_status(value) {
 return { phase: index(['connecting', 'connected', 'blocked', 'disconnected', 'error'], value?.phase) >= 0 ? value.phase : null,
  error: index(runtime_errors, value?.error) >= 0 ? value.error : null,
  connected: value?.connected == true, enforced: value?.enforced == true };
};
