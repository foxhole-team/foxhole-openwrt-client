'use strict';

import * as digest from 'digest';

export function enabled(state) {
 return state?.settings?.vpnServerEnabled == true;
};
export function require_enabled(state) {
 if (!enabled(state)) die('vpn_server_disabled');
};
export function settings(current, requested) {
 if (type(requested) != 'object') die('invalid_settings');
 if (requested.vpnServerEnabled != null &&
     requested.vpnServerEnabled != enabled(current))
  die('vpn_server_confirmation_required');
 return enabled(current);
};
function component(value) {
 if (value?.schema != 1 || value.protocol != 'hysteria2' ||
     (value.kind != 'verified-legacy-server' && value.kind != 'verified-managed-server') ||
     type(value.version) != 'string' ||
     !match(value.version, /^[0-9]+\.[0-9]+\.[0-9]+$/) ||
     !match(value.binarySha256 || '', /^[a-f0-9]{64}$/) ||
     type(value.binaryBytes) != 'int' || value.binaryBytes < 1 ||
     value.binaryBytes > 134217728) return null;
 return { protocol: value.protocol, kind: value.kind,
  version: value.version, binarySha256: value.binarySha256,
  binaryBytes: value.binaryBytes };
};
export function plan(state, fact) {
 let verified = component(fact);
 let value = { schema: 1, revision: state.revision,
  enabled: enabled(state), available: verified != null,
  action: verified ? 'reuse' : 'unavailable',
  downloadBytes: verified ? 0 : null, component: verified,
  reason: verified ? null : 'vpn_server_unavailable' };
 return { ...value, planSha256: digest.sha256(sprintf('%J', value)) };
};
export function change(state, args, fact) {
 if (type(args.enabled) != 'bool') die('invalid_settings');
 if (type(args.revision) != 'int' || args.revision != state.revision) die('revision_conflict');
 if (args.enabled) {
  let current = plan(state, fact);
  if (!current.available) die('vpn_server_unavailable');
  if (type(args.confirmed) != 'bool' || args.confirmed != true || args.planSha256 != current.planSha256)
   die('vpn_server_confirmation_required');
 }
 let next = json(sprintf('%J', state));
 if (enabled(state) != args.enabled) next.revision++;
 next.settings.vpnServerEnabled = args.enabled;
 return next;
};
