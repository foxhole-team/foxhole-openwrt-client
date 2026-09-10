import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';
import * as inbound from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/inbound.uc';
import * as history from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/history.uc';

function check(value) { if (!value) die('assertion_failed'); };
let state = model.defaults();
state.settings.clientRules = true;
state.activeServerId = 'server-000000000001';
state.servers = [{ id: state.activeServerId, name: 'VPN',
	endpoint: 'vpn.invalid:443', config: 'hy2://sample@vpn.invalid:443/' }];
let client = { id: 'client-000000000001', name: 'MAC',
	secret: join('', map([1,2,3,4,5,6,7,8], _ => 'a1b2c3d4')),
	inbound: true, allowLan: false, port: 14443, deviceType: 'computer' };
let base = { listenerMode: 'per-client', template: {}, allowedLan: ['192.168.1.2/32'],
	public: {}, endpointHost: 'router.invalid' };
let closed = inbound.config(base, state, client, true, ['203.0.113.0/24']);
check(index(closed.acl.inline, 'reject(10.0.0.0/8)') >= 0);
check(index(closed.acl.inline, 'upstream(all)') >= 0);
check(index(closed.acl.inline, 'direct(192.168.1.2/32)') < 0);
client.allowLan = true;
let open = inbound.config(base, state, client, true, []);
check(open.acl.inline[0] == 'direct(192.168.1.2/32)');
let fallback = inbound.config(base, state, client, false, []);
check(fallback.acl.inline[length(fallback.acl.inline)-1] == 'direct(all)');
check(length(fallback.outbounds) == 1);
let profile = inbound.profile(base, client);
check(model.parse_config(profile.uri).endpoint == 'router.invalid:14443');
check(profile.allowLan && profile.provisioned);
base.listenerMode = 'shared';
let shared = inbound.shared_config(base, state, [client], true, []);
check(shared.listen == '0.0.0.0:443');
check(shared.auth.userpass[client.id] == client.secret);
check(index(shared.acl.inline, 'direct(192.168.1.2/32)') < 0);
check(inbound.limit(base) == 32);
check(inbound.profile(base, client).lanAccessConfigurable == false);
check(model.parse_config(inbound.profile(base, client).uri).endpoint == 'router.invalid:443');
let now = 1788868000000;
let rows = history.compact([
	{t: now-2592000001}, {t: now-1000101},
	{t: now-1000100}, {t: now-15000}, {t: now}, {t: now+999999}
], now);
check(length(rows) == 3);
check(rows[length(rows)-1].t == now);
check(history.cpu_percent({total:1000,idle:900}, {total:1200,idle:1090}) == 5.0);
check(history.cpu_percent({total:1000,idle:900}, {total:1000,idle:900}) == null);
check(history.cpu_percent({total:1000,idle:900}, {total:900,idle:800}) == null);
print('Inbound ACL, direct fallback, QR target and history retention: passed.\n');
