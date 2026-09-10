'use strict';
'require rpc';
'require view';

const parameters = {
	unlock: ['pin'],
	lock: ['token'],
	state: ['token'],
	telemetry: ['token'],
	settings: ['token', 'revision', 'settings', 'countries', 'devices', 'sites'],
	'server.test': ['token', 'config'],
	'server.save': ['token', 'revision', 'config', 'id', 'name'],
	'server.get': ['token', 'id'],
	'server.start': ['token', 'revision', 'id'],
	'server.stop': ['token', 'revision'],
	'server.delete': ['token', 'revision', 'id'],
	'client.save': ['token', 'revision', 'name', 'deviceType', 'serverId'],
	'client.update': ['token', 'revision', 'id', 'name'],
	'client.access': ['token', 'revision', 'id', 'allowLan'],
	'client.get': ['token', 'id'],
	'client.delete': ['token', 'revision', 'id'],
	'pin.change': ['token', 'newPin'],
	'device.resolve': ['token', 'address'],
	'device.list': ['token']
};

const methods = Object.fromEntries(Object.entries(parameters).map(
	([method, params]) => [method, rpc.declare({
		object: 'foxhole', method, params, reject: true
	})]));

const allowed = new Set(Object.keys(methods));

function errorCode(error) {
	if (error && typeof error === 'object' && error.code)
		return String(error.code).slice(0, 48);
	return 'unavailable';
}

function resultError(result) {
	return result && typeof result === 'object' && result._foxhole_error
		? String(result._foxhole_error).slice(0, 48) : null;
}

function validMessage(message) {
	if (!message || typeof message !== 'object' ||
		message.source !== 'foxhole-panel' || typeof message.id !== 'string' ||
		message.id.length > 128 || !allowed.has(message.action)) return false;
	if (message.payload != null &&
		(typeof message.payload !== 'object' || Array.isArray(message.payload)))
		return false;
	try {
		return JSON.stringify(message.payload || {}).length <= 300000;
	} catch (_) {
		return false;
	}
}

return view.extend({
	load: function() {
		return Promise.resolve();
	},

	render: function() {
		const frame = E('iframe', {
			'class': 'foxhole-luci-frame',
			'src': L.resource('foxhole/shell.html'),
			'title': 'FoxHole OpenWRT Client',
			'referrerpolicy': 'no-referrer',
			'loading': 'eager',
			'allow': 'clipboard-write'
		});
		const host = E('div', { 'class': 'foxhole-luci-host' }, [frame]);
		const style = E('style', {}, [
			'.foxhole-luci-host{width:100%;min-height:720px;margin:0}',
			'.foxhole-luci-frame{display:block;width:100%;min-height:720px;',
			'height:calc(100vh - 112px);border:0;background:#080808}',
			'@media(max-width:700px){.foxhole-luci-host{min-height:640px}',
			'.foxhole-luci-frame{min-height:640px;height:calc(100vh - 64px)}}'
		]);
		if (!document.getElementById('foxhole-luci-style')) {
			style.id = 'foxhole-luci-style';
			document.head.appendChild(style);
		}

		const relay = async (event) => {
			if (event.origin !== window.location.origin ||
				event.source !== frame.contentWindow || !validMessage(event.data)) return;
			const message = event.data;
			let response;
			try {
				const payload = message.payload || {};
				const values = parameters[message.action].map(key => payload[key]);
				const result = await methods[message.action](...values);
				const code = resultError(result);
				response = code
					? { source: 'foxhole-host', id: message.id, error: { code } }
					: { source: 'foxhole-host', id: message.id, result: result || {} };
			} catch (error) {
				response = {
					source: 'foxhole-host', id: message.id,
					error: { code: errorCode(error) }
				};
			}
			frame.contentWindow.postMessage(response, window.location.origin);
		};

		window.addEventListener('message', relay);
		this._foxholeRelay = relay;
		this._foxholeFrame = frame;
		return host;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	remove: function() {
		if (this._foxholeRelay)
			window.removeEventListener('message', this._foxholeRelay);
		if (this._foxholeFrame && this._foxholeFrame.contentWindow)
			this._foxholeFrame.contentWindow.postMessage({
				source: 'foxhole-host', id: 'foxhole-close', result: {}
			}, window.location.origin);
	}
});
