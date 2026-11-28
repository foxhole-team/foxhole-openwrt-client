'use strict';
'require rpc';
'require view';
'require foxhole.loader as pixelLoader';

const parameters = {
 'vpnServer.plan': ['token'],
 'vpnServer.job': ['token', 'jobId'],
 'vpnServer.set': ['token', 'revision', 'enabled', 'confirmed', 'planSha256', 'removeComponent'],
  'package.status': [],
  'diagnostics.logs': ['token'],
  'diagnostics.journal': ['token', 'beforeSequence'],
  'backup.export': ['token'],
  'backup.validate': ['token', 'document', 'expectedRevision'],
  'backup.apply': ['token', 'document', 'expectedRevision', 'confirmed', 'requestId'],
  'backup.status': ['token'],
	'updates.status': ['token'],
	'updates.check': ['token', 'expectedRevision'],
	'updates.plan': ['token', 'expectedRevision'],
	'updates.apply': ['token', 'planId', 'planSha256', 'expectedRevision', 'confirmed'],
	'updates.job': ['token', 'jobId'],
	'updates.settings': ['token', 'expectedRevision', 'autoUpdateEnabled'],
	'updates.deviceBegin': ['token', 'cohortKind', 'assetId', 'uploadId', 'expectedRevision', 'requestId', 'releaseTag', 'version', 'fileSha256', 'fileBytes'],
	'updates.deviceChunk': ['token', 'cohortKind', 'assetId', 'uploadId', 'offset', 'dataBase64', 'chunkSha256'],
	'updates.deviceStatus': ['token', 'cohortKind', 'assetId', 'uploadId'],
	'updates.deviceFinish': ['token', 'cohortKind', 'assetId', 'uploadId'],
	'engines.status': ['token'],
	'engines.plan': ['token', 'operation', 'engineIds', 'storage', 'expectedRevision', 'catalogSha256'],
	'engines.apply': ['token', 'planId', 'planSha256', 'expectedRevision', 'confirmed'],
	'engines.job': ['token', 'jobId'],
	unlock: ['pin'],
	lock: ['token'],
	state: ['token'],
	'pair.list': ['token'],
	'pair.revoke': ['token', 'id'],
	telemetry: ['token'],
	settings: ['token', 'revision', 'settings', 'countries', 'devices', 'sites'],
	'routing.test': ['token', 'revision', 'settings', 'countries', 'devices', 'sites'],
	'server.test': ['token', 'config', 'engine', 'reachability'],
	'server.save': ['token', 'revision', 'config', 'id', 'name', 'engine', 'subscription'],
	'server.get': ['token', 'id'],
	'server.start': ['token', 'revision', 'id'],
	'server.stop': ['token', 'revision'],
	'server.delete': ['token', 'revision', 'id'],
	'client.save': ['token', 'revision', 'name', 'deviceType', 'serverId'],
	'client.update': ['token', 'revision', 'id', 'name'],
	'client.access': ['token', 'revision', 'id', 'allowLan'],
	'client.get': ['token', 'id'],
	'client.delete': ['token', 'revision', 'id'],
	'pin.change': ['token', 'newPin', 'licenseAccepted', 'licenseVersion', 'initialAutoUpdateEnabled'],
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

function panelMetadata() {
	const title = document.title, changes = [];
	document.title = 'FOXHOLE OPENWRT';
	for (const [tag, selector, attributes] of [
		['meta', 'meta[name="application-name"]', { name: 'application-name', content: 'FOXHOLE OPENWRT' }],
		['meta', 'meta[name="apple-mobile-web-app-title"]', { name: 'apple-mobile-web-app-title', content: 'FOXHOLE OPENWRT' }],
		['link', 'link[rel="icon"]', { rel: 'icon', href: L.resource('foxhole/assets/foxhole-32.png'), type: 'image/png', sizes: '32x32' }],
		['link', 'link[rel="apple-touch-icon"]', { rel: 'apple-touch-icon', href: L.resource('foxhole/assets/foxhole-180.png'), sizes: '180x180' }],
		['link', 'link[rel="manifest"]', { rel: 'manifest', href: L.resource('foxhole/manifest.json') + '?v=1.0.20-r1-ui23' }]
	]) {
		const existing = document.querySelector(selector);
		const node = existing || document.createElement(tag);
		const before = Object.fromEntries(Object.keys(attributes).map(key => [key, node.getAttribute(key)]));
		for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
		if (!existing) document.head.appendChild(node);
		changes.push(() => {
			if (!existing) { node.remove(); return; }
			for (const [key, value] of Object.entries(before)) {
				if (value == null) node.removeAttribute(key);
				else node.setAttribute(key, value);
			}
		});
	}
	return () => {
		if (document.title === 'FOXHOLE OPENWRT') document.title = title;
		changes.forEach(restore => restore());
	};
}

return view.extend({
	load: function() {
		pixelLoader.mount(_('Loading data'));
		return new Promise(resolve => setTimeout(resolve, 600));
	},

	render: function() {
		this._foxholeRestoreMetadata = panelMetadata();
		const frame = E('iframe', {
			'class': 'foxhole-luci-frame',
			'src': L.resource('foxhole/shell.html') + '?v=1.0.20-r1-ui23',
			'title': 'FOXHOLE OPENWRT',
			'referrerpolicy': 'no-referrer',
			'loading': 'eager',
			'allow': 'clipboard-write'
		});
		const host = E('div', { 'class': 'foxhole-luci-host' }, [frame]);
		const style = E('style', {}, [
			'.foxhole-luci-host{width:100%;min-height:720px;margin:0}',
			'.foxhole-luci-frame{display:block;width:100%;min-height:720px;',
			'height:calc(100vh - 112px);border:0;background:#080808}',
			'@media(max-width:720px){.foxhole-luci-host{width:100vw;max-width:none;',
			'min-height:0;margin-inline:calc(50% - 50vw)}',
			'.foxhole-luci-frame{min-height:0;height:calc(100dvh - 64px)}}'
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
					? { source: 'foxhole-host', id: message.id, error: { code,
						...(code === 'pin_cooldown' && Number.isInteger(result.retryAfterSeconds) && result.retryAfterSeconds >= 1 && result.retryAfterSeconds <= 300
							? { retryAfterSeconds: result.retryAfterSeconds } : {}) } }
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
		this._foxholeRestoreMetadata?.();
		if (this._foxholeRelay)
			window.removeEventListener('message', this._foxholeRelay);
		if (this._foxholeFrame && this._foxholeFrame.contentWindow)
			this._foxholeFrame.contentWindow.postMessage({
				source: 'foxhole-host', id: 'foxhole-close', result: {}
			}, window.location.origin);
	}
});
