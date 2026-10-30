'use strict';
'require rpc';
'require request';
'require view';

const setPin = rpc.declare({
	object: 'foxhole.admin', method: 'set_pin', params: ['newPin', 'licenseAccepted', 'licenseVersion'],
	reject: true
});

const packageStatus = rpc.declare({ object: 'foxhole', method: 'package.status', params: [], reject: true });

const languages = ['ru', 'en', 'ja', 'de', 'fr', 'es', 'zh'];

return view.extend({
	load: function() {
		return Promise.all([...languages.map(language =>
			request.get(L.resource('foxhole/locales/' + language + '.json'),
				{ cache: false }).then(response => response.json())), packageStatus()]);
	},

	render: function(locales) {
		const language = String(document.documentElement.lang || 'en')
			.toLowerCase().split(/[-_]/)[0];
		const dictionary = locales[languages.indexOf(language)] || locales[1];
		const text = key => dictionary[key] || locales[1][key];
		const status = locales[languages.length] || {};
		const agreementRequired = status.licenseRequired === true ||
			(status.licenseRequired == null && status.pinConfigured !== true);
		const supported = (status.licenseRequired == null || typeof status.licenseRequired === 'boolean') &&
			(status.licenseVersion == null || status.licenseVersion === 1);
		const acceptance = E('input', { type: 'checkbox' });
		let saving = false;
		const input = name => E('input', {
			id: name, type: 'password', inputmode: 'numeric',
			maxlength: 4, pattern: '[0-9]{4}', autocomplete: 'new-password',
			required: true, 'class': 'cbi-input-password'
		});
		const first = input('foxhole-new-pin');
		const repeat = input('foxhole-repeat-pin');
		const message = E('p', { role: 'status', 'aria-live': 'polite' });
		const button = E('button', { type: 'submit',
			'class': 'cbi-button cbi-button-apply' }, text('action.save'));
		const row = (field, label) => E('div', { 'class': 'cbi-value' }, [
			E('label', { 'for': field.id, 'class': 'cbi-value-title' },
				text(label)),
			E('div', { 'class': 'cbi-value-field' }, [field])
		]);
		const agreement = agreementRequired ? [
			E('details', {}, [E('summary', {}, text('license.title')),
				E('p', { style: 'white-space: pre-wrap' }, text('license.body'))]),
			E('label', { 'class': 'cbi-value' }, [acceptance, ' ', text('license.accept')])
		] : [];
		const updateAcceptance = () => { button.disabled = saving || !supported || (agreementRequired && !acceptance.checked); };
		acceptance.addEventListener('change', updateAcceptance);
		updateAcceptance();
		const form = E('form', { autocomplete: 'off' }, [
			...agreement, row(first, 'pin_change.new_pin'),
			row(repeat, 'pin_change.repeat_pin'), message, button
		]);
		form.addEventListener('submit', async event => {
			event.preventDefault();
			if (button.disabled) return;
			if (!supported || (agreementRequired && !acceptance.checked)) {
				message.textContent = text('error.license_required');
				return;
			}
			if (!/^[0-9]{4}$/.test(first.value) || first.value !== repeat.value) {
				message.textContent = text('error.pin_mismatch');
				return;
			}
			saving = true; acceptance.disabled = true; updateAcceptance();
			try {
				const result = await setPin(first.value, agreementRequired && acceptance.checked, agreementRequired && acceptance.checked ? 1 : 0);
				if (!result?.changed) throw new Error('unavailable');
				form.reset();
				message.textContent = text('pin_change.success');
			} catch (_) {
				message.textContent = text('error.unavailable');
			} finally { saving = false; acceptance.disabled = false; updateAcceptance(); }
		});
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, text('pin_change.title')),
			E('p', {}, text('luci.pin_description')), form
		]);
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
