'use strict';
'require rpc';
'require request';
'require view';

const setPin = rpc.declare({
	object: 'foxhole.admin', method: 'set_pin', params: ['newPin'],
	reject: true
});

return view.extend({
	load: function() {
		return Promise.all(['ru', 'en'].map(language =>
			request.get(L.resource('foxhole/locales/' + language + '.json'),
				{ cache: false }).then(response => response.json())));
	},

	render: function(locales) {
		const russian = String(document.documentElement.lang || 'en')
			.toLowerCase().startsWith('ru');
		const text = key => locales[russian ? 0 : 1][key] || locales[1][key];
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
		const form = E('form', { autocomplete: 'off' }, [
			row(first, 'pin_change.new_pin'),
			row(repeat, 'pin_change.repeat_pin'), message, button
		]);
		form.addEventListener('submit', async event => {
			event.preventDefault();
			if (button.disabled) return;
			if (!/^[0-9]{4}$/.test(first.value) || first.value !== repeat.value) {
				message.textContent = text('error.pin_mismatch');
				return;
			}
			button.disabled = true;
			try {
				const result = await setPin(first.value);
				if (!result?.changed) throw new Error('unavailable');
				form.reset();
				message.textContent = text('pin_change.success');
			} catch (_) {
				message.textContent = text('error.unavailable');
			} finally { button.disabled = false; }
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
