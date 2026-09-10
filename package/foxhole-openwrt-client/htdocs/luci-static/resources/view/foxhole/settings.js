'use strict';
'require form';
'require request';
'require view';

function loadLocale(name) {
	return request.get(L.resource('foxhole/locales/' + name + '.json'), {
		cache: false
	}).then(response => response.json());
}

return view.extend({
	load: function() {
		return Promise.all([loadLocale('ru'), loadLocale('en')]);
	},

	render: function(locales) {
		const language = String(document.documentElement.lang || 'en')
			.toLowerCase().startsWith('ru') ? 'ru' : 'en';
		const dictionary = language === 'ru' ? locales[0] : locales[1];
		const fallback = locales[1];
		const text = key => dictionary[key] || fallback[key] || key;
		let map, section, option;

		map = new form.Map('foxhole', text('luci.title'),
			text('luci.access_description'));
		section = map.section(form.NamedSection, 'panel', 'foxhole',
			text('luci.access_section'));
		section.addremove = false;
		option = section.option(form.Flag, 'standalone',
			text('luci.standalone_access'));
		option.default = option.enabled;
		option.rmempty = false;
		return map.render();
	}
});
