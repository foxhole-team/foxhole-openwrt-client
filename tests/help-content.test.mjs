import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { helpTopics, helpResourceKeys, HelpPanel } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/help-content.js';

test('all twelve stable topics have explicit structure and translated text in every locale', () => {
  assert.deepEqual(helpTopics.map(x => x.id), ['start','profiles','routing','dns','blocking','phone','clients','updates','storage','privacy','diagnostics','current']);
  const keys = helpResourceKeys();
  for (const lang of ['en','ru','de','fr','es','ja','zh','ar']) {
    const values = JSON.parse(readFileSync(new URL(`../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/locales/${lang}.json`, import.meta.url), 'utf8'));
    for (const key of keys) assert.ok(typeof values[key] === 'string' && values[key].trim(), `${lang}: ${key}`);
  }
  assert.equal(helpTopics[0].blocks.find(x => x.type === 'steps').items.length, 4);
});

function node(tag) {
  return { tag, children: [], dataset: {}, attributes: {}, listeners: {}, textContent: '', isConnected: true,
    append(...items) { this.children.push(...items); }, replaceChildren(...items) { this.children = items; },
    setAttribute(key, value) { this.attributes[key] = value; }, addEventListener(key, value) { this.listeners[key] = value; },
    set innerHTML(_value) { assert.fail('Help must not interpolate HTML'); } };
}

test('Help safely renders text, keeps native disclosure and never performs a request', () => {
  const root = node('root'), panel = new HelpPanel({
    text: key => key === 'manual.intro' ? '<img src=x onerror=alert(1)>' : key,
    element: (tag, cls, text) => Object.assign(node(tag), { className: cls, textContent: text || '' }),
    icon: () => node('svg'), facts: () => ({ version: null, storage: null, modules: null })
  });
  panel.render(root, 'diagnostics');
  assert.equal(root.children[0].textContent, '<img src=x onerror=alert(1)>');
  const details = root.children.filter(x => x.tag === 'details');
  assert.equal(details.length, 11);
  assert.ok(details.some(x => x.dataset.helpTopic === 'diagnostics' && x.open));
  assert.ok(details.every(x => x.children[0].tag === 'summary'));
  const links = [];
  function visit(value) { if (value.tag === 'a') links.push(value); value.children.forEach(visit); }
  visit(root);
  assert.equal(links.length, 0);
  assert.ok(!helpResourceKeys().includes('manual.start.install'));
  assert.ok(!helpResourceKeys().includes('manual.start.link'));
});

test('one global Help entry stays outside every modal and install calls to action are absent',()=>{
 const html=readFileSync(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/shell.html',import.meta.url),'utf8');
 const dialog=html.slice(html.indexOf('<dialog id="modal-shell"'),html.indexOf('</dialog>'));
 assert.doesNotMatch(dialog,/data-action="open-help"/);
 assert.equal((html.match(/data-action="open-help"/g)||[]).length,1);
 assert.ok(html.indexOf('data-main-help-entry')<html.indexOf('<dialog id="modal-shell"'));
});
