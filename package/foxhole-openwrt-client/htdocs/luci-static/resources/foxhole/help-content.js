const paragraph = key => ({ type: 'paragraph', key });
const warning = key => ({ type: 'warning', key });
const steps = (...items) => ({ type: 'steps', items });
const bullets = (...items) => ({ type: 'bullets', items });
const topic = (id, icon, blocks) => ({ id, icon, title: `manual.${id}.title`, blocks });

export const helpTopics = Object.freeze([
  topic('start', 'router', [steps('manual.start.one','manual.start.two','manual.start.three','manual.start.four')]),
  topic('profiles', 'server', [paragraph('manual.profiles.body'), warning('manual.profiles.editor')]),
  topic('routing', 'globe', [paragraph('manual.routing.body'),
    steps('manual.routing.devices','manual.routing.vpn','manual.routing.direct','manual.routing.countries'), warning('manual.routing.note')]),
  topic('dns', 'globe', [paragraph('manual.dns.body'), { type: 'examples', values: ['example.com', '*.example.com'] }, warning('manual.dns.limits')]),
  topic('blocking', 'shield', [paragraph('manual.blocking.start'), paragraph('manual.blocking.stop'),
    paragraph('manual.blocking.direct'), warning('manual.blocking.notice')]),
  topic('phone', 'mobile', [paragraph('manual.phone.body'), paragraph('manual.phone.pin'), warning('manual.phone.trust')]),
  topic('clients', 'mobile', [paragraph('manual.clients.body'), warning('manual.clients.privacy'),
    paragraph('manual.clients.revoke'), paragraph('manual.clients.home')]),
  topic('updates', 'download', [paragraph('manual.updates.body'), paragraph('manual.updates.auto'),
    warning('manual.updates.lost'), paragraph('manual.updates.core')]),
  topic('storage', 'floppy', [{ type: 'definitions', items: [['manual.storage.flash_title','manual.storage.flash'],['manual.storage.ram_title','manual.storage.ram']] },
    paragraph('manual.storage.settings'), warning('manual.storage.bootstrap')]),
  topic('privacy', 'lock', [paragraph('manual.privacy.backup'), warning('manual.privacy.restore'), paragraph('manual.privacy.online')]),
  topic('diagnostics', 'logs', [paragraph('manual.diagnostics.body'), paragraph('logs.flash_policy'), warning('logs.ram_unavailable'),
    { type: 'definitions', items: ['pin','test','dns','module','memory','lost','remote','stale']
      .map(id => [`manual.problem.${id}.title`, `manual.problem.${id}.body`]) }]),
  topic('current', 'info', [paragraph('manual.current.body'), { type: 'facts' }, warning('manual.current.requirements')])
]);

export function helpResourceKeys() {
  const keys = new Set(['manual.intro', 'about.version', 'about.storage', 'about.modules', 'about.unavailable', 'about.no_modules']);
  for (const item of helpTopics) {
    keys.add(item.title);
    for (const block of item.blocks) {
      if (block.key) keys.add(block.key);
      for (const value of block.items || [])
        for (const key of Array.isArray(value) ? value : [value]) keys.add(key);
    }
  }
  return [...keys];
}

export class HelpPanel {
  constructor({ text, element, icon, facts }) {
    Object.assign(this, { text, element, icon, facts });
    this.expanded = new Set();
    this.factsNodes = null;
  }
  textNode(tag, key, cls = '') {
    const node = this.element(tag, cls, this.text(key));
    node.dataset.i18n = key;
    return node;
  }
  heading(item) {
    const heading = this.element('h3');
    const icon = this.element('span', 'help-topic-icon');
    icon.setAttribute('aria-hidden', 'true'); icon.append(this.icon(item.icon));
    heading.append(icon, this.textNode('span', item.title));
    return heading;
  }
  block(block) {
    if (block.type === 'paragraph') return this.textNode('p', block.key);
    if (block.type === 'warning') {
      const note = this.element('div', 'help-notice');
      const icon = this.element('span', 'help-topic-icon');
      icon.setAttribute('aria-hidden', 'true'); icon.append(this.icon('info'));
      note.append(icon, this.textNode('p', block.key));
      return note;
    }
    if (block.type === 'link') {
      const link = this.textNode('a', block.key, 'outline-button');
      link.href = block.href; link.target = '_blank'; link.rel = 'noopener noreferrer';
      return link;
    }
    if (['steps', 'bullets'].includes(block.type)) {
      const list = this.element(block.type === 'steps' ? 'ol' : 'ul');
      for (const key of block.items) list.append(this.textNode('li', key));
      return list;
    }
    if (block.type === 'definitions') {
      const list = this.element('dl', 'help-definitions');
      for (const [title, copy] of block.items) {
        const row = this.element('div');
        row.append(this.textNode('dt', title), this.textNode('dd', copy)); list.append(row);
      }
      return list;
    }
    if (block.type === 'examples') {
      const row = this.element('div', 'help-examples');
      for (const value of block.values) {
        const code = this.element('code', '', value);
        code.dir = 'ltr'; row.append(code);
      }
      return row;
    }
    if (block.type === 'facts') {
      const list = this.element('dl', 'help-definitions');
      this.factsNodes = {};
      for (const key of ['version', 'storage', 'modules']) {
        const row = this.element('div'), value = this.element('dd');
        this.factsNodes[key] = value;
        row.append(this.textNode('dt', `about.${key}`), value); list.append(row);
      }
      return list;
    }
    throw new Error('unsupported-help-block');
  }
  render(root, selected = null) {
    this.factsNodes = null;
    root.replaceChildren(this.textNode('p', 'manual.intro', 'help-intro'));
    for (const item of helpTopics) {
      if (item.id === 'start') {
        const section = this.element('section', 'help-topic help-start');
        section.append(this.heading(item), ...item.blocks.map(block => this.block(block)));
        root.append(section); continue;
      }
      const details = this.element('details', 'help-topic help-disclosure');
      details.dataset.helpTopic = item.id;
      const summary = this.element('summary'), content = this.element('div', 'help-topic-content');
      content.id = `help-topic-${item.id}`;
      details.open = this.expanded.has(item.id) || selected === item.id;
      summary.setAttribute('aria-controls', content.id);
      summary.setAttribute('aria-expanded', String(details.open));
      const heading = this.heading(item), chevron = this.element('span', 'help-chevron');
      chevron.setAttribute('aria-hidden', 'true'); chevron.append(this.icon('chevron'));
      heading.append(chevron); summary.append(heading);
      content.append(...item.blocks.map(block => this.block(block)));
      details.append(summary, content);
      details.addEventListener('toggle', () => {
        if (details.open) this.expanded.add(item.id); else this.expanded.delete(item.id);
        summary.setAttribute('aria-expanded', String(details.open));
      });
      root.append(details);
    }
    this.updateFacts();
  }
  focusTopic(root, selected) {
    if (!root || !selected) return;
    const topic = [...root.querySelectorAll('details[data-help-topic]')]
      .find(node => node.dataset.helpTopic === selected);
    const summary = topic?.querySelector('summary');
    summary?.focus({ preventScroll: true });
    summary?.scrollIntoView({ block: 'start', inline: 'nearest' });
  }
  updateFacts() {
    if (!this.factsNodes) return;
    const facts = this.facts?.() || {}, unavailable = this.text('about.unavailable');
    this.factsNodes.version.textContent = facts.version || unavailable;
    this.factsNodes.storage.textContent = facts.storage || unavailable;
    this.factsNodes.modules.textContent = facts.modules?.length
      ? facts.modules.map(item => `${item.id}: ${item.version} (${item.storage})`).join('\n') : Array.isArray(facts.modules) ? this.text('about.no_modules') : unavailable;
  }
}
