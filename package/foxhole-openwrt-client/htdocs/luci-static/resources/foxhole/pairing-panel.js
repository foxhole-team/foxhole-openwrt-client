const pairingId = value => typeof value === 'string' && /^pair-[a-f0-9]{32}$/.test(value);
const versionName = value => typeof value === 'string' && value.length <= 64 &&
  /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$/.test(value);
function unavailable() { throw Object.assign(new Error('unavailable'), { code: 'unavailable' }); }

export function pairedCount(value) {
  return Number.isInteger(value) && value >= 0 && value <= 16 ? value : null;
}

export function parsePairings(value) {
  if (!value || !Array.isArray(value.devices) || value.devices.length > 16) unavailable();
  const seen = new Set();
  return value.devices.map(device => {
    if (!device || !pairingId(device.id) || seen.has(device.id) || typeof device.name !== 'string' ||
        !device.name.length || device.name.length > 128 || /[\x00-\x1f\x7f]/.test(device.name) ||
        !Number.isSafeInteger(device.created) || device.created < 0) unavailable();
    seen.add(device.id);
    const client = ['guard', 'vpn'].includes(device.client) ? device.client : null;
    return { id: device.id, name: device.name, created: device.created, client,
      clientVersion: client && versionName(device.clientVersion) ? device.clientVersion : null };
  });
}

export function authorizationDate(created, language) {
  if (!Number.isSafeInteger(created) || created <= 0 || created > 253402300799) return '—';
  try {
    return new Intl.DateTimeFormat(language, { year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit' }).format(new Date(created * 1000));
  } catch { return '—'; }
}

export class PairingPanel {
  constructor({ call, text, element, icon, scope, language, confirm, refreshed, error }) {
    Object.assign(this, { call, text, element, icon, scope, language, confirm, refreshed, error });
    this.sequence = 0;
    this.devices = null;
    this.loading = false;
    this.failed = false;
  }
  close() { this.sequence++; this.devices = null; this.loading = false; this.failed = false; }
  current(sequence, scope) { return sequence === this.sequence && scope === this.scope(); }
  async open() {
    const sequence = ++this.sequence, scope = this.scope();
    this.loading = true; this.failed = false; this.devices = null; this.render();
    try {
      const devices = parsePairings(await this.call('pair.list'));
      if (!this.current(sequence, scope)) return;
      this.devices = devices;
    } catch (error) {
      if (!this.current(sequence, scope)) return;
      this.failed = true; this.error(error);
    } finally {
      if (this.current(sequence, scope)) { this.loading = false; this.render(); }
    }
  }
  async revoke(id) {
    if (!pairingId(id) || !this.devices?.some(device => device.id === id)) unavailable();
    const sequence = this.sequence, scope = this.scope();
    await this.call('pair.revoke', { id });
    if (!this.current(sequence, scope)) return false;
    this.devices = this.devices.filter(device => device.id !== id);
    try { await this.refreshed(); }
    catch (error) { if (this.current(sequence, scope)) this.error(error); }
    return this.current(sequence, scope);
  }
  renderHeader(value) {
    const button = document.querySelector('[data-paired-phone-button]');
    if (!button) return;
    const count = pairedCount(value), badge = button.querySelector('[data-paired-phone-count]');
    const label = count === null ? this.text('pairing.title') : this.text('pairing.count', { count });
    button.title = label; button.setAttribute('aria-label', label);
    button.classList.toggle('has-pairings', count !== null && count > 0);
    badge.hidden = count === null || count === 0;
    badge.textContent = count === null ? '' : String(count);
  }
  render() {
    const root = document.querySelector('[data-pairing-list]');
    if (!root) return;
    const status = document.querySelector('[data-pairing-status]');
    const refresh = document.querySelector('[data-action="pairing-refresh"]');
    if (refresh) refresh.disabled = this.loading;
    status.textContent = this.loading ? this.text('auth.loading') : this.failed ? this.text('error.unavailable')
      : !this.devices?.length ? this.text('pairing.empty') : '';
    status.hidden = !status.textContent;
    root.replaceChildren();
    if (!this.devices?.length || this.loading || this.failed) return;
    const table = this.element('table', 'pairing-table');
    const head = this.element('thead'), header = this.element('tr');
    for (const key of ['device', 'client', 'version', 'authorized', 'revoke']) {
      const cell = this.element('th', key === 'revoke' ? 'visually-hidden' : '', this.text(`pairing.${key}`));
      cell.scope = 'col'; header.append(cell);
    }
    head.append(header); table.append(head);
    const body = this.element('tbody');
    for (const device of this.devices) {
      const row = this.element('tr');
      for (const value of [device.name, device.client === 'guard' ? 'Guard' : device.client === 'vpn' ? 'VPN'
        : this.text('pairing.unknown'), device.clientVersion || '—', authorizationDate(device.created, this.language())])
        row.append(this.element('td', '', value));
      const action = this.element('td'), button = this.element('button', 'icon-button compact-icon is-danger');
      button.type = 'button'; button.title = this.text('pairing.revoke');
      button.setAttribute('aria-label', this.text('pairing.revoke_device', { name: device.name }));
      button.append(this.icon('trash'));
      button.addEventListener('click', () => { void this.confirm(device); });
      action.append(button); row.append(action); body.append(row);
    }
    table.append(body); root.append(table);
  }
}
