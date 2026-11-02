export const MAX_BACKUP_BYTES = 294912;
const PANEL_OPTIONS = ['mode', 'telemetry_interval', 'standalone', 'lan_devices', 'mobile_devices',
  'dns_via_tunnel', 'preserve_loopback_socks', 'tun_mtu'];
const STATES = new Set(['IDLE', 'BUSY', 'PREPARED', 'APPLYING', 'STATE_COMMITTING', 'COMMITTED', 'CANCELLED', 'RECOVERY_REQUIRED']);
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;

function invalid() { throw Object.assign(new Error('backup_invalid'), { code: 'backup_invalid' }); }
function exact(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || Object.keys(value).some(key => !names.includes(key))) invalid();
}
function boundedTree(value, depth = 0) {
  if (depth > 16) invalid();
  if (!value || typeof value !== 'object') return;
  for (const key of Object.keys(value)) {
    if (['__proto__', 'prototype', 'constructor'].includes(key)) invalid();
    boundedTree(value[key], depth + 1);
  }
}

export function parseBackup(raw) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > MAX_BACKUP_BYTES) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  boundedTree(value);
  exact(value, ['schema', 'kind', 'createdAtUnixMs', 'state', 'panel', 'autoUpdate']);
  if (value.schema !== 1 || value.kind !== 'foxhole-settings-backup-v1' || !integer(value.createdAtUnixMs)) invalid();
  exact(value.state, ['schema', 'revision', 'activeServerId', 'settings', 'countries', 'devices', 'sites', 'servers', 'clients']);
  if (value.state.schema !== 1 || !integer(value.state.revision) || !value.state.settings ||
      typeof value.state.settings !== 'object' || Array.isArray(value.state.settings)) invalid();
  for (const key of ['countries', 'devices', 'sites', 'servers', 'clients'])
    if (!Array.isArray(value.state[key]) || value.state[key].length > 512) invalid();
  if (value.panel && typeof value.panel === 'object' && !Array.isArray(value.panel) &&
      Object.keys(value.panel).length === PANEL_OPTIONS.length - 1 && !Object.hasOwn(value.panel, 'mobile_devices'))
    value.panel = { ...value.panel, mobile_devices: null };
  exact(value.panel, PANEL_OPTIONS);
  exact(value.autoUpdate, ['enabled']);
  if (typeof value.autoUpdate.enabled !== 'boolean') invalid();
  for (const [key, item] of Object.entries(value.panel)) {
    if (item === null) continue;
    if (key === 'lan_devices' || key === 'mobile_devices') {
      if (!Array.isArray(item) || item.length > (key === 'mobile_devices' ? 8 : 32) ||
          (key === 'mobile_devices' && item.length === 0) || new Set(item).size !== item.length ||
          item.some(device => typeof device !== 'string' || !/^[A-Za-z0-9_.:-]{1,32}$/.test(device))) invalid();
    } else if (key === 'mode') {
      if (!['runtime', 'off'].includes(item)) invalid();
    } else if (['standalone', 'dns_via_tunnel', 'preserve_loopback_socks'].includes(key)) {
      if (!['0', '1'].includes(item)) invalid();
    } else if (typeof item !== 'string' || !/^[0-9]{1,4}$/.test(item) ||
        (key === 'tun_mtu' && (+item < 1280 || +item > 1500)) ||
        (key === 'telemetry_interval' && (+item < 1 || +item > 3600))) invalid();
  }
  if (value.state.settings.standaloneAccess !== (value.panel.standalone !== '0')) invalid();
  return value;
}

function validateSummary(value) {
  if (!value || value.schema !== 1 || !sha(value.backupSha256) || !integer(value.revision) ||
      value.confirmationRequired !== true || value.reconnectRequired !== true ||
      !['servers', 'clients', 'devices', 'sites', 'countries'].every(key => integer(value[key]) && value[key] <= 512)) invalid();
  return value;
}
function validateJob(value) {
  if (!value || value.schema !== 1 || !STATES.has(value.state) ||
      !(value.jobId === null || /^restore-[a-f0-9]{32}$/.test(value.jobId))) invalid();
  return value;
}
function requestId() {
  const bytes = new Uint8Array(16);
  if (!globalThis.crypto?.getRandomValues) invalid();
  crypto.getRandomValues(bytes);
  return `restore-${[...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

export class BackupPanel {
  constructor({ call, text, scope, revision, notice, restored }) {
    Object.assign(this, { call, text, scope, revision, notice, restored });
    this.sequence = 0;
    this.uncertain = null;
    this.supported = false;
    this.capabilitySequence = 0;
  }
  close() { this.sequence++; clearTimeout(this.timer); this.supported = false; }
  current(sequence, scope) { return sequence === this.sequence && scope === this.scope(); }
  async capability() {
    const sequence = this.sequence, scope = this.scope();
    const capability = ++this.capabilitySequence;
    this.supported = false;
    try {
      const value = await this.call('package.status');
      if (!this.current(sequence, scope) || capability !== this.capabilitySequence) return false;
      this.supported = value?.schema === 1 && value.product === 'foxhole' &&
        value.installed === true && value.backupSupported === true;
    } catch {
      if (this.current(sequence, scope) && capability === this.capabilitySequence) this.supported = false;
    }
    return this.supported;
  }
  available() {
    if (!this.supported) throw Object.assign(new Error('backup_unavailable'), { code: 'backup_unavailable' });
  }
  secure() {
    this.available();
    if (location.protocol !== 'https:') throw Object.assign(new Error('tls_required'), { code: 'tls_required' });
  }
  render() {
    const root = document.querySelector('[data-modal-view="backup"]');
    if (!root) return;
    root.querySelector('[data-action="backup-save"]').disabled = Boolean(this.uncertain);
    root.querySelector('[data-action="backup-choose"]').disabled = Boolean(this.uncertain);
    root.querySelector('[data-action="backup-status"]').hidden = !this.uncertain;
    const status = root.querySelector('[data-backup-status]');
    status.hidden = !this.uncertain;
    status.textContent = this.uncertain ? this.text(this.jobState === 'RECOVERY_REQUIRED'
      ? 'error.backup_recovery_required' : 'backup.uncertain') : '';
  }
  async save() {
    this.secure();
    if (this.uncertain || !window.confirm(this.text('backup.save_confirm'))) return false;
    const sequence = this.sequence, scope = this.scope();
    const filename = `foxhole-backup-${new Date().toISOString().slice(0, 10)}.json`;
    let handle = null;
    if (typeof window.showSaveFilePicker === 'function') {
      try {
        handle = await window.showSaveFilePicker({ suggestedName: filename,
          types: [{ description: 'FoxHole backup', accept: { 'application/json': ['.json'] } }] });
      } catch (error) {
        if (['AbortError', 'NotAllowedError'].includes(error?.name)) return false;
        if (error?.name !== 'SecurityError') throw error;
      }
    }
    if (!this.current(sequence, scope)) return false;
    const value = await this.call('backup.export');
    if (!this.current(sequence, scope)) return false;
    const raw = JSON.stringify(value);
    parseBackup(raw);
    const blob = new Blob([raw], { type: 'application/json' });
    if (handle) {
      const output = await handle.createWritable();
      if (!this.current(sequence, scope)) { await output.abort(); return false; }
      try { await output.write(blob); await output.close(); }
      catch (error) { try { await output.abort(); } catch {} throw error; }
    } else {
      const url = URL.createObjectURL(blob), link = document.createElement('a');
      link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    if (this.current(sequence, scope)) this.notice(this.text('backup.saved'));
    return true;
  }
  choose() {
    this.secure();
    if (!this.uncertain) document.querySelector('[data-backup-file]')?.click();
  }
  async restore(file) {
    this.secure();
    if (this.uncertain || !file || file.size < 2 || file.size > MAX_BACKUP_BYTES) invalid();
    const sequence = this.sequence, scope = this.scope();
    const document = parseBackup(await file.text());
    if (!this.current(sequence, scope)) return false;
    const summary = validateSummary(await this.call('backup.validate', { document, expectedRevision: this.revision() }));
    if (!this.current(sequence, scope) || !window.confirm(this.text('backup.restore_confirm', summary))) return false;
    const id = requestId();
    this.uncertain = id;
    try {
      const job = validateJob(await this.call('backup.apply', { document, expectedRevision: summary.revision,
        confirmed: true, requestId: id }));
      if (!this.current(sequence, scope)) return false;
      if (job.jobId !== id) invalid();
      this.jobState = job.state;
      if (job.state === 'COMMITTED') {
        this.uncertain = null;
        await this.restored(); this.notice(this.text('backup.restored')); return true;
      }
      if (job.state === 'CANCELLED') {
        this.uncertain = null; this.notice(this.text('backup.cancelled'), 'error'); return false;
      }
      if (['PREPARED', 'APPLYING', 'STATE_COMMITTING'].includes(job.state)) { await this.status(); return false; }
      throw Object.assign(new Error('backup_recovery_required'), { code: 'backup_recovery_required' });
    } catch (error) {
      if (this.current(sequence, scope)) {
        try { await this.status(); if (this.resolved === id) return true; } catch {}
      }
      throw error;
    } finally { if (this.current(sequence, scope)) this.render(); }
  }
  async status() {
    this.available();
    clearTimeout(this.timer);
    const sequence = this.sequence, scope = this.scope(),id = this.uncertain;
    const job = validateJob(await this.call('backup.status'));
    if (!this.current(sequence, scope)) return false;
    this.jobState = job.state;
    if (id && job.jobId === id && ['COMMITTED', 'CANCELLED'].includes(job.state)) {
      this.uncertain = null;
      if (job.state === 'COMMITTED') { this.resolved = id; await this.restored(); this.notice(this.text('backup.restored')); }
      else this.notice(this.text('backup.cancelled'), 'error');
    } else if (id && job.state === 'IDLE') {
      this.uncertain = null;
    } else if (!id && ['PREPARED', 'APPLYING', 'STATE_COMMITTING', 'RECOVERY_REQUIRED', 'BUSY'].includes(job.state))
      this.uncertain = job.jobId || 'busy';
    this.render();
    if (this.uncertain && ['PREPARED', 'APPLYING', 'STATE_COMMITTING'].includes(job.state))
      this.timer = setTimeout(() => { void this.status().catch(() => this.render()); }, 750);
    return !this.uncertain;
  }
}
