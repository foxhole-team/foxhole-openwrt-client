const phases = new Set(['connecting', 'connected', 'blocked', 'disconnected', 'error']);
const processes = new Set(['foxhole-history', 'hysteria', 'foxcore-cli', 'ucode', 'rpcd', 'uhttpd', 'logd', 'ubusd', 'apk', 'dnsmasq', 'other']);
const integer = value => Number.isSafeInteger(value) && value >= 0;
function invalid() { throw Object.assign(new Error('unavailable'), { code: 'unavailable' }); }
export function parseLogSnapshot(value) {
  if (!value || value.schema !== 1 || !integer(value.collectedAtUnixMs) || value.collectedAtUnixMs > 8640000000000000 ||
      !(value.memAvailableKiB === null || integer(value.memAvailableKiB)) ||
      !(value.uptimeSeconds === null || integer(value.uptimeSeconds)) || !value.runtime ||
      !(value.runtime.phase === null || phases.has(value.runtime.phase)) ||
      !(value.runtime.error === null || typeof value.runtime.error === 'string' && /^[a-z_]{1,64}$/.test(value.runtime.error))) invalid();
  for (const source of [value.package, value.core, value.kernel])
    if (!source || typeof source.available !== 'boolean' || !Array.isArray(source.events) || source.events.length > 32) invalid();
  if (typeof value.core.eventsAvailable !== 'boolean' || value.core.available && !['running', 'stopped'].includes(value.core.phase)) invalid();
  for (const event of [...value.package.events, ...value.core.events])
    if (event.event !== 'tunnel_exited' || !['core', 'hysteria', 'unknown'].includes(event.engine) ||
        !integer(event.exitStatus) || event.exitStatus > 255 ||
        !(event.time === null || typeof event.time === 'string' && /^[A-Za-z0-9 :]{1,32}$/.test(event.time))) invalid();
  for (const event of value.kernel.events)
    if (!['oom_killed', 'oom_selected', 'oom_invoked'].includes(event.event) || !processes.has(event.process) ||
        !Number.isFinite(event.uptimeSeconds) || event.uptimeSeconds < 0 ||
        !(event.pid === null || integer(event.pid))) invalid();
  return value;
}

export function parseJournalSnapshot(value) {
  if (!value || value.schema !== 2 || !['FLASH', 'RAM'].includes(value.storage) || typeof value.available !== 'boolean' ||
      ![null, 'RAM_DISABLED', 'LOW_MEMORY', 'BUSY'].includes(value.reason) ||
      value.retentionSeconds !== 2592000 || value.sharePercent !== 2 ||
      !integer(value.limitBytes) || value.limitBytes > 1048576 || !integer(value.reserveBytes) ||
      !integer(value.totalRecords) || value.totalRecords > 2048 || !integer(value.droppedRecords) ||
      !integer(value.beforeSequence) || typeof value.hasMore !== 'boolean' ||
      !Array.isArray(value.entries) || value.entries.length > 128 || value.entries.length > value.totalRecords ||
      !value.available && value.entries.length || value.hasMore && !value.entries.length) invalid();
  parseLogSnapshot(value.snapshot);
  const sequences = new Set();
  let previousSequence = Number.POSITIVE_INFINITY;
  for (const row of value.entries) {
    if (!row || !integer(row.sequence) || !row.sequence || sequences.has(row.sequence) ||
        !integer(row.observedAtUnixMs) || row.observedAtUnixMs > 8640000000000000 || !['package', 'kernel'].includes(row.source)) invalid();
    if (row.sequence >= previousSequence) invalid();
    previousSequence = row.sequence;
    sequences.add(row.sequence);
    parseLogSnapshot({ ...value.snapshot, package: { available: true, events: row.source === 'package' ? [row.event] : [] },
      core: { available: false, eventsAvailable: true, events: [] },
      kernel: { available: true, events: row.source === 'kernel' ? [row.event] : [] } });
  }
  if (value.beforeSequence !== (value.entries.at(-1)?.sequence || 0)) invalid();
  return value;
}
export class LogsPanel {
  constructor({ call, text, scope, bytes, error, storage }) {
    Object.assign(this, { call, text, scope, bytes, error, storage });
    this.sequence = 0;
  }
  close() { this.sequence++; this.loading = false; this.value = null; this.archive = null; this.failed = false; this.failureCode = null; this.ramDisabled = false; }
  open() { this.close(); return this.refresh(); }
  render() {
    const root = document.querySelector('[data-modal-view="logs"]');
    if (!root) return;
    const status = root.querySelector('[data-log-status]');
    status.textContent = this.ramDisabled ? this.text('logs.ram_unavailable') : this.loading ? this.text('logs.loading') : this.failed ? this.text(this.failureCode === 'tls_required' ? 'logs.tls_required' : 'error.unavailable') : '';
    const refresh = document.querySelector('[data-action="logs-refresh"]');
    refresh?.toggleAttribute('disabled', Boolean(this.loading || this.ramDisabled));
    if (refresh) refresh.hidden = this.ramDisabled;
    const content = root.querySelector('[data-log-content]');
    if (content) content.hidden = this.ramDisabled;
    const older = root.querySelector('[data-action="logs-older"]');
    if (older) { older.hidden = !this.archive?.hasMore; older.disabled = Boolean(this.loading); }
    if (!this.value) return;
    const value = this.value;
    root.querySelector('[data-log-summary]').textContent = this.text('logs.memory', {
      value: value.memAvailableKiB === null ? '—' : this.bytes(value.memAvailableKiB * 1024),
      time: new Date(value.collectedAtUnixMs).toLocaleTimeString()
    });
    root.querySelector('[data-log-runtime]').textContent = this.text('logs.runtime_state', { phase: value.runtime.phase ? this.text(`logs.phase_${value.runtime.phase}`) : '—' })
      + (value.runtime.error ? ` · ${this.text(`error.${value.runtime.error}`)}` : '');
    root.querySelector('[data-core-log-state]').textContent = value.core.available
      ? this.text('logs.core_state', { phase: this.text(`logs.phase_${value.core.phase}`) }) : this.text('logs.core_unavailable');
    for (const name of ['package', 'core', 'kernel']) {
      const source = value[name];
      const records = this.archive?.entries.filter(row => name === 'kernel' ? row.source === 'kernel'
        : row.source === 'package' && (name !== 'core' || row.event.engine === 'core'));
      const rows = records || source.events.map(event => ({ event }));
      const lines = rows.map(row => {
        const event = row.event, time = row.observedAtUnixMs == null ? event.time ?? '—'
          : new Date(row.observedAtUnixMs).toLocaleString(document.documentElement?.lang);
        return name === 'kernel'
          ? `${time} · ${event.uptimeSeconds.toFixed(3)}s · ${this.text(`logs.${event.event}`)} · ${event.process}${event.pid === null ? '' : ` (${event.pid})`}`
          : `${time} · ${this.text('logs.tunnel_exited')} · ${event.engine === 'core' ? 'FoxHole Core' : event.engine === 'hysteria' ? 'Hysteria' : '—'} · ${this.text('logs.exit_code', { value: event.exitStatus })}`;
      });
      root.querySelector(`[data-log-source="${name}"]`).textContent = lines.length ? lines.join('\n')
        : this.text((name === 'core' ? source.eventsAvailable : source.available) ? 'logs.empty' : 'logs.unavailable');
    }
  }
  async refresh(older = false) {
    if (this.loading) return;
    const sequence = ++this.sequence, scope = this.scope();
    this.loading = true; this.failed = false; this.render();
    try {
      if (this.storage) {
        const storage = await this.storage();
        if (sequence !== this.sequence || scope !== this.scope()) return;
        this.ramDisabled = storage === 'RAM';
        if (this.ramDisabled) { this.value = null; return; }
      }
      const result = parseJournalSnapshot(await this.call('diagnostics.journal', {
        beforeSequence: older ? this.archive?.beforeSequence || 0 : 0
      }));
      if (sequence !== this.sequence || scope !== this.scope()) return;
      if (result.reason === 'RAM_DISABLED') { this.ramDisabled = true; this.value = null; this.archive = null; return; }
      if (!result.available) throw Object.assign(new Error('unavailable'), { code: 'unavailable' });
      const entries = older ? [...new Map([...(this.archive?.entries || []), ...result.entries]
        .map(row => [row.sequence, row])).values()].slice(0, 2048) : result.entries;
      this.archive = { ...result, entries };
      this.value = result.snapshot;
    } catch (error) {
      if (sequence !== this.sequence || scope !== this.scope()) return;
      this.failed = true; this.failureCode = error?.code; this.error?.(error);
    } finally {
      if (sequence === this.sequence && scope === this.scope()) { this.loading = false; this.render(); }
    }
  }
}
