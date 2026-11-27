const phases = new Set(['connecting', 'connected', 'blocked', 'disconnected', 'error']);
const lifecycle = new Set(['tunnel_connected', 'tunnel_start_failed', 'tunnel_exited', 'runtime_stopped']);
const engines = new Set(['core', 'hysteria', 'unknown']);
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
  if (value.recent != null && (!Array.isArray(value.recent) || value.recent.length > 10 ||
      value.recent.some(row => !row || Object.keys(row).length !== 4 || !lifecycle.has(row.event) ||
        !engines.has(row.engine) || !integer(row.observedAtUnixMs) || row.observedAtUnixMs > 8640000000000000 ||
        !(row.event === 'tunnel_exited' ? integer(row.exitStatus) && row.exitStatus <= 255 : row.exitStatus === null)))) invalid();
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
  constructor({ call, text, scope, bytes, error }) {
    Object.assign(this, { call, text, scope, bytes, error });
    this.sequence = 0;
  }
  close() {
    clearTimeout(this.timer);
    this.sequence++;
    this.isOpen = this.loading = this.failed = this.ramDisabled = false;
    this.value = this.archive = this.failureCode = null;
  }
  open() {
    this.close();
    this.isOpen = true;
    return this.refresh(false, true);
  }
  visibilityChanged() {
    clearTimeout(this.timer);
    if (this.isOpen && !document.hidden) void this.refresh(false, false, true);
  }
  renderRecent(body) {
    const rows = this.value.recent;
    if (!rows?.length) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 2;
      cell.textContent = this.text(rows ? 'logs.empty' : 'logs.unavailable');
      return;
    }
    const labels = { tunnel_connected: 'logs.phase_connected', tunnel_start_failed: 'error.tunnel_start_failed',
      tunnel_exited: 'logs.tunnel_exited', runtime_stopped: 'logs.phase_disconnected' };
    for (const event of rows) {
      const row = body.insertRow();
      row.insertCell().textContent = new Date(event.observedAtUnixMs).toLocaleTimeString(document.documentElement?.lang);
      const engine = event.engine === 'core' ? 'FoxHole Core' : event.engine === 'hysteria' ? 'Hysteria 2' : null;
      row.insertCell().textContent = [this.text(labels[event.event]), engine,
        event.exitStatus === null ? null : this.text('logs.exit_code', { value: event.exitStatus })].filter(Boolean).join(' · ');
    }
  }
  render() {
    const root = document.querySelector('[data-modal-view="logs"]');
    if (!root) return;
    const status = root.querySelector('[data-log-status]');
    const initial = this.loading && !this.value;
    status.hidden = !initial && !this.failed;
    status.textContent = initial ? this.text('logs.loading') : this.failed ? this.text(this.failureCode === 'tls_required' ? 'logs.tls_required' : 'error.unavailable') : '';
    status.classList.toggle('foxhole-loading', initial);
    document.querySelector('[data-action="logs-refresh"]')?.toggleAttribute('disabled', Boolean(this.loading));
    const recent = root.querySelector('[data-log-recent]');
    recent.hidden = !this.ramDisabled || !this.value;
    const content = root.querySelector('[data-log-content]');
    content.hidden = this.ramDisabled || !this.value;
    if (!this.value) return;
    if (this.ramDisabled) {
      const body = recent.querySelector('[data-log-recent-rows]');
      body.replaceChildren();
      this.renderRecent(body);
      return;
    }
    const older = root.querySelector('[data-action="logs-older"]');
    older.hidden = !this.archive?.hasMore;
    older.disabled = Boolean(this.loading);
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
  async refresh(older = false, initial = false, automatic = false) {
    if (!this.isOpen || this.loading) return;
    clearTimeout(this.timer);
    const sequence = ++this.sequence, scope = this.scope();
    this.loading = true;
    this.render();
    const minimum = initial ? new Promise(resolve => setTimeout(resolve, 600)) : null;
    const previous = this.archive;
    try {
      const result = parseJournalSnapshot(await this.call('diagnostics.journal', {
        beforeSequence: older ? previous?.beforeSequence || 0 : 0
      }));
      await minimum;
      if (sequence !== this.sequence || scope !== this.scope()) return;
      if (result.reason !== 'RAM_DISABLED' && !result.available) invalid();
      this.failed = false;
      this.ramDisabled = result.reason === 'RAM_DISABLED';
      this.value = result.snapshot;
      if (this.ramDisabled) { this.archive = null; return; }
      const keepOlder = automatic && previous?.expanded === true;
      const first = older ? previous?.entries || [] : result.entries;
      const rest = older ? result.entries : keepOlder ? previous.entries : [];
      const entries = [...new Map([...first, ...rest].map(row => [row.sequence, row])).values()]
        .sort((a, b) => b.sequence - a.sequence).slice(0, 2048);
      this.archive = { ...result, entries, expanded: older || keepOlder,
        hasMore: keepOlder ? previous.hasMore : result.hasMore, beforeSequence: entries.at(-1)?.sequence || 0 };
    } catch (error) {
      await minimum;
      if (sequence !== this.sequence || scope !== this.scope()) return;
      this.failed = true;
      this.failureCode = error?.code;
      this.error?.(error);
    } finally {
      if (sequence === this.sequence && scope === this.scope()) {
        this.loading = false;
        this.render();
        if (this.isOpen && !document.hidden)
          this.timer = setTimeout(() => void this.refresh(false, false, true), 6000);
      }
    }
  }
}
