const phases = new Set(['connecting', 'connected', 'blocked', 'disconnected', 'error']);
const processes = new Set(['hysteria', 'foxcore-cli', 'ucode', 'rpcd', 'uhttpd', 'logd', 'ubusd', 'apk', 'dnsmasq', 'other']);
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
export class LogsPanel {
  constructor({ call, text, scope, bytes, error }) {
    Object.assign(this, { call, text, scope, bytes, error });
    this.sequence = 0;
  }
  close() { this.sequence++; this.loading = false; this.value = null; this.failed = false; this.failureCode = null; }
  open() { this.close(); return this.refresh(); }
  render() {
    const root = document.querySelector('[data-modal-view="logs"]');
    if (!root) return;
    const status = root.querySelector('[data-log-status]');
    status.textContent = this.loading ? this.text('logs.loading') : this.failed ? this.text(this.failureCode === 'tls_required' ? 'logs.tls_required' : 'error.unavailable') : '';
    document.querySelector('[data-action="logs-refresh"]')?.toggleAttribute('disabled', Boolean(this.loading));
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
      const lines = source.events.map(event => name === 'kernel'
        ? `${event.uptimeSeconds.toFixed(3)}s · ${this.text(`logs.${event.event}`)} · ${event.process}${event.pid === null ? '' : ` (${event.pid})`}`
        : `${event.time ?? '—'} · ${this.text('logs.tunnel_exited')} · ${event.engine === 'core' ? 'FoxHole Core' : event.engine === 'hysteria' ? 'Hysteria' : '—'} · ${this.text('logs.exit_code', { value: event.exitStatus })}`);
      root.querySelector(`[data-log-source="${name}"]`).textContent = lines.length ? lines.join('\n')
        : this.text((name === 'core' ? source.eventsAvailable : source.available) ? 'logs.empty' : 'logs.unavailable');
    }
  }
  async refresh() {
    if (this.loading) return;
    const sequence = ++this.sequence, scope = this.scope();
    this.loading = true; this.failed = false; this.render();
    try {
      const value = parseLogSnapshot(await this.call('diagnostics.logs'));
      if (sequence !== this.sequence || scope !== this.scope()) return;
      this.value = value;
    } catch (error) {
      if (sequence !== this.sequence || scope !== this.scope()) return;
      this.failed = true; this.failureCode = error?.code; this.error?.(error);
    } finally {
      if (sequence === this.sequence && scope === this.scope()) { this.loading = false; this.render(); }
    }
  }
}
