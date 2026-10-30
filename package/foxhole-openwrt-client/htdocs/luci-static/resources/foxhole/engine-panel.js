const IDS = ['vless', 'vmess', 'hysteria2', 'tuic', 'trojan', 'shadowsocks',
  'wireguard', 'naive', 'anytls', 'shadowtls', 'socks', 'http'];
const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED']);
const STATES = new Set(['QUEUED', 'DOWNLOADING', 'VERIFYING', 'INSTALLING', 'CHECKING', 'RECONNECTING', ...TERMINAL]);
const STEPS = new Set(["PREPARING", "DOWNLOADING_INDEX", "DOWNLOADING_PACKAGE", "VERIFYING_PACKAGE", "INSTALLING_PACKAGE", "CHECKING_ENGINE", "SWITCHING_ENGINE", "RECONNECTING_VPN", "COMPLETED", "FAILED", "RECOVERY_REQUIRED"]);
const sha = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function engineStatus(value) {
  if (!value || value.schema !== 1 || typeof value.busy !== 'boolean' || !sha(value.routerId) || !sha(value.catalogSha256) ||
      !Number.isInteger(value.revision) || value.revision < 0 ||
      !Array.isArray(value.entries) || value.entries.length > 12) throw new Error('invalid-engine-status');
  const seen = new Set();
  for (const row of value.entries) {
    if (!IDS.includes(row.id) || seen.has(row.id) || typeof row.installed !== 'boolean' ||
        !['AVAILABLE', 'NOT_RELEASED', 'UNSUPPORTED_TARGET'].includes(row.availability))
      throw new Error('invalid-engine-status');
    seen.add(row.id);
  }
  return value;
}

export function enginePlan(value, status, operation, id) {
  if (!value || value.schema !== 1 || value.routerId !== status.routerId ||
      value.revision !== status.revision || value.operation !== operation ||
      !sha(value.planSha256) || !/^engine-plan-[a-f0-9]{32}$/.test(value.planId) ||
      JSON.stringify(value.engineIds) !== JSON.stringify([id]) ||
      !['KEEP_ACTIVE', 'RECONNECT_REQUIRED'].includes(value.impact) ||
      !Number.isInteger(value.expiresAtUptimeMs) || typeof value.bootId !== 'string' ||
      value.confirmationRequired !== true || !Array.isArray(value.changes) || value.changes.length !== 1 ||
      value.changes[0].id !== id || !['FLASH', 'RAM'].includes(value.changes[0].storage) ||
      !value.budget || !['downloadBytes', 'stagingBytes', 'flashRequiredBytes', 'ramRequiredBytes',
        'flashAvailableBytes', 'ramAvailableBytes', 'reservedBytes'].every((key) =>
        Number.isSafeInteger(value.budget[key]) && value.budget[key] >= 0))
    throw new Error('invalid-engine-plan');
  return value;
}

export class EnginePanel {
  constructor({ call, text, element, icon, show, scope, error, notice }) {
    Object.assign(this, { call, text, element, icon, show, scope, error, notice });
    this.sequence = 0;
    this.current = null;
    this.plan = null;
    this.job = null;
    this.pending = false;
    this.timer = null;
  }

  close() {
    this.sequence += 1;
    clearTimeout(this.timer);
    this.plan = null;
    this.current = null;
    this.job = null;
    this.pending = false;
  }

  fresh(sequence, scope) { return sequence === this.sequence && scope === this.scope(); }

  async open() {
    const sequence = ++this.sequence, scope = this.scope();
    try {
      const value = engineStatus(await this.call('engines.status'));
      if (!this.fresh(sequence, scope)) return;
      this.current = value;
      this.renderList();
    } catch (error) { if (this.fresh(sequence, scope)) this.error(error); }
  }

  button(action, label, id, operation) {
    const node = this.element('button', 'outline-button', this.text(label));
    node.type = 'button';
    node.dataset.action = action;
    if (id) node.dataset.id = id;
    if (operation) node.dataset.operation = operation;
    node.disabled = this.pending || this.current?.busy;
    return node;
  }

  renderList() {
    const list = document.querySelector('[data-engine-list]');
    if (!list || !this.current) return;
    list.replaceChildren();
    const job = this.current.activeOwnJob || this.current.lastOwnJob;
    if (job) {
      const show = this.button('engine-job', 'engines.show_job');
      show.disabled = false;
      list.append(show);
    }
    const rows = this.current.entries.filter((row) => row.availability === 'AVAILABLE' || row.installed);
    if (!rows.length) list.append(this.element('p', 'muted', this.text('engines.not_released')));
    for (const row of rows) {
      const node = this.element('div', 'setting-row engine-row');
      const copy = this.element('span', 'setting-copy');
      copy.append(this.element('strong', '', this.text(`protocol.${row.id}`)),
        this.element('small', '', this.text(row.installed ? 'engines.installed' : 'engines.available')));
      node.append(this.icon('network'), copy);
      if (row.availability === 'AVAILABLE' && (!row.installed || row.updateAvailable))
        node.append(this.button('engine-plan', row.installed ? 'action.update' : 'action.add', row.id,
          row.installed ? 'UPDATE' : 'ADD'));
      if (row.installed && row.binarySha256) {
        const remove = this.button('engine-plan', 'action.delete', row.id, 'REMOVE');
        remove.classList.add('is-danger');
        remove.disabled ||= row.active;
        node.append(remove);
      }
      list.append(node);
    }
  }

  async prepare(id, operation) {
    if (!this.current || this.pending || this.current.busy) return;
    const scope = this.scope(), sequence = this.sequence;
    this.pending = true;
    this.renderList();
    try {
      const storage = document.querySelector('[data-engine-storage]')?.value || 'AUTO';
      const value = await this.call('engines.plan', { operation, engineIds: [id], storage,
        expectedRevision: this.current.revision, catalogSha256: this.current.catalogSha256 });
      if (!this.fresh(sequence, scope)) return;
      this.plan = enginePlan(value, this.current, operation, id);
      this.pending = false;
      await this.show('engine-plan');
    } catch (error) { if (this.fresh(sequence, scope)) this.error(error); }
    finally { if (this.fresh(sequence, scope)) { this.pending = false; this.renderList(); } }
  }

  renderPlan() {
    const root = document.querySelector('[data-engine-plan]');
    if (!root || !this.plan) return;
    root.replaceChildren();
    const label = this.plan.engineIds.map((id) => this.text(`protocol.${id}`)).join(', ');
    root.append(this.element('strong', '', label));
    const table = this.element('dl', 'engine-budget');
    for (const [key, value] of [['download', this.plan.budget.downloadBytes],
      ['flash', this.plan.budget.flashRequiredBytes], ['ram', this.plan.budget.ramRequiredBytes]]) {
      table.append(this.element('dt', '', this.text(`engines.${key}`)),
        this.element('dd', '', `${Math.ceil(value / 1024)} KiB`));
    }
    root.append(table, this.element('p', 'muted', this.text(this.plan.impact === 'RECONNECT_REQUIRED'
      ? 'engines.confirm_reconnect' : 'engines.confirm')));
  }

  async apply() {
    if (!this.plan || this.pending) return;
    const value = this.plan, sequence = this.sequence, scope = this.scope();
    this.pending = true;
    try {
      const job = await this.call('engines.apply', { planId: value.planId,
        planSha256: value.planSha256, expectedRevision: value.revision, confirmed: true });
      if (!this.fresh(sequence, scope)) return;
      if (job.planId !== value.planId) throw new Error('invalid-engine-job');
      this.acceptJob(job);
      this.pending = false;
      await this.show('engine-progress');
      this.renderJob();
    } catch (error) { if (this.fresh(sequence, scope)) this.error(error); }
    finally { if (this.fresh(sequence, scope)) this.pending = false; }
  }

  acceptJob(value) {
    if (!value || value.routerId !== this.current?.routerId ||
        !/^engine-job-[a-f0-9]{32}$/.test(value.jobId) ||
        !Number.isInteger(value.progressPercent) || value.progressPercent < 0 || value.progressPercent > 100 ||
        !STATES.has(value.state) || !STEPS.has(value.step) || !/^engine-plan-[a-f0-9]{32}$/.test(value.planId))
      throw new Error('invalid-engine-job');
    this.job = value;
  }

  async showJob() {
    const ref = this.current?.activeOwnJob || this.current?.lastOwnJob;
    if (!ref || this.pending) return;
    const sequence = this.sequence, scope = this.scope();
    try {
      const value = await this.call('engines.job', { jobId: ref.jobId });
      if (!this.fresh(sequence, scope)) return;
      if (value.jobId !== ref.jobId) throw new Error('invalid-engine-job');
      this.acceptJob(value);
      await this.show('engine-progress');
      this.renderJob();
    } catch (error) { if (this.fresh(sequence, scope)) this.error(error); }
  }

  renderJob() {
    clearTimeout(this.timer);
    const root = document.querySelector('[data-engine-progress]');
    if (!root || !this.job) return;
    root.replaceChildren();
    const progress = this.element('progress', 'engine-progress');
    progress.max = 100;
    progress.value = this.job.progressPercent;
    progress.setAttribute('aria-label', this.text('engines.progress'));
    root.append(progress, this.element('strong', '', `${this.job.progressPercent}%`),
      this.element('p', 'muted', this.text(`engines.step.${this.job.step}`)));
    if (this.job.failureReason) root.append(this.element('p', 'is-danger',
      this.text(`error.engine_${this.job.failureReason.toLowerCase()}`)));
    if (TERMINAL.has(this.job.state)) return;
    const sequence = this.sequence, scope = this.scope(), id = this.job.jobId;
    this.timer = setTimeout(async () => {
      try {
        const value = await this.call('engines.job', { jobId: id });
        if (!this.fresh(sequence, scope) || !document.querySelector('[data-engine-progress]')) return;
        if (value.jobId !== id) throw new Error('invalid-engine-job');
        this.acceptJob(value);
        this.renderJob();
      } catch (error) { if (this.fresh(sequence, scope)) this.error(error); }
    }, 2000);
  }
}
