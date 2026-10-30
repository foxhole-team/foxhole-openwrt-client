const IDS = new Set(['vless', 'hysteria2', 'wireguard']);
const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED']);
const STATES = new Set(['QUEUED', 'DOWNLOADING', 'VERIFYING', 'INSTALLING', 'CHECKING', 'RECONNECTING', ...TERMINAL]);
const STEPS = new Set(['PREPARING', 'CHECKING_RELEASE', 'DOWNLOADING_INDEX', 'DOWNLOADING_PACKAGE',
  'VERIFYING_PACKAGE', 'BACKING_UP', 'INSTALLING_PACKAGE', 'CHECKING_PACKAGE', 'RECONNECTING_VPN',
  'COMPLETED', 'FAILED', 'RECOVERY_REQUIRED']);
const REASONS = new Set(['UNSUPPORTED_TARGET', 'NOT_CHECKED', 'RELEASE_UNAVAILABLE', 'AUTHENTICATION_FAILED',
  'STALE_PLAN', 'STALE_SESSION', 'BUSY', 'NO_SPACE', 'DOWNLOAD_FAILED', 'PACKAGE_VERIFICATION_FAILED',
  'DOWNGRADE_REJECTED', 'VERSION_IDENTITY_CONFLICT', 'ROLLBACK_UNAVAILABLE', 'RAM_STAGE_UNAVAILABLE',
  'ROUTER_UNAVAILABLE', 'RECOVERY_REQUIRED', 'INVALID_REQUEST', 'LEGACY_CONNECTION_ACTIVE']);
const BUDGET = ['downloadBytes', 'stagingBytes', 'flashRequiredBytes', 'flashAvailableBytes',
  'ramRequiredBytes', 'ramAvailableBytes', 'reservedBytes'];
const sha = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const integer = v => Number.isSafeInteger(v) && v >= 0;
const version = v => typeof v === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.~+-]{0,159}$/.test(v);
const failure = v => v === null || REASONS.has(v);
function invalid() { throw new Error('invalid-update-response'); }
function ref(v) {
  if (!v || !/^update-job-[a-f0-9]{32}$/.test(v.jobId) || v.automatic !== false ||
      !['CHECK', 'APPLY'].includes(v.operation) || !STATES.has(v.state) || !STEPS.has(v.step) ||
      !integer(v.progressPercent) || v.progressPercent > 100 ||
      (v.operation === 'CHECK' ? v.planId !== null : !/^update-plan-[a-f0-9]{32}$/.test(v.planId))) invalid();
  return v;
}
export function updateJob(v, routerId) {
  ref(v);
  if (v.schema !== 1 || v.routerId !== routerId || !integer(v.revision) || !failure(v.failureReason) ||
      ![null, true, false].includes(v.previousConnectionRestored)) invalid();
  return v;
}
export function updateStatus(v) {
  if (!v || v.schema !== 1 || typeof v.supported !== 'boolean' || !sha(v.routerId) || !integer(v.revision) ||
      typeof v.busy !== 'boolean' || (v.supported && v.currentVersion === null) || (!v.supported && v.availability !== 'UNSUPPORTED') ||
      (v.supported && v.availability === 'UNSUPPORTED') ||
      (v.availability === 'CHECK_FAILED' && v.failureReason === null) || !['NOT_CHECKED', 'CURRENT', 'AVAILABLE', 'UNSUPPORTED', 'CHECK_FAILED'].includes(v.availability) ||
      !(v.currentVersion === null || version(v.currentVersion)) || !(v.availableVersion === null || version(v.availableVersion)) ||
      !(v.lastCheckedAtUnixMs === null || integer(v.lastCheckedAtUnixMs)) || !failure(v.failureReason) ||
      !Array.isArray(v.installedModules) || v.installedModules.length > 3) invalid();
  if (v.availability === 'CURRENT' && (!v.currentVersion || v.currentVersion !== v.availableVersion || v.failureReason !== null) ||
      v.availability === 'AVAILABLE' && (!v.currentVersion || !v.availableVersion ||
        ![null, 'LEGACY_CONNECTION_ACTIVE'].includes(v.failureReason))) invalid();
  const seen = new Set();
  for (const row of v.installedModules) {
    if (!IDS.has(row.id) || seen.has(row.id) || !['FLASH', 'RAM'].includes(row.storage) || !version(row.version)) invalid();
    seen.add(row.id);
  }
  const a = v.autoUpdate;
  if (!a || typeof a.enabled !== 'boolean' || a.intervalSeconds !== 86400 ||
      ![a.lastAttemptAtUnixMs, a.nextCheckAtUnixMs].every(x => x === null || integer(x)) ||
      !(a.suspendedReason === null || ['RECOVERY_REQUIRED', 'UNSUPPORTED_TARGET', 'ROLLBACK_UNAVAILABLE', 'RAM_STAGE_UNAVAILABLE', 'LEGACY_CONNECTION_ACTIVE'].includes(a.suspendedReason))) invalid();
  if (v.activeOwnJob !== null) { ref(v.activeOwnJob); if (TERMINAL.has(v.activeOwnJob.state)) invalid(); }
  if (v.lastOwnJob !== null) ref(v.lastOwnJob);
  if (v.activeAutomaticJob !== null) {
    const job = v.activeAutomaticJob;
    if (job.automatic !== true || !['CHECK', 'APPLY'].includes(job.operation) || !STATES.has(job.state) || TERMINAL.has(job.state) ||
        !STEPS.has(job.step) || !integer(job.progressPercent) || job.progressPercent > 100 || !failure(job.failureReason) ||
        'jobId' in job || 'owner' in job) invalid();
  }
  return v;
}
export function updatePlan(v, status) {
  if (!v || v.schema !== 1 || v.routerId !== status.routerId || v.revision !== status.revision ||
      !/^update-plan-[a-f0-9]{32}$/.test(v.planId) || !sha(v.planSha256) || v.confirmationRequired !== true ||
      v.fromVersion !== status.currentVersion || v.toVersion !== status.availableVersion ||
      !integer(v.expiresAtUptimeMs) || typeof v.bootId !== 'string' || !v.bootId ||
      !['KEEP_ACTIVE', 'RECONNECT_REQUIRED'].includes(v.impact) || !Array.isArray(v.changes) ||
      !v.changes.length || v.changes.length > 4 || !Array.isArray(v.engineIds) ||
      JSON.stringify([...v.engineIds].sort()) !== JSON.stringify(status.installedModules.map(x => x.id).sort()) ||
      !v.budget || Object.keys(v.budget).length !== 7 || !BUDGET.every(k => integer(v.budget[k]))) invalid();
  const seen = new Set();
  for (const row of v.changes) {
    if (seen.has(row.id) || !version(row.toVersion) || row.toVersion === row.fromVersion) invalid();
    seen.add(row.id);
    if (row.id === 'foxhole') {
      if (row.storage !== null || row.fromVersion !== status.currentVersion || row.toVersion !== status.availableVersion ||
          v.impact !== 'RECONNECT_REQUIRED') invalid();
    } else {
      const current = status.installedModules.find(x => x.id === row.id);
      if (!current || current.storage !== row.storage || current.version !== row.fromVersion) invalid();
    }
  }
  if (!seen.has('foxhole') && v.fromVersion !== v.toVersion) invalid();
  return v;
}

export class UpdatePanel {
  constructor({ call, text, element, show, scope, error }) {
    Object.assign(this, { call, text, element, show, scope, error });
    this.sequence = 0; this.current = null; this.plan = null; this.job = null;
    this.pending = false; this.uncertain = false; this.timer = null;
  }
  close() { this.sequence++; clearTimeout(this.timer); this.plan = null; this.pending = false; }
  fresh(sequence, scope) { return sequence === this.sequence && scope === this.scope(); }
  async open() {
    const sequence = ++this.sequence, scope = this.scope(); clearTimeout(this.timer);
    try {
      const result = updateStatus(await this.call('updates.status'));
      if (!this.fresh(sequence, scope)) return;
      this.current = result; this.plan = null;
      const owned = result.activeOwnJob || result.lastOwnJob;
      this.job = owned ? updateJob(await this.call('updates.job', { jobId: owned.jobId }), result.routerId) : null;
      if (!this.fresh(sequence, scope)) return;
      this.uncertain = false; this.render(); this.poll(sequence, scope);
    } catch (e) {
      if (this.fresh(sequence, scope)) { this.current = null; this.render(); this.error(e); }
    }
  }
  async summary() {
    const sequence = this.sequence, scope = this.scope();
    try {
      const value = updateStatus(await this.call('updates.status'));
      if (!this.fresh(sequence, scope)) return;
      const node = document.querySelector('[data-update-summary]');
      if (node) node.textContent = `${value.currentVersion || '—'} · ${this.text(`updates.${value.availability === 'CURRENT' ? 'up_to_date' : value.availability.toLowerCase()}`)}`;
    } catch { /* Older or unreachable packages never appear current. */ }
  }
  async action(name, payload = {}) {
    if (!this.current || this.pending || this.uncertain && name !== 'settings') return;
    const sequence = this.sequence, scope = this.scope();
    const previous = this.current;
    if (['plan', 'apply'].includes(name) && (previous.failureReason === 'LEGACY_CONNECTION_ACTIVE' || previous.busy)) {
      this.plan = null; this.render(); return;
    }
    this.pending = true; this.render();
    try {
      const result = await this.call(`updates.${name}`, { expectedRevision: previous.revision, ...payload });
      if (!this.fresh(sequence, scope)) return;
      if (name === 'settings') this.current = updateStatus(result);
      else if (name === 'plan') { this.plan = updatePlan(result, previous); await this.show('update-plan'); }
      else {
        const accepted = updateJob(result, previous.routerId);
        if (name === 'apply' && accepted.planId !== this.plan?.planId || name === 'check' && accepted.operation !== 'CHECK') invalid();
        this.job = accepted; this.plan = null;
      }
      this.pending = false; this.render();
      if (name === 'apply' || name === 'check') await this.open();
    } catch (e) {
      if (this.fresh(sequence, scope)) {
        // A lost write response is uncertainty. Only status/job reads may
        // resolve it.
        if (name === 'apply' || name === 'check') this.uncertain = true;
        this.error(e);
      }
    } finally { if (this.fresh(sequence, scope)) { this.pending = false; this.render(); } }
  }
  async apply() {
    if (!this.plan || this.pending || this.uncertain) return;
    await this.action('apply', { planId: this.plan.planId, planSha256: this.plan.planSha256, confirmed: true });
    if (!this.uncertain) await this.show('updates');
  }
  async poll(sequence, scope) {
    if (!this.fresh(sequence, scope)) return;
    const active = this.job && !TERMINAL.has(this.job.state) || this.current?.activeAutomaticJob;
    if (!active) return;
    this.timer = setTimeout(() => { if (this.fresh(sequence, scope)) void this.open(); }, 2000);
  }
  button(action, key, disabled) {
    const node = this.element('button', 'outline-button', this.text(key));
    node.type = 'button'; node.dataset.action = action; node.disabled = disabled; return node;
  }
  render() {
    const root = document.querySelector('[data-update-detail]');
    if (root) {
      root.replaceChildren(); const v = this.current;
      if (!v) { root.append(this.element('p', 'muted', this.text('updates.unavailable'))); return; }
      const versions = this.element('dl', 'engine-budget');
      for (const [key, value] of [['current', v.currentVersion], ['available_version', v.availableVersion]])
        versions.append(this.element('dt', '', this.text(`updates.${key}`)), this.element('dd', '', value || '—'));
      root.append(versions, this.element('p', 'muted', this.text(`updates.${v.availability === 'CURRENT' ? 'up_to_date' : v.availability.toLowerCase()}`)));
      if (v.failureReason) root.append(this.element('p', 'muted', this.text(`error.update_${v.failureReason.toLowerCase()}`)));
      if (v.autoUpdate.enabled && v.autoUpdate.suspendedReason && v.autoUpdate.suspendedReason !== v.failureReason)
        root.append(this.element('p', 'muted', this.text(`error.update_${v.autoUpdate.suspendedReason.toLowerCase()}`)));
      const job = this.job || v.activeAutomaticJob;
      if (job) {
        root.append(this.element('p', 'muted', this.text(`updates.state_${job.state.toLowerCase()}`)));
        const progress = this.element('progress', 'engine-progress'); progress.max = 100; progress.value = job.progressPercent;
        progress.setAttribute('aria-label', this.text('updates.progress')); root.append(progress);
      }
      const row = this.element('label', 'setting-row'); const label = this.element('span', 'setting-copy');
      label.append(this.element('strong', '', this.text('updates.auto'))); const control = this.element('input');
      control.type = 'checkbox'; control.checked = v.autoUpdate.enabled; control.disabled = this.pending || !v.supported;
      control.addEventListener('change', () => void this.action('settings', { autoUpdateEnabled: control.checked }));
      const toggle = this.element('span', 'switch'); const decoration = this.element('i');
      decoration.setAttribute('aria-hidden', 'true'); toggle.append(control, decoration);
      row.append(label, toggle); root.append(row, this.element('small', 'muted', this.text('updates.auto_detail')));
      const disabled = this.pending || this.uncertain || v.busy || !v.supported;
      root.append(this.button('update-check', 'updates.check', disabled),
        this.button('update-plan', 'updates.update', disabled || v.availability !== 'AVAILABLE' || v.failureReason === 'LEGACY_CONNECTION_ACTIVE'));
      if (this.uncertain) root.append(this.element('p', 'muted', this.text('updates.uncertain')),
        this.button('update-status', 'updates.status_only', this.pending));
    }
    const apply = document.querySelector('[data-action="update-apply"]');
    if (apply) apply.disabled = !this.plan || this.pending || this.uncertain;
    const planRoot = document.querySelector('[data-update-plan]');
    if (planRoot && this.plan) {
      planRoot.replaceChildren();
      for (const change of this.plan.changes) planRoot.append(this.element('p', '',
        `${change.id === 'foxhole' ? 'FoxHole' : change.id}: ${change.fromVersion} → ${change.toVersion}${change.storage ? ` · ${change.storage}` : ''}`));
      planRoot.append(this.element('p', 'muted', this.text(this.plan.impact === 'RECONNECT_REQUIRED' ? 'updates.reconnect' : 'updates.confirm')));
      const table = this.element('dl', 'engine-budget');
      for (const [key, bytes] of [['download', this.plan.budget.downloadBytes], ['flash', this.plan.budget.flashRequiredBytes], ['ram', this.plan.budget.ramRequiredBytes]])
        table.append(this.element('dt', '', this.text(`engines.${key}`)), this.element('dd', '', `${Math.ceil(bytes / 1024)} KiB`));
      planRoot.append(table);
    }
  }
}
