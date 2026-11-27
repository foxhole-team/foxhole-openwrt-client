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
  if ('coreAvailability' in v && !['UNKNOWN', 'CURRENT', 'AVAILABLE'].includes(v.coreAvailability) ||
      'coreCohortRelay' in v && ![0, 1].includes(v.coreCohortRelay) ||
      'coreCohortSha256' in v && v.coreCohortSha256 !== null && !sha(v.coreCohortSha256) ||
      ['CURRENT', 'AVAILABLE'].includes(v.coreAvailability) && !sha(v.coreCohortSha256) ||
      'deviceDownloadKind' in v && !['BASE', 'CORE'].includes(v.deviceDownloadKind) ||
      v.deviceDownloadRequired === true && v.deviceDownloadKind === 'CORE' && v.coreCohortRelay !== 1) invalid();
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
  for (const job of [v.activeOwnJob, v.lastOwnJob]) {
    if (job && ('routerId' in job || 'schema' in job)) updateJob(job, v.routerId);
  }
  if (v.activeOwnJob && v.activeAutomaticJob) invalid();
  if (v.activeAutomaticJob !== null) {
    const job = v.activeAutomaticJob;
    if (job.automatic !== true || !['CHECK', 'APPLY'].includes(job.operation) || !STATES.has(job.state) || TERMINAL.has(job.state) ||
        !STEPS.has(job.step) || !integer(job.progressPercent) || job.progressPercent > 100 || !failure(job.failureReason) ||
        'jobId' in job || 'owner' in job) invalid();
  }
  return v;
}
function verifiedCurrent(value) {
  return value.supported === true && value.failureReason === null && value.coreAvailability !== 'AVAILABLE' && version(value.currentVersion) &&
    value.currentVersion === value.availableVersion && Number.isSafeInteger(value.lastCheckedAtUnixMs) && value.lastCheckedAtUnixMs > 0;
}
function verifiedAvailable(value) {
  return value?.supported === true && value.availability === 'AVAILABLE' && integer(value.lastCheckedAtUnixMs) &&
    value.lastCheckedAtUnixMs > 0 && version(value.availableVersion) && version(value.currentVersion) &&
    (value.availableVersion !== value.currentVersion || value.coreAvailability === 'AVAILABLE' && sha(value.coreCohortSha256));
}
export function updatePlan(plan, status) {
  if (!verifiedAvailable(status) || status.busy || status.activeOwnJob || status.activeAutomaticJob || status.failureReason ||
      !plan || plan.schema !== 1 || plan.routerId !== status.routerId || plan.revision !== status.revision ||
      plan.confirmationRequired !== true || !/^update-plan-[a-f0-9]{32}$/.test(plan.planId) || !sha(plan.planSha256) ||
      !integer(plan.expiresAtUptimeMs) || plan.expiresAtUptimeMs === 0 || typeof plan.bootId !== 'string' ||
      !/^[a-zA-Z0-9-]{1,96}$/.test(plan.bootId) || plan.fromVersion !== status.currentVersion ||
      plan.toVersion !== status.availableVersion || !['RECONNECT_REQUIRED','KEEP_ACTIVE'].includes(plan.impact)) invalid();
  const modules = new Map(status.installedModules.map(row => [row.id,row]));
  if (!Array.isArray(plan.engineIds) || plan.engineIds.length !== modules.size ||
      new Set(plan.engineIds).size !== modules.size || !plan.engineIds.every(id => modules.has(id)) ||
      !Array.isArray(plan.changes) || !plan.changes.length || plan.changes.length > modules.size + 1) invalid();
  const changed = new Set();
  for (const row of plan.changes) {
    if (!row || changed.has(row.id) || !version(row.fromVersion) || !version(row.toVersion) || row.fromVersion === row.toVersion) invalid();
    changed.add(row.id);
    if (row.id === 'foxhole') {
      if (row.storage !== null || row.fromVersion !== plan.fromVersion || row.toVersion !== plan.toVersion ||
          plan.impact !== 'RECONNECT_REQUIRED') invalid();
    } else {
      const installed = modules.get(row.id);
      if (!installed || installed.storage !== row.storage || installed.version !== row.fromVersion) invalid();
    }
  }
  if (changed.has('foxhole') !== (plan.fromVersion !== plan.toVersion)) invalid();
  for (const field of ['downloadBytes','stagingBytes','flashRequiredBytes','ramRequiredBytes','flashAvailableBytes','ramAvailableBytes'])
    if (!integer(plan.budget?.[field])) invalid();
  if (plan.budget.flashRequiredBytes > plan.budget.flashAvailableBytes || plan.budget.ramRequiredBytes > plan.budget.ramAvailableBytes) invalid();
  return plan;
}
export function availabilityLabel(value, text) {
  if (value.availability === 'NOT_CHECKED' && value.coreAvailability === 'CURRENT') return text('updates.core_up_to_date');
  if (value.availability === 'NOT_CHECKED') return '';
  if (value.availability === 'AVAILABLE' && !verifiedAvailable(value)) return text('updates.check_failed');
  if (value.availability === 'CURRENT') return text(verifiedCurrent(value) ? 'updates.up_to_date' :
    value.supported === false ? 'updates.unsupported' : 'updates.check_failed');
  return text(`updates.${value.availability.toLowerCase()}`);
}
export async function initializeUpdatePolicy(eligible, enabled, call) {
  if (eligible !== true) return { initialized: false };
  if (typeof enabled !== 'boolean') throw new Error('invalid-update-policy-choice');
  const current = updateStatus(await call('updates.status'));
  if (current.autoUpdate.configured !== false) return { initialized: false, status: current };
  const saved = updateStatus(await call('updates.settings', {
    expectedRevision: current.revision, autoUpdateEnabled: enabled
  }));
  return { initialized: true, status: saved };
}

export function updateBadgeKey(value) {
  if (!value?.supported || value.busy || value.activeOwnJob || value.activeAutomaticJob || (!integer(value.lastCheckedAtUnixMs) || value.lastCheckedAtUnixMs === 0)) return null;
  if (verifiedAvailable(value)) return 'updates.badge_available';
  return null;
}

export class UpdatePanel {
  constructor({ call, text, element, icon, scope, error, confirmPlan }) {
    Object.assign(this, { call, text, element, icon, scope, error, confirmPlan });
    this.cache = null; this.statusRequest = null; this.warmedScope = null; this.recheck = null;
    this.sequence = 0; this.current = null; this.job = null;
    this.pending = false; this.reading = false; this.uncertain = false; this.timer = null;
  }
  close() {
    this.sequence++; clearTimeout(this.timer);
    this.current = this.job = null;
    this.pending = this.reading = this.uncertain = false;
  }
  fresh(sequence, scope) { return sequence === this.sequence && scope === this.scope(); }
  cached() {
    return this.cache?.scope === this.scope() && performance.now() - this.cache.readAt < 300000 ? this.cache.value : null;
  }
  forget() { this.cache = this.statusRequest = this.warmedScope = this.recheck = null; }
  status() {
    const scope = this.scope();
    if (this.statusRequest?.scope === scope) return this.statusRequest.promise;
    const promise = this.call('updates.status').then(updateStatus).then(value => {
      if (this.scope() === scope && this.statusRequest?.promise === promise) this.cache = { scope, value, readAt:performance.now() };
      return value;
    }).finally(() => { if (this.statusRequest?.promise === promise) this.statusRequest = null; });
    this.statusRequest = { scope, promise };
    return promise;
  }
  async warm() {
    const scope = this.scope();
    if (this.warmedScope === scope) return;
    this.warmedScope = scope;
    try {
      const value = await this.status();
      if (scope !== this.scope() || !value.supported || value.busy || value.activeOwnJob || value.activeAutomaticJob ||
          !value.autoUpdate.enabled || value.autoUpdate.suspendedReason || value.availability === 'AVAILABLE') return;
      const last = Math.max(value.lastCheckedAtUnixMs || 0, value.autoUpdate.lastAttemptAtUnixMs || 0);
      if (Date.now() - last < value.autoUpdate.intervalSeconds * 1000) return;
      const accepted = updateJob(await this.call('updates.check', {expectedRevision:value.revision}), value.routerId);
      if (scope === this.scope() && accepted.operation === 'CHECK') await this.status();
    } catch { /* The check is optional; opening Updates can always read the current status. */ }
  }
  async open(reportError = false) {
    const sequence = ++this.sequence, scope = this.scope();
    clearTimeout(this.timer);
    this.current = this.cached(); this.pending = false; this.reading = true; this.render();
    try {
      const value = await this.status();
      if (!this.fresh(sequence, scope)) return;
      let job = null;
      if (value.activeOwnJob) {
        const ref = value.activeOwnJob;
        job = updateJob(await this.call('updates.job', { jobId: ref.jobId }), value.routerId);
        if (!this.fresh(sequence, scope)) return;
        if (job.jobId !== ref.jobId || job.operation !== ref.operation || job.planId !== ref.planId) invalid();
      }
      this.current = value; this.job = job; this.uncertain = false;
    } catch (e) {
      if (this.fresh(sequence, scope)) { this.cache = this.current = this.job = null; if (reportError) this.error(e); }
    } finally {
      if (this.fresh(sequence, scope)) { this.reading = false; this.render(); this.poll(sequence, scope); }
    }
  }
  async summary() {
    const sequence = this.sequence, scope = this.scope();
    const node = document.querySelector('[data-update-summary]');
    if (!node) return;
    const slot = node.parentElement;
    const paint = value => {
      const key = updateBadgeKey(value);
      node.hidden = !key;
      node.textContent = key ? this.text(key) : '';
      if (key) { node.dataset.updateState = 'available'; node.dataset.i18n = key; }
      else { delete node.dataset.i18n; delete node.dataset.updateState; }
    };
    paint(this.cached());
    slot.setAttribute('aria-busy', 'true');
    try {
      const value = await this.status();
      if (this.fresh(sequence, scope) && node.isConnected) paint(value);
    } catch {
      if (this.fresh(sequence, scope) && node.isConnected) { this.cache = null; paint(null); }
    } finally { slot.removeAttribute('aria-busy'); }
  }
  activeJob() {
    const value = this.current;
    if (!value) return null;
    if (value.activeAutomaticJob) return value.activeAutomaticJob;
    const ref = value.activeOwnJob;
    if (!ref) return null;
    const job = this.job?.jobId === ref.jobId ? this.job : ref;
    return TERMINAL.has(job.state) ? null : job;
  }
  async action(name, payload = {}) {
    if (this.pending || this.reading || !['check','settings'].includes(name)) return;
    if (name === 'check' && (!this.current || this.uncertain)) return this.open(true);
    const previous = this.current;
    if (!previous?.supported || this.uncertain) return;
    if (name === 'check' && (previous.busy || previous.activeOwnJob || previous.activeAutomaticJob)) return;
    if (name === 'settings' && (typeof payload.autoUpdateEnabled !== 'boolean' ||
        payload.autoUpdateEnabled === previous.autoUpdate.enabled)) return;
    const sequence = ++this.sequence, scope = this.scope();
    this.cache = this.statusRequest = null;
    clearTimeout(this.timer); this.pending = true; this.render();
    try {
      if (name === 'settings') {
        const value = updateStatus(await this.call('updates.settings', {
          expectedRevision: previous.revision, autoUpdateEnabled: payload.autoUpdateEnabled
        }));
        if (!this.fresh(sequence, scope)) return;
        if (value.routerId !== previous.routerId || value.revision <= previous.revision ||
            value.autoUpdate.enabled !== payload.autoUpdateEnabled) invalid();
        this.current = value; this.cache = {scope, value, readAt:performance.now()}; this.job = null;
      } else {
        const value = await this.call('updates.check', { expectedRevision: previous.revision });
        if (!this.fresh(sequence, scope)) return;
        const accepted = updateJob(value, previous.routerId);
        if (accepted.operation !== 'CHECK') invalid();
        await this.open(true);
      }
    } catch (e) {
      if (this.fresh(sequence, scope)) { this.uncertain = true; this.error(e); }
    } finally {
      if (this.fresh(sequence, scope)) { this.pending = false; this.render(); this.poll(sequence, scope); }
    }
  }
  poll(sequence, scope) {
    const v = this.current;
    if (!this.fresh(sequence, scope) || this.uncertain || !v ||
        !(v.activeOwnJob || v.activeAutomaticJob || (v.busy && v.failureReason !== 'RECOVERY_REQUIRED'))) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => { if (this.fresh(sequence, scope)) void this.open(); }, 2000);
  }
  primaryAction() {
    const v = this.current;
    const needsCheck = v && this.recheck?.scope === this.scope() && this.recheck.router === v.routerId && this.recheck.revision === v.revision;
    const install = !this.uncertain && !needsCheck && updateBadgeKey(v) !== null;
    return { install, disabled:this.pending || this.reading || (!this.uncertain && !!v &&
      (!v.supported || v.busy || !!v.activeOwnJob || !!v.activeAutomaticJob ||
       install && (!!v.failureReason || !!v.autoUpdate.suspendedReason))) };
  }
  renderFooter() {
    const button = document.querySelector('[data-update-primary]');
    if (!button) return;
    const {install,disabled} = this.primaryAction();
    const label = button.querySelector('[data-i18n]');
    label.dataset.i18n = install ? 'updates.update' : 'updates.check';
    label.textContent = this.text(label.dataset.i18n);
    button.querySelector('use').setAttribute('href', install ? '#icon-download' : '#icon-refresh');
    button.dataset.action = install ? 'update-install' : 'update-check';
    button.disabled = disabled;
  }
  async install() {
    const action = this.primaryAction();
    if (!action.install || action.disabled) return;
    const previous = this.current, sequence = ++this.sequence, scope = this.scope();
    let submitted = false;
    clearTimeout(this.timer); this.pending = true; this.render();
    try {
      const raw = await this.call('updates.plan', {expectedRevision:previous.revision});
      if (!this.fresh(sequence,scope)) return;
      const plan = updatePlan(raw,previous);
      const changes = plan.changes.map(row => (row.id === 'foxhole' ? 'FoxHole OpenWrt' :
        this.text('protocol.'+row.id)+' ('+row.storage+')') + ': ' + row.fromVersion + ' → ' + row.toVersion);
      const lines = [this.text('updates.confirm_title'),this.text('updates.confirm'),...changes];
      if (plan.impact === 'RECONNECT_REQUIRED') lines.push(this.text('updates.reconnect'));
      if (this.confirmPlan?.(lines.join('\n')) !== true || !this.fresh(sequence,scope) || this.current !== previous) return;
      this.cache = this.statusRequest = null;
      submitted = true;
      const reply = await this.call('updates.apply', {planId:plan.planId,planSha256:plan.planSha256,
        expectedRevision:plan.revision,confirmed:true});
      if (!this.fresh(sequence,scope)) return;
      const accepted = updateJob(reply,previous.routerId);
      if (accepted.operation !== 'APPLY' || accepted.planId !== plan.planId) invalid();
      await this.open(true);
    } catch (error) {
      if (this.fresh(sequence,scope)) {
        this.recheck = {scope,router:previous.routerId,revision:previous.revision};
        if (submitted) this.uncertain = true;
        this.error(error);
      }
    } finally {
      if (this.fresh(sequence,scope)) { this.pending = false; this.render(); this.poll(sequence,scope); }
    }
  }
  render() {
    const root = document.querySelector('[data-update-detail]');
    if (!root) return;
    this.renderFooter();
    root.replaceChildren();
    const v = this.current, waiting = this.pending || this.reading;
    if (!v) {
      root.append(this.element('p', this.reading ? 'muted foxhole-loading' : 'muted', this.text(this.uncertain ? 'updates.uncertain' : this.reading ? 'updates.state_checking' : 'updates.unavailable')));
      return;
    }
    const job = this.activeJob(), idle = !this.pending && !this.uncertain && !v.busy && !v.activeOwnJob && !v.activeAutomaticJob;
    const current = idle && v.availability === 'CURRENT' && verifiedCurrent(v);
    const available = idle && updateBadgeKey(v) !== null;
    const versions = this.element('dl', 'engine-budget update-versions');
    for (const [key, value] of [['current', v.currentVersion], ['available_version', v.availableVersion]]) {
      const css = key === 'available_version' && available ? 'is-update-available' : '';
      versions.append(this.element('dt', css, this.text(`updates.${key}`)), this.element('dd', css, value || '—'));
    }
    root.append(versions);
    if (current || available) {
      const result = this.element('div', 'update-result');
      const mark = this.element('span', current ? 'success-mark' : 'download-mark');
      mark.setAttribute('aria-hidden','true'); mark.append(this.icon(current ? 'check' : 'download'));
      result.append(mark, this.element('p', '', this.text(current ? 'updates.up_to_date' : 'updates.required'))); root.append(result);
    } else if ((v.availability !== 'CURRENT' || idle) && !v.failureReason) {
      const label = availabilityLabel(v, this.text);
      if (label) root.append(this.element('p', 'muted', label));
    }
    if (v.failureReason) root.append(this.element('p', 'muted', this.text(`error.update_${v.failureReason.toLowerCase()}`)));
    const suspended = v.autoUpdate.suspendedReason;
    if (v.autoUpdate.enabled && suspended && suspended !== v.failureReason)
      root.append(this.element('p', 'muted', this.text(`error.update_${suspended.toLowerCase()}`)));
    if (job) {
      const state = job.step === 'CHECKING_RELEASE' && job.state === 'DOWNLOADING' ? 'CHECKING' : job.state;
      const transferring = job.state === 'DOWNLOADING' && ['DOWNLOADING_INDEX', 'DOWNLOADING_PACKAGE'].includes(job.step);
      root.append(this.element('p', transferring ? 'muted' : 'muted foxhole-loading', this.text(`updates.state_${state.toLowerCase()}`)));
      if (transferring) {
        const bar = this.element('progress', 'engine-progress'); bar.max = 100; bar.value = job.progressPercent;
        bar.setAttribute('aria-label', this.text('updates.progress'));
        root.append(bar, this.element('p', 'update-progress-label', `${job.progressPercent}%`));
      }
    }
    if (this.uncertain) root.append(this.element('p', 'muted', this.text('updates.uncertain')));
    const row = this.element('label', 'setting-row'), label = this.element('span', 'setting-copy');
    label.append(this.element('strong', '', this.text('updates.auto')));
    const control = this.element('input'); control.type = 'checkbox'; control.checked = v.autoUpdate.enabled;
    control.disabled = waiting || this.uncertain || !v.supported;
    control.addEventListener('change', () => void this.action('settings', { autoUpdateEnabled: control.checked }));
    const toggle = this.element('span', 'switch'), decoration = this.element('i');
    decoration.setAttribute('aria-hidden', 'true'); toggle.append(control, decoration); row.append(label, toggle);
    root.append(row);
  }
}
