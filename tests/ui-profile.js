const report = document.createElement('output');
report.id = 'ui-profile';
report.hidden = true;
document.body.append(report);
const records = { clicks: [], longTasks: [], listReplacements: 0 };
const publish = () => { report.textContent = JSON.stringify(records); };
new MutationObserver((entries) => {
  records.listReplacements += entries.length;
  publish();
}).observe(document.querySelector('[data-server-list]'), { childList: true });
if (PerformanceObserver.supportedEntryTypes.includes('longtask')) {
  new PerformanceObserver((list) => {
    records.longTasks.push(...list.getEntries().map((entry) => ({
      start: entry.startTime, duration: entry.duration
    })));
    publish();
  }).observe({ type: 'longtask' });
}
document.addEventListener('click', (event) => {
  const action = event.target.closest('[data-action]')?.dataset.action;
  if (!action) return;
  const started = performance.now();
  const record = { action, firstFrame: null, maxGap: 0, heights: [] };
  records.clicks.push(record);
  let previous = started;
  const sample = () => {
    const now = performance.now();
    record.firstFrame ??= now - started;
    record.maxGap = Math.max(record.maxGap, now - previous);
    previous = now;
    const dialog = document.querySelector('dialog[open]');
    if (dialog) record.heights.push(dialog.offsetHeight);
    publish();
    if (now - started < 350) requestAnimationFrame(sample);
  };
  requestAnimationFrame(sample);
}, true);
publish();
