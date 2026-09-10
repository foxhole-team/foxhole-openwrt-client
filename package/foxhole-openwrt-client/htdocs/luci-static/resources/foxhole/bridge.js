const pending = new Map();
let sequence = 0;

const embedded = window.parent !== window;
const direct = /^https?:$/.test(location.protocol);
export const hasHost = embedded || direct;

export class PanelError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function settle(id, result, error) {
  const request = pending.get(id);
  if (!request) return;
  pending.delete(id);
  clearTimeout(request.timer);
  if (error) request.reject(new PanelError(error));
  else request.resolve(result);
}

window.addEventListener('message', (event) => {
  if (!embedded || event.origin !== location.origin || event.source !== parent) return;
  const message = event.data;
  if (!message || message.source !== 'foxhole-host') return;
  settle(message.id, message.result,
    message.error ? message.error.code || 'unavailable' : null);
});

function frameRequest(action, payload) {
  const id = `foxhole-${Date.now()}-${++sequence}`;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => settle(id, null, 'unavailable'), 15000);
    pending.set(id, { resolve, reject, timer, controller: null });
    parent.postMessage({ source: 'foxhole-panel', id, action, payload },
      location.origin);
  });
}

function directRequest(action, payload) {
  const id = `foxhole-${Date.now()}-${++sequence}`;
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      controller.abort();
      settle(id, null, 'unavailable');
    }, 15000);
    pending.set(id, { resolve, reject, timer, controller });
    void fetch('/cgi-bin/foxhole', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, payload }),
      cache: 'no-store',
      credentials: 'same-origin',
      signal: controller.signal
    }).then(async (response) => {
      let result;
      try { result = await response.json(); }
      catch { settle(id, null, 'unavailable'); return; }
      if (result?._foxhole_error) {
        settle(id, null, String(result._foxhole_error).slice(0, 48));
      } else if (!response.ok) settle(id, null, 'unavailable');
      else settle(id, result || {}, null);
    }).catch((error) => {
      if (error?.name !== 'AbortError') settle(id, null, 'unavailable');
    });
  });
}

export function request(action, payload = {}) {
  if (!hasHost) return Promise.reject(new PanelError('host_required'));
  return embedded ? frameRequest(action, payload) : directRequest(action, payload);
}

export function cancelPending() {
  for (const [id, request] of pending) {
    request.controller?.abort();
    settle(id, null, 'locked');
  }
}
