import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ModalFlow, PopupController, waitForMotion
} from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/ui-controller.js';

test('motion without active animations completes without another frame', async (t) => {
  t.mock.method(globalThis, 'requestAnimationFrame', () => {
    assert.fail('No frame is needed to discover CSS animations');
  });
  await waitForMotion(null, {}, { getAnimations: () => [] });
});

test('motion waits for every animation and tolerates cancellation', async () => {
  const entering = Promise.withResolvers();
  const resizing = Promise.withResolvers();
  let completed = false;
  const motion = waitForMotion(
    { getAnimations: () => [{ finished: entering.promise }] },
    { getAnimations: () => [{ finished: resizing.promise }] }
  ).then(() => { completed = true; });
  entering.resolve();
  await Promise.resolve();
  assert.equal(completed, false);
  resizing.reject(new Error('Animation cancelled'));
  await motion;
  assert.equal(completed, true);
});

test('an open dialog can reset and close when CSS motion is absent', async () => {
  const dialog = {
    open: false, classList: classes(),
    style: { removeProperty() {}, setProperty() {} },
    getAnimations: () => [],
    showModal() { this.open = true; },
    close() { this.open = false; }
  };
  const stage = {
    classList: classes(), dataset: {},
    replaceChildren(node) { this.firstElementChild = node || null; }
  };
  let closed = 0;
  const flow = new ModalFlow({
    dialog, stage, title: { focus() {} }, createPanel: () => ({}),
    prepare() {}, closed() { closed += 1; }
  });
  assert.equal(await flow.open('settings', {}, true), true);
  assert.equal(await flow.open('other', {}, true), true);
  assert.equal(flow.transitioning, false);
  assert.equal(flow.current.name, 'other');
  assert.equal(await flow.close(), true);
  assert.equal(closed, 1);
  assert.equal(flow.current, null);
  assert.equal(dialog.open, false);
});

test('navigation replaces one panel immediately while motion is active', async () => {
  const pending = new Promise(() => {});
  const properties = new Map();
  let measurements = 0;
  const dialog = {
    open: false, classList: classes(),
    style: {
      setProperty: (key, value) => properties.set(key, value),
      removeProperty: (key) => properties.delete(key)
    },
    get offsetHeight() { measurements += 1; return 448; },
    getAnimations: () => [{ finished: pending }],
    showModal() { this.open = true; }, close() { this.open = false; }
  };
  const stage = { replaceChildren(node) { this.children = node ? [node] : []; } };
  const flow = new ModalFlow({ dialog, stage, title: { focus() {} },
    createPanel: ({ name }) => ({ name, classList: classes() }),
    prepare() {}
  });
  await flow.open('settings', {}, true);
  for (let i = 0; i < 20; i += 1) {
    assert.equal(await flow.open('rules'), true);
    assert.equal(stage.children.length, 1);
    assert.equal(stage.children[0].name, 'rules');
    assert.equal(await flow.back(), true);
    assert.equal(stage.children[0].name, 'settings');
  }
  assert.equal(measurements, 1);
  assert.equal(properties.get('--modal-session-height'), '448px');
  assert.equal(flow.transitioning, false);
  flow.reset();
  assert.equal(properties.size, 0);
});

function classes() {
  const values = new Set();
  return {
    add: (...names) => names.forEach((name) => values.add(name)),
    remove: (...names) => names.forEach((name) => values.delete(name)),
    contains: (name) => values.has(name),
    toggle(name, active) {
      if (active) values.add(name);
      else values.delete(name);
    }
  };
}

function setup(t, rect, height = 78) {
  t.mock.method(globalThis, 'requestAnimationFrame', (callback) => {
    callback();
    return 1;
  });
  const viewport = { width: 390, height: 640, offsetTop: 0, offsetLeft: 0 };
  const priorWindow = globalThis.window;
  globalThis.window = { innerWidth: 390, innerHeight: 640,
    visualViewport: viewport };
  t.after(() => { globalThis.window = priorWindow; });
  const attributes = new Map([['data-popup-menu', '']]);
  const measurements = { width: 0, height: 0 };
  const menu = {
    classList: classes(), hidden: true,
    style: { removeProperty(name) {
      delete this[name.replace(/-([a-z])/g, (_, char) => char.toUpperCase())];
    } },
    contains(node) { return node === this; },
    matches(selector) {
      return selector === ':popover-open' && this.shown;
    },
    setAttribute: (name, value) => attributes.set(name, value),
    hasAttribute: (name) => attributes.has(name),
    removeAttribute: (name) => attributes.delete(name),
    showPopover() { this.shown = true; },
    hidePopover() { this.shown = false; },
    querySelectorAll: () => [],
    get offsetWidth() {
      measurements.width += 1;
      return Number.parseFloat(this.style.width) || 220;
    },
    get offsetHeight() {
      measurements.height += 1;
      return Math.min(height, Number.parseFloat(this.style.maxHeight) || height);
    }
  };
  const trigger = {
    isConnected: true,
    getBoundingClientRect: () => ({ ...rect, width: rect.right - rect.left }),
    setAttribute(name, value) { this[name] = value; },
    focus() { this.focused = true; }
  };
  const popup = {
    classList: classes(), children: [menu],
    querySelector: () => trigger,
    getBoundingClientRect: trigger.getBoundingClientRect
  };
  const root = {
    classList: classes(), style: Object.freeze({}),
    addEventListener() {},
    querySelectorAll: () => popup.classList.contains('is-open') ? [popup] : [],
    querySelector: () => popup.classList.contains('is-open') ? popup : null
  };
  return { controller: new PopupController(root), popup, menu, trigger,
    viewport, root, measurements };
}

if (!globalThis.requestAnimationFrame)
  globalThis.requestAnimationFrame = () => 0;

test('popup uses the top layer without resizing or scrolling its modal', (t) => {
  const { controller, popup, menu, trigger, root } = setup(t,
    { left: 190, right: 290, top: 500, bottom: 532 });
  controller.setOpen(popup, true);
  assert.equal(menu.shown, true);
  assert.equal(menu.style.top, '538px');
  assert.equal(menu.style.left, '190px');
  assert.equal(menu.style.width, '100px');
  assert.equal(trigger['aria-expanded'], 'true');
  assert.equal(controller.popupFor(menu), popup);
  assert.deepEqual(root.style, {});
  controller.closeActive();
  assert.equal(menu.shown, false);
  assert.equal(menu.hidden, true);
  assert.equal(menu.hasAttribute('popover'), false);
  assert.equal(controller.floating, null);
  assert.equal(menu.style.top, undefined);
  assert.equal(trigger.focused, true);
});

test('popup flips at the viewport edge, not at the modal footer', (t) => {
  const { controller, popup, menu } = setup(t,
    { left: 290, right: 390, top: 590, bottom: 622 });
  controller.setOpen(popup, true);
  assert.equal(menu.classList.contains('is-above'), true);
  assert.equal(menu.style.top, '506px');
  assert.equal(menu.style.left, '282px');
});

test('popup bounds its own scroll area when the keyboard reduces space', (t) => {
  const { controller, popup, menu, viewport } = setup(t,
    { left: 40, right: 340, top: 100, bottom: 142 }, 360);
  viewport.height = 310;
  controller.setOpen(popup, true);
  assert.equal(menu.style.maxHeight, '154px');
  assert.equal(menu.style.top, '148px');
  assert.equal(menu.offsetHeight, 154);
  viewport.height = 640;
  controller.reposition();
  assert.equal(menu.style.maxHeight, '484px');
  assert.equal(menu.offsetHeight, 360);
});

test('detaching a popup trigger clears the open menu owner', (t) => {
  const { controller, popup, trigger, menu } = setup(t,
    { left: 190, right: 290, top: 500, bottom: 532 });
  controller.setOpen(popup, true);
  trigger.isConnected = false;
  controller.reposition();
  assert.equal(menu.hidden, true);
  assert.equal(controller.floating, null);
});

test('legacy popup portal restores ownership and original position', (t) => {
  const { controller, popup, menu, root } = setup(t,
    { left: 190, right: 290, top: 500, bottom: 532 });
  let restored = null;
  const marker = { replaceWith(node) { restored = node; } };
  const previous = globalThis.document;
  globalThis.document = { createComment: () => marker };
  t.after(() => { globalThis.document = previous; });
  delete menu.showPopover;
  menu.before = (node) => assert.equal(node, marker);
  root.append = (node) => assert.equal(node, menu);
  root.getBoundingClientRect = () => ({ top: 100, left: 20 });
  controller.setOpen(popup, true);
  assert.equal(root.classList.contains('has-popup-fallback'), true);
  assert.equal(controller.parts(popup).menu, menu);
  assert.equal(controller.popupFor(menu), popup);
  assert.equal(menu.style.top, '438px');
  controller.closeAll();
  assert.equal(restored, menu);
  assert.equal(root.classList.contains('has-popup-fallback'), false);
  assert.equal(controller.floating, null);
});

test('settings menu fits its longest label while keeping the right anchor', (t) => {
  const { controller, popup, menu } = setup(t,
    { left: 190, right: 290, top: 300, bottom: 332 });
  const matches = menu.matches.bind(menu);
  menu.matches = (selector) => selector === '.setting-picker-menu' ||
    matches(selector);
  controller.setOpen(popup, true);
  assert.equal(menu.style.width, '220px');
  assert.equal(menu.style.left, '70px');
  assert.equal(menu.style.top, '338px');
});

test('popup measures content once while viewport positioning stays live', (t) => {
  const { controller, popup, measurements } = setup(t,
    { left: 190, right: 290, top: 300, bottom: 332 });
  controller.setOpen(popup, true);
  for (let index = 0; index < 10; index += 1) controller.reposition();
  assert.deepEqual(measurements, { width: 1, height: 1 });
  controller.invalidate(popup);
  assert.deepEqual(measurements, { width: 2, height: 2 });
});
