export async function waitForMotion(...elements) {
  const animations = elements.flatMap((element) =>
    element?.getAnimations?.() || []);
  await Promise.allSettled(animations.map((animation) =>
    animation.finished));
}

export class ModalFlow {
  constructor({ dialog, stage, title, createPanel, prepare, closed }) {
    this.dialog = dialog;
    this.stage = stage;
    this.title = title;
    this.createPanel = createPanel;
    this.prepare = prepare;
    this.closed = closed;
    this.views = [];
    this.transitioning = false;
  }

  get current() {
    return this.views.at(-1) || null;
  }

  find(name) {
    return [...this.views].reverse().find((view) => view.name === name);
  }

  async open(name, data = {}, reset = false) {
    if (this.transitioning) return false;
    if (reset) {
      this.dialog.style.removeProperty('--modal-session-height');
      this.views.length = 0;
      this.stage.replaceChildren();
    }
    this.views.push({ name, data });
    await this.paint(reset ? 'initial' : 'forward');
    return true;
  }

  async repaint(direction = 'forward') {
    if (this.transitioning || !this.current) return false;
    await this.paint(direction);
    return true;
  }

  async back() {
    if (this.transitioning) return false;
    if (this.views.length <= 1) return this.close();
    this.views.pop();
    await this.paint('back');
    return true;
  }

  paint(direction) {
    const view = this.current;
    if (!view) return;
    const next = this.createPanel(view);
    this.stage.replaceChildren(next);
    this.prepare(view, next);
    this.stage.scrollTop = 0;
    if (!this.dialog.open) {
      this.dialog.classList.add('is-opening');
      this.dialog.showModal();
    } else if (direction !== 'initial') {
      next.classList.add('is-entering');
    }
    if (direction === 'initial')
      this.dialog.style.setProperty('--modal-session-height',
        `${this.dialog.offsetHeight}px`);
    this.title.focus({ preventScroll: true });
  }

  async close() {
    if (this.transitioning || !this.dialog.open) return false;
    this.transitioning = true;
    this.dialog.classList.remove('is-opening');
    this.dialog.classList.add('is-closing');
    try {
      await waitForMotion(this.dialog);
      this.dialog.close();
      this.stage.replaceChildren();
      this.dialog.style.removeProperty('--modal-session-height');
      this.views.length = 0;
      await this.closed?.();
    } finally {
      this.dialog.classList.remove('is-closing');
      this.transitioning = false;
    }
    return true;
  }

  reset() {
    if (this.dialog.open) this.dialog.close();
    this.dialog.classList.remove('is-opening', 'is-closing',
      'has-open-popup');
    this.stage.replaceChildren();
    this.dialog.style.removeProperty('--modal-session-height');
    this.views.length = 0;
    this.transitioning = false;
  }
}

export class PopupController {
  constructor(root) {
    this.root = root;
    this.floating = null;
    this.frame = 0;
    root.addEventListener('scroll', (event) => {
      if (!this.floating ||
          this.floating.menu.contains(event.target) || this.frame) return;
      this.requestReposition();
    }, true);
  }

  popupFor(node) {
    if (this.floating?.menu.contains(node)) return this.floating.popup;
    return node?.closest?.('[data-popup]') || null;
  }

  parts(popup) {
    if (!popup) return {};
    if (this.floating?.popup === popup) return this.floating;
    const trigger = popup.querySelector('[data-popup-trigger]');
    const menu = [...popup.children].find((child) =>
      child.hasAttribute('data-popup-menu')) ||
      popup.querySelector(':scope > * > [data-popup-menu]');
    return { trigger, menu };
  }

  options(popup) {
    const { menu } = this.parts(popup);
    if (!menu) return [];
    return [...menu.querySelectorAll(
      'button:not(:disabled), input:not(:disabled), [tabindex="0"]')]
      .filter((node) => !node.closest('[hidden]'));
  }

  refresh() {
    this.root.classList.toggle('has-open-popup', Boolean(this.floating));
  }

  requestReposition() {
    if (!this.floating || this.frame) return;
    this.frame = requestAnimationFrame(() => {
      this.frame = 0;
      this.reposition();
    });
  }

  invalidate(popup) {
    if (this.floating?.popup !== popup) return;
    this.floating.naturalWidth = null;
    this.floating.naturalHeight = null;
    this.requestReposition();
  }

  place(popup, trigger, menu) {
    const triggerRect = trigger.getBoundingClientRect();
    const viewport = window.visualViewport;
    const edge = 8;
    const gap = 6;
    const viewportTop = viewport?.offsetTop || 0;
    const viewportLeft = viewport?.offsetLeft || 0;
    const viewportBottom = viewportTop +
      (viewport?.height || window.innerHeight);
    const viewportRight = viewportLeft +
      (viewport?.width || window.innerWidth);
    const anchor = menu.matches('.device-picker-menu')
      ? popup.getBoundingClientRect() : triggerRect;
    const origin = this.floating?.marker
      ? this.root.getBoundingClientRect() : { top: 0, left: 0 };
    if (this.floating?.naturalHeight == null) {
      menu.style.width = menu.matches('.setting-picker-menu')
        ? 'max-content' : `${anchor.width}px`;
      menu.style.maxHeight = 'none';
      this.floating.naturalWidth = menu.offsetWidth;
      this.floating.naturalHeight = menu.offsetHeight;
    }
    const naturalWidth = menu.matches('.setting-picker-menu')
      ? this.floating.naturalWidth : anchor.width;
    const width = Math.min(Math.max(anchor.width, naturalWidth),
      viewportRight - viewportLeft - edge * 2);
    menu.style.width = `${width}px`;
    const below = Math.max(0, viewportBottom - triggerRect.bottom - gap - edge);
    const above = Math.max(0, triggerRect.top - viewportTop - gap - edge);
    const isAbove = this.floating.naturalHeight > below && above > below;
    const available = isAbove ? above : below;
    const height = Math.min(this.floating.naturalHeight, available);
    menu.style.maxHeight = `${available}px`;
    menu.classList.toggle('is-above', isAbove);
    const top = isAbove ? triggerRect.top - gap - height
      : triggerRect.bottom + gap;
    const left = Math.max(viewportLeft + edge,
      Math.min(anchor.right - width, viewportRight - width - edge));
    menu.style.top = `${top - origin.top}px`;
    menu.style.left = `${left - origin.left}px`;
  }

  reposition() {
    if (!this.floating) return;
    const { popup, trigger, menu } = this.floating;
    if (!trigger.isConnected) this.closeAll();
    else this.place(popup, trigger, menu);
  }

  setOpen(popup, open, focus = false) {
    const { trigger, menu } = this.parts(popup);
    if (!trigger || !menu) return false;
    if (open) this.closeAll(popup);
    popup.classList.toggle('is-open', open);
    trigger.setAttribute('aria-expanded', String(open));
    menu.hidden = !open;
    if (open) {
      if (this.floating?.popup !== popup) {
        this.floating = {
          popup, trigger, menu, naturalWidth: null, naturalHeight: null
        };
        menu.classList.add('popup-surface');
        if (typeof menu.showPopover === 'function') {
          menu.setAttribute('popover', 'manual');
          menu.showPopover();
        } else {
          const marker = document.createComment('popup');
          menu.before(marker);
          this.floating.marker = marker;
          this.root.append(menu);
          this.root.classList.add('has-popup-fallback');
        }
      }
      this.place(popup, trigger, menu);
    } else {
      if (menu.hasAttribute('popover')) {
        if (menu.matches(':popover-open')) menu.hidePopover();
        menu.removeAttribute('popover');
      }
      if (this.floating?.popup === popup) {
        this.floating.marker?.replaceWith(menu);
        this.root.classList.remove('has-popup-fallback');
      }
      menu.classList.remove('popup-surface', 'is-above');
      for (const property of ['width', 'max-height', 'top', 'left'])
        menu.style.removeProperty(property);
      if (this.floating?.popup === popup) this.floating = null;
    }
    this.refresh();
    if (open && focus) {
      const options = this.options(popup);
      const selected = options.find((node) =>
        node.getAttribute('aria-selected') === 'true' || node.checked);
      (selected || options[0])?.focus({ preventScroll: true });
    }
    return true;
  }

  toggle(trigger, focus = true) {
    const popup = this.popupFor(trigger);
    if (!popup) return false;
    return this.setOpen(popup, !popup.classList.contains('is-open'),
      focus);
  }

  closeAll(except = null) {
    if (this.floating && this.floating.popup !== except)
      this.setOpen(this.floating.popup, false);
  }

  closeActive(restoreFocus = true) {
    if (!this.floating) return false;
    const { popup, trigger } = this.floating;
    this.setOpen(popup, false);
    if (restoreFocus) trigger?.focus({ preventScroll: true });
    return true;
  }

  closeOutside(target) {
    const popup = this.popupFor(target);
    this.closeAll(popup?.classList.contains('is-open') ? popup : null);
  }

  moveFocus(popup, current, offset) {
    const options = this.options(popup);
    if (!options.length) return;
    const index = options.indexOf(current);
    options[(index + offset + options.length) % options.length]
      .focus({ preventScroll: true });
  }

  keydown(event) {
    const trigger = event.target.closest?.('[data-popup-trigger]');
    if (trigger && ['ArrowDown', 'ArrowUp'].includes(event.key)) {
      event.preventDefault();
      const popup = this.popupFor(trigger);
      this.setOpen(popup, true);
      const options = this.options(popup);
      options[event.key === 'ArrowDown' ? 0 : options.length - 1]
        ?.focus({ preventScroll: true });
      return true;
    }

    const popup = this.popupFor(event.target);
    if (!popup?.classList.contains('is-open')) return false;
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      this.setOpen(popup, false);
      this.parts(popup).trigger?.focus({ preventScroll: true });
      return true;
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      this.moveFocus(popup, event.target,
        event.key === 'ArrowDown' ? 1 : -1);
      return true;
    }
    if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault();
      const options = this.options(popup);
      options[event.key === 'Home' ? 0 : options.length - 1]
        ?.focus({ preventScroll: true });
      return true;
    }
    if (event.key === 'Tab') this.setOpen(popup, false);
    return false;
  }
}
