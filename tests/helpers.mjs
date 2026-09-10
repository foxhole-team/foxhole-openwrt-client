import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import vm from 'node:vm';

export const root = fileURLToPath(new URL('..', import.meta.url));
export const packageRoot = 'package/foxhole-openwrt-client';
export const panelRoot = `${packageRoot}/htdocs/luci-static/resources/foxhole`;
export const modelPath = `${packageRoot}/root/usr/share/foxhole/model.uc`;
export const rpcPath = `${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`;
export const hostPath = `${packageRoot}/htdocs/luci-static/resources/view/foxhole/client.js`;
export const read = (path) => readFile(resolve(root, path), 'utf8');
export const plain = (value) => JSON.parse(JSON.stringify(value));

export function balanced(source, start, open = '{', close = '}') {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === '/' && source[index + 1] === '/') {
      const end = source.indexOf('\n', index + 2);
      index = end < 0 ? source.length : end;
      continue;
    }
    if (character === '/' && source[index + 1] === '*') {
      const end = source.indexOf('*/', index + 2);
      if (end < 0) throw new Error('Unclosed source comment');
      index = end + 1;
      continue;
    }
    if (character === '"' || character === "'" || character === '`') quote = character;
    else if (character === open) depth += 1;
    else if (character === close && --depth === 0) return source.slice(start, index + 1);
  }
  throw new Error('Unbalanced source fixture');
}

export function functionBody(source, name) {
  const marker = `function ${name}(`;
  const index = source.indexOf(marker);
  if (index < 0) throw new Error(`Missing function: ${name}`);
  return balanced(source, source.indexOf('{', index));
}

export async function rpcMethods() {
  const source = await read(rpcPath);
  const index = source.lastIndexOf('const methods =');
  if (index < 0) throw new Error('Missing RPC method registry');
  const registry = balanced(source, source.indexOf('{', index));
  return vm.runInNewContext(`(${registry})`, {}, { timeout: 1000 });
}

export async function hostHarness() {
  const source = await read(hostPath);
  const origin = 'http://router.invalid';
  const listeners = new Map();
  const declarations = new Map();
  const calls = [];
  const replies = [];
  let frame;
  const context = {
    rpc: {
      declare(specification) {
        declarations.set(specification.method, plain(specification));
        return (...args) => {
          calls.push({ method: specification.method, args: plain(args) });
          return Promise.resolve({ ok: true });
        };
      }
    },
    view: { extend: (value) => value },
    window: {
      location: { origin },
      addEventListener: (event, callback) => listeners.set(event, callback),
      removeEventListener: (event) => listeners.delete(event)
    },
    document: { getElementById: () => true, head: { appendChild() {} } },
    L: { resource: (path) => `/luci-static/resources/${path}` },
    E(tag, attributes = {}, children = []) {
      const node = { tag, attributes, children };
      if (tag === 'iframe') {
        node.contentWindow = { postMessage: (...args) => replies.push(plain(args)) };
        frame = node;
      }
      return node;
    }
  };
  const view = vm.runInNewContext(`(function() {${source}\n})()`, context, { timeout: 1000 });
  view.render();
  return {
    declarations, calls, replies, origin, view,
    async send(data, overrides = {}) {
      return listeners.get('message')({ origin, source: frame.contentWindow, data, ...overrides });
    }
  };
}
