// Isolated UI fixture. It never contacts OpenWrt or real APIs.
// Run: node tests/mobile-ui-server.mjs 8879
// Set FOXHOLE_UI_HOST=0.0.0.0 for a containerized browser.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../package/foxhole-openwrt-client/htdocs/', import.meta.url));
const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ttf': 'font/ttf' };
const luciHost = '<meta name="viewport" content="width=device-width, initial-scale=1">' +
  '<title>LuCI original</title><link rel="icon" href="/luci-original.png">' +
  '<style>body{margin:0}header{height:64px}main{padding:24px;max-width:1100px;' +
  'margin:auto;box-sizing:border-box}</style><header></header><main id="content"></main>';
const server = createServer(async (request, response) => {
  try {
    let path = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.writeHead(405); response.end(); return;
    }
    if (path === '/cgi-bin/luci/admin/services/foxhole') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end(request.method === 'HEAD' ? '' : luciHost); return;
    }
    if (path === '/foxhole.html') path = '/luci-static/resources/foxhole/shell.html';
    const file = resolve(root, '.' + path);
    if (!file.startsWith(root.endsWith(sep) ? root : root + sep)) throw new Error('outside fixture');
    const data = await readFile(file);
    response.writeHead(200, { 'Content-Type': mime[extname(file)] || 'application/octet-stream',
      'Content-Length': data.length, 'Cache-Control': 'no-store' });
    response.end(request.method === 'HEAD' ? undefined : data);
  } catch {
    response.writeHead(404); response.end();
  }
});
const port = Number(process.argv[2] || 8879);
server.listen(port, process.env.FOXHOLE_UI_HOST || '127.0.0.1', () => {
  console.log(`UI fixture listening on ${port}`);
});
