// Свой сервер для Empire Clicker: запуск `npm start`. Подходит для VPS, Render, Railway, Fly.io и т. п.
// Хранит данные в файлах (папка DATA_DIR, по умолчанию ./data), раздаёт API и (по желанию) саму игру.
process.env.EC_STORAGE = process.env.EC_STORAGE || 'file';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { default: apiHandler } = await import('../netlify/functions/api.mjs');
const { makeBackup } = await import('../netlify/lib/backup.mjs');
const { makeStoreFactory } = await import('../netlify/lib/storage.mjs');

const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '0.0.0.0';
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const SERVE_STATIC = process.env.SERVE_STATIC !== '0', TRUST_PROXY = process.env.TRUST_PROXY === '1';
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function ipOf(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || 'x';
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > 400 * 1024) { res.writeHead(413); return res.end(); } chunks.push(c); }
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string' && k !== 'x-nf-client-connection-ip') headers.set(k, v);
      headers.set('x-nf-client-connection-ip', ipOf(req));
      const r = await apiHandler(new Request(url.href, { method: req.method, headers, body: ['GET', 'HEAD', 'OPTIONS'].includes(req.method) ? undefined : Buffer.concat(chunks) }));
      res.writeHead(r.status, Object.fromEntries(r.headers));
      return res.end(Buffer.from(await r.arrayBuffer()));
    }
    if (!SERVE_STATIC || !['GET', 'HEAD'].includes(req.method)) { res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }); return res.end('Не найдено'); }
    let p = decodeURIComponent(url.pathname); if (p.endsWith('/')) p += 'index.html';
    const file = path.normalize(path.join(ROOT, p));
    if (!file.startsWith(ROOT + path.sep)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (e, buf) => {
      if (e) { res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }); return res.end('Не найдено'); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'x-content-type-options': 'nosniff', 'cache-control': /sw\.js|admin\.html/.test(p) ? 'no-cache' : 'public, max-age=300' });
      res.end(buf);
    });
  } catch (e) { console.error(e); res.writeHead(500); res.end(); }
});
server.listen(PORT, HOST, () => console.log(`Empire Clicker: http://localhost:${PORT}  (данные: ${process.env.DATA_DIR || './data'})`));

// ежедневная резервная копия (хранятся 7 последних)
const doBackup = async () => { try { console.log('backup', JSON.stringify(await makeBackup(await makeStoreFactory()))); } catch (e) { console.error('backup failed', e.message); } };
setTimeout(doBackup, 60000).unref(); setInterval(doBackup, 24 * 3600 * 1000).unref();
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => process.exit(0));
