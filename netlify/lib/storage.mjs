import fs from 'node:fs';
import path from 'node:path';

/* Хранилище данных. На Netlify используется Netlify Blobs.
   На любом другом хосте (свой сервер, Render, Railway, VPS) данные лежат в обычных файлах в папке DATA_DIR (по умолчанию ./data). */
export function fileStoreFactory(root = process.env.DATA_DIR || path.join(process.cwd(), 'data')) {
  const enc = k => encodeURIComponent(k).replace(/\./g, '%2E') || '%00';
  return name => {
    const dir = path.join(root, enc(name));
    fs.mkdirSync(dir, { recursive: true });
    const file = k => path.join(dir, enc(k));
    return {
      async get(k, o) {
        let t; try { t = fs.readFileSync(file(k), 'utf8'); } catch { return null; }
        if (o && o.type === 'json') { try { return JSON.parse(t); } catch { return null; } }
        return t;
      },
      async set(k, v) { const f = file(k), tmp = f + '.' + process.pid + '.tmp'; fs.writeFileSync(tmp, typeof v === 'string' || Buffer.isBuffer(v) ? v : String(v)); fs.renameSync(tmp, f); },
      async setJSON(k, v) { const f = file(k), tmp = f + '.' + process.pid + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(v)); fs.renameSync(tmp, f); },
      async delete(k) { try { fs.unlinkSync(file(k)); } catch {} },
      async list() { return { blobs: fs.readdirSync(dir).filter(x => !x.endsWith('.tmp')).map(x => ({ key: decodeURIComponent(x) })) }; },
    };
  };
}

export async function makeStoreFactory() {
  if (process.env.EC_STORAGE === 'file') return fileStoreFactory();
  try { const m = await import('@netlify/blobs'); return name => m.getStore({ name, consistency: 'strong' }); }
  catch { return fileStoreFactory(); }
}
