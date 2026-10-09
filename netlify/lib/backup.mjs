import zlib from 'node:zlib';

// Резервная копия: пользователи, рейтинг, сохранения и настройки. Хранится 7 последних копий (gzip + base64).
export async function makeBackup(store) {
  const dump = async name => {
    const st = store(name), { blobs } = await st.list(), out = {};
    for (let i = 0; i < blobs.length; i += 25) await Promise.all(blobs.slice(i, i + 25).map(async b => { out[b.key] = await st.get(b.key); }));
    return out;
  };
  const data = { v: 1, at: Date.now(), users: await dump('users'), lb: await dump('lb'), saves: await dump('saves'), clans: await dump('clans') };
  const meta = store('meta'); data.meta = {};
  for (const k of ['cfg', 'settings', 'season', 'seasonLast', 'giftSum', 'ann', 'event']) { const v = await meta.get(k); if (v != null) data.meta[k] = v; }
  const key = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const bk = store('backup');
  await bk.set(key, zlib.gzipSync(Buffer.from(JSON.stringify(data))).toString('base64'));
  const { blobs } = await bk.list(), old = blobs.map(b => b.key).sort().reverse().slice(7);
  for (const k of old) await bk.delete(k);
  return { key, users: Object.keys(data.users).length };
}

export async function restoreBackup(store, key) {
  const raw = await store('backup').get(key); if (!raw) throw new Error('Копия не найдена');
  const data = JSON.parse(zlib.gunzipSync(Buffer.from(raw, 'base64')).toString('utf8'));
  for (const name of ['users', 'lb', 'saves', 'clans']) { const st = store(name), src = data[name] || {}; for (const k of Object.keys(src)) await st.set(k, src[k]); }
  for (const k of Object.keys(data.meta || {})) await store('meta').set(k, data.meta[k]);
  await store('meta').delete('top');
  return { users: Object.keys(data.users || {}).length };
}
