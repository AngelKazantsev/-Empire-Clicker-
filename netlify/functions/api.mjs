import { makeStoreFactory } from '../lib/storage.mjs';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { adminRoute } from '../lib/admin.mjs';

const scrypt = promisify(crypto.scrypt);
const store = await makeStoreFactory();
const SESSION_MS = 90 * 24 * 3600 * 1000;
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const fail = (status, message) => Object.assign(new Error(message), { status });
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = async (pw, salt) => (await scrypt(pw, salt, 64)).toString('hex');
const cleanNick = s => String(s || '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, 20);
const pub = u => ({ public_id: u.public_id, username: u.username, nick: u.nick });

const hits = new Map(); // ограничение попыток (в пределах одного экземпляра функции)
function limited(ip, max) {
  const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 600000);
  a.push(now); hits.set(ip, a);
  return a.length > max;
}

/* ---------- user.json: начальная база пользователей ---------- */
function readSeed() {
  const dirs = [process.env.LAMBDA_TASK_ROOT, process.cwd()];
  try { dirs.push(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..')); } catch {}
  for (const d of dirs) { if (!d) continue; try { return fs.readFileSync(path.join(d, 'user.json'), 'utf8'); } catch {} }
  return null;
}
let seeded = false;
async function ensureSeed() {
  if (seeded) return; seeded = true;
  const raw = readSeed(); if (!raw) return;
  const h = sha(raw), meta = store('meta');
  if ((await meta.get('seed')) === h) return;
  let j; try { j = JSON.parse(raw); } catch { return; }
  const users = store('users'), lb = store('lb'), saves = store('saves');
  for (const u of (j.users || [])) {
    const name = String(u.username || '').trim();
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) continue;
    const key = 'u:' + name.toLowerCase();
    if (await users.get(key)) continue;
    let salt = u.salt, hash = u.hash;
    if (!hash) { if (typeof u.password !== 'string' || !u.password) continue; salt = crypto.randomBytes(16).toString('hex'); hash = await hashPw(u.password, salt); }
    const wanted = typeof u.public_id === 'string' && /^[A-Z0-9]{8}$/.test(u.public_id) && !(await lb.get(u.public_id));
    const rec = { public_id: wanted ? u.public_id : await newPublicId(), username: name, nick: cleanNick(u.nick || name) || name, salt, hash, created: u.created || Date.now() };
    await users.setJSON(key, rec);
    const tot = Math.max(0, Math.floor(Number(u.tot) || 0)), stars = Math.max(0, Math.floor(Number(u.stars) || 0));
    await lb.setJSON(rec.public_id, { nick: rec.nick, tot, bal: Math.max(0, Math.floor(Number(u.bal) || 0)), stars, t: Date.now() });
    if (u.data) await saves.setJSON(name.toLowerCase(), { data: typeof u.data === 'string' ? u.data : JSON.stringify(u.data), tot, stars, t: Date.now() });
  }
  await meta.set('seed', h);
}

let pubCache = { t: 0, ann: [], ev: null };
async function pubState() {
  if (Date.now() - pubCache.t < 8000) return pubCache;
  const meta = store('meta'), now = Date.now();
  const ann = ((await meta.get('ann', { type: 'json' })) || []).filter(a => !a.exp || a.exp > now).slice(-10);
  let ev = await meta.get('event', { type: 'json' }); if (ev && ev.until && ev.until < now) ev = null;
  pubCache = { t: now, ann, ev };
  return pubCache;
}
// то, что игра получает вместе с ответами: команды администратора, объявления и событие
async function sync(user) {
  const p = await pubState(), ops = user.ops || [], cf = await getCfg();
  if (ops.length) await store('users').setJSON('u:' + user.username.toLowerCase(), { ...user, ops: [] });
  return { ops, ann: p.ann, ev: p.ev ? { n: p.ev.name, m: p.ev.mult, until: p.ev.until || 0 } : null, cfg: { clickMul: cf.clickMul, incomeMul: cf.incomeMul, priceMul: cf.priceMul, shopSale: cf.shopSale || 0, maintenance: !!cf.maintenance, maintText: cf.maintText } };
}

/* ---------- Админ-панель ---------- */
const DEF_CFG = { clickMul: 1, incomeMul: 1, priceMul: 1, shopSale: 0, regOpen: true, maintenance: false, maintText: 'Идут технические работы. Скоро вернёмся!', events: [], messages: [] };
async function getCfg() { const c = await store('meta').get('cfg', { type: 'json' }); return { ...DEF_CFG, ...(c || {}) }; }
async function readBody(req) {
  const text = await req.text();
  if (text.length > 300 * 1024) throw fail(413, 'Слишком большой запрос');
  if (!text) return {};
  try { return JSON.parse(text); } catch { throw fail(400, 'Неверный JSON'); }
}

async function newPublicId() {
  const lb = store('lb');
  for (let i = 0; i < 20; i++) {
    const b = crypto.randomBytes(8);
    let id = '';
    for (let j = 0; j < 8; j++) id += ALPHA[b[j] % ALPHA.length];
    if (!(await lb.get(id))) return id;
  }
  throw fail(500, 'Не удалось создать ID');
}

async function newSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  await store('sessions').setJSON(sha(token), { u: username, exp: Date.now() + SESSION_MS });
  return token;
}

async function authUser(req) {
  const h = req.headers.get('authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  const th = sha(h.slice(7)), sess = store('sessions');
  const s = await sess.get(th, { type: 'json' });
  if (!s || s.exp < Date.now()) return null;
  if (s.exp - Date.now() < SESSION_MS * 0.8) await sess.setJSON(th, { ...s, exp: Date.now() + SESSION_MS }); // продлеваем вход, пока игрок играет
  const user = await store('users').get('u:' + s.u, { type: 'json' });
  if (user && user.banned) throw fail(403, 'Аккаунт заблокирован администратором');
  if (user && Date.now() - (user.seen || 0) > 60000) { user.seen = Date.now(); await store('users').setJSON('u:' + user.username.toLowerCase(), user); }
  return user || null;
}

/* ---------- сезоны (неделя, считаем прирост заработка) ---------- */
const WEEK = 7 * 864e5, EPOCH = Date.UTC(2024, 0, 1);
const sidOf = x => Math.floor((x - EPOCH) / WEEK);
const PRIZES = [
  { c: 100000, tk: 10, it: { k: 'chest', id: 'c3', n: 1 } }, { c: 50000, tk: 6, it: { k: 'chest', id: 'c2', n: 1 } }, { c: 25000, tk: 4, it: { k: 'chest', id: 'c2', n: 1 } },
  ...Array(7).fill({ c: 10000, tk: 2, it: { k: 'chest', id: 'c1', n: 1 } })];
let seasonKnown = -1;
async function ensureSeason() {
  const cur = sidOf(Date.now()); if (seasonKnown === cur) return;
  const meta = store('meta'), s = await meta.get('season', { type: 'json' });
  if (!s || s.id >= cur) { if (!s) await meta.setJSON('season', { id: cur }); seasonKnown = cur; return; }
  seasonKnown = cur;
  await meta.setJSON('season', { id: cur }); // сначала фиксируем, чтобы призы не выдались дважды
  const lb = store('lb'), users = store('users'), { blobs } = await lb.list();
  const rows = (await Promise.all(blobs.slice(0, 3000).map(async b => { const v = await lb.get(b.key, { type: 'json' }); return v ? { id: b.key, ...v } : null; })))
    .filter(r => r && !r.hidden && !r.susHide && r.sid === s.id).map(r => ({ ...r, gain: Math.max(0, (r.tot || 0) - (r.sb || 0)) })).filter(r => r.gain > 0).sort((a, b) => b.gain - a.gain);
  const top = rows.slice(0, 10);
  for (let i = 0; i < top.length; i++) {
    const r = top[i], pz = PRIZES[i]; if (!r.un) continue;
    const key = 'u:' + r.un, u = await users.get(key, { type: 'json' }); if (!u || u.banned) continue;
    u.ops = [...(u.ops || []), { t: 'add', c: pz.c, tk: pz.tk, items: [pz.it], msg: '🏆 Приз сезона: ' + (i + 1) + ' место' }].slice(-20);
    await users.setJSON(key, u);
    await lb.setJSON(r.id, { ...(await lb.get(r.id, { type: 'json' })), gr: (r.gr || 0) + pz.c });
  }
  await meta.setJSON('seasonLast', { id: s.id, at: Date.now(), top: top.map((r, i) => ({ rank: i + 1, nick: r.nick, gain: r.gain })) });
  await meta.delete('top');
}

/* ---------- защита рейтинга от подделки (эвристики) ---------- */
function cheatFlags(e, now, o) {
  const f = [], dt = Math.max(1, (now - (e.t || now)) / 1000), dc = o.clicks - (e.clicks || 0);
  const first = !e.n; // первое сохранение (в т.ч. прогресс гостя при регистрации) не проверяем на скорость
  if (!first && dc > 30 * dt + 150) f.push('скорость кликов');
  if (o.bal > o.tot + 60 + (e.gr || 0) + o.gifts + 1000 + o.tot * 0.001) f.push('баланс больше заработанного');
  const dtot = o.tot - (e.tot || 0);
  if (!first && dtot > 1e7 && dtot > 1e6 + Math.max(0, dc) * (o.maxHit || 1) * 1.1 + dt * (o.maxIps || 0) * 1.2 + 0.5 * (e.tot || 0)) f.push('скачок заработка');
  return f;
}

async function board() {
  const meta = store('meta');
  const cached = await meta.get('top', { type: 'json' });
  if (cached && cached.bals && Date.now() - cached.t < 20000) return cached;
  const lb = store('lb');
  const { blobs } = await lb.list();
  const rows = (await Promise.all(blobs.slice(0, 3000).map(async b => {
    const v = await lb.get(b.key, { type: 'json' });
    return v ? { id: b.key, ...v } : null;
  }))).filter(r => r && !r.hidden && !r.susHide);
  rows.sort((a, b) => (b.bal || 0) - (a.bal || 0) || a.id.localeCompare(b.id)); // рейтинг по текущему балансу
  const c = {
    t: Date.now(), total: rows.length,
    top: rows.slice(0, 100).map((r, i) => ({ rank: i + 1, public_id: r.id, nick: r.nick, bal: r.bal || 0, tot: r.tot || 0, stars: r.stars || 0 })),
    bals: rows.map(r => r.bal || 0),
  };
  const sid = sidOf(Date.now()), sr = rows.filter(r => r.sid === sid).map(r => ({ id: r.id, nick: r.nick, gain: Math.max(0, (r.tot || 0) - (r.sb || 0)) })).filter(r => r.gain > 0).sort((a, b) => b.gain - a.gain);
  c.season = { id: sid, top: sr.slice(0, 50).map((r, i) => ({ rank: i + 1, public_id: r.id, nick: r.nick, gain: r.gain })), gains: sr.map(r => r.gain) };
  const cl = {};
  rows.forEach(r => { if (r.clan) (cl[r.clan] = cl[r.clan] || []).push({ p: r.id, n: r.nick, b: r.bal || 0 }); });
  c.cl = cl;
  await meta.setJSON('top', c);
  return c;
}

const CORS = () => ({
  'access-control-allow-origin': process.env.ALLOWED_ORIGIN || '*',
  'access-control-allow-headers': 'authorization, content-type, x-admin-token',
  'access-control-allow-methods': 'GET, POST, PUT, OPTIONS',
  'access-control-max-age': '86400',
  vary: 'Origin',
});
export default async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS() });
  const res = await handle(req);
  try { Object.entries(CORS()).forEach(([k, v]) => res.headers.set(k, v)); } catch {}
  return res;
};
async function handle(req) {
  try {
    await ensureSeed();
    const url = new URL(req.url);
    const route = req.method + ' ' + url.pathname.replace(/\/+$/, '');
    const ip = req.headers.get('x-nf-client-connection-ip') || req.headers.get('x-forwarded-for') || 'x';

    if (url.pathname.startsWith('/api/admin/') && route !== 'GET /api/admin/export') {
      const ctx = { store, json, fail, sha, hashPw, cleanNick, readBody, limited, ip, dropPub: () => { pubCache.t = 0; } };
      return (await adminRoute(route, req, url, ctx)) || json({ error: 'Не найдено' }, 404);
    }

    if (route === 'POST /api/register') {
      if (limited(ip, 10)) throw fail(429, 'Слишком много попыток, попробуйте позже');
      const st = (await store('meta').get('settings', { type: 'json' })) || {};
      if (st.regOpen === false) throw fail(403, 'Регистрация временно закрыта');
      const b = await readBody(req);
      const username = String(b.username || '').trim(), password = String(b.password || ''), nick = cleanNick(b.nick || username);
      if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) throw fail(400, 'Логин: 3–20 символов, латиница, цифры и _');
      if (!password || password.length > 200) throw fail(400, 'Введите пароль (до 200 символов)');
      if (nick.length < 2) throw fail(400, 'Ник: минимум 2 символа');
      if (!(await getCfg()).regOpen) throw fail(403, 'Регистрация временно закрыта');
      const key = 'u:' + username.toLowerCase(), users = store('users');
      if (await users.get(key)) throw fail(409, 'Этот логин уже занят');
      const salt = crypto.randomBytes(16).toString('hex');
      const user = { public_id: await newPublicId(), username, nick, salt, hash: await hashPw(password, salt), created: Date.now() };
      await users.setJSON(key, user);
      await store('lb').setJSON(user.public_id, { nick, tot: 0, bal: 0, stars: 0, plv: 1, clicks: 0, t: Date.now() });
      return json({ token: await newSession(username.toLowerCase()), user: pub(user), save: null, ...(await sync(user)) }, 201);
    }

    if (route === 'POST /api/login') {
      if (limited(ip, 20)) throw fail(429, 'Слишком много попыток, попробуйте позже');
      const b = await readBody(req);
      const user = await store('users').get('u:' + String(b.username || '').trim().toLowerCase(), { type: 'json' });
      const pw = String(b.password || '');
      let ok = false;
      if (user) {
        const a = Buffer.from(await hashPw(pw, user.salt), 'hex'), c = Buffer.from(user.hash, 'hex');
        ok = a.length === c.length && crypto.timingSafeEqual(a, c);
      } else await hashPw(pw, 'x');
      if (!ok) throw fail(401, 'Неверный логин или пароль');
      if (user.banned) throw fail(403, 'Аккаунт заблокирован администратором');
      if (user.banned) throw fail(403, 'Аккаунт заблокирован администратором');
      const save = await store('saves').get(user.username.toLowerCase(), { type: 'json' });
      return json({ token: await newSession(user.username.toLowerCase()), user: pub(user), save: save ? { data: save.data, tot: save.tot, stars: save.stars } : null, ...(await sync(user)) });
    }

    if (route === 'GET /api/config') {
      const c = await getCfg(), now = Date.now();
      const ev = (c.events || []).filter(e => e.on !== false && e.start <= now && e.end > now);
      return json({ clickMul: c.clickMul, incomeMul: c.incomeMul, priceMul: c.priceMul, shopSale: c.shopSale || 0, maintenance: c.maintenance, maintText: c.maintText, events: ev, messages: (c.messages || []).slice(0, 15) });
    }

    if (route === 'GET /api/leaderboard') {
      let user = await authUser(req); if (user && user.banned) user = null;
      const limit = Math.max(1, Math.min(100, +url.searchParams.get('limit') || 50)), mode = url.searchParams.get('mode');
      await ensureSeason();
      const c = await board(), e = user ? await store('lb').get(user.public_id, { type: 'json' }) : null;
      if (mode === 'season') {
        const meta = store('meta'), mine = e && e.sid === c.season.id ? Math.max(0, (e.tot || 0) - (e.sb || 0)) : 0;
        return json({ mode: 'season', top: c.season.top.slice(0, limit), me: e ? { rank: mine > 0 ? c.season.gains.filter(v => v > mine).length + 1 : 0, gain: mine } : null,
          total: c.season.gains.length, end: EPOCH + (c.season.id + 1) * WEEK, last: await meta.get('seasonLast', { type: 'json' }), prizes: PRIZES.slice(0, 10).map(p => ({ c: p.c, tk: p.tk, it: p.it })) });
      }
      let me = null;
      if (e) { const mine = e.bal || 0; me = { rank: c.bals.filter(v => v > mine).length + 1, bal: mine, tot: e.tot || 0, stars: e.stars || 0 }; }
      return json({ top: c.top.slice(0, limit), me, total: c.total });
    }

    if (route === 'GET /api/admin/export') {
      const key = process.env.ADMIN_KEY, given = req.headers.get('x-admin-key') || url.searchParams.get('key') || '';
      const ok = key && given.length === key.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(key));
      if (!ok) throw fail(403, 'Нет доступа (задайте переменную ADMIN_KEY и передайте ключ)');
      const full = url.searchParams.get('full') === '1', users = store('users'), lb = store('lb'), saves = store('saves');
      const { blobs } = await users.list();
      const out = (await Promise.all(blobs.map(async b => {
        const u = await users.get(b.key, { type: 'json' }); if (!u) return null;
        const e = (await lb.get(u.public_id, { type: 'json' })) || {};
        const r = { username: u.username, nick: u.nick, public_id: u.public_id, salt: u.salt, hash: u.hash, created: u.created, tot: e.tot || 0, bal: e.bal || 0, stars: e.stars || 0 };
        if (full) { const sv = await saves.get(u.username.toLowerCase(), { type: 'json' }); if (sv) r.data = sv.data; }
        return r;
      }))).filter(Boolean);
      return new Response(JSON.stringify({ users: out }, null, 2), { headers: { 'content-type': 'application/json; charset=utf-8', 'content-disposition': 'attachment; filename="user.json"', 'cache-control': 'no-store' } });
    }

    const user = await authUser(req);
    if (!user) throw fail(401, 'Требуется вход');
    if (user.banned) throw fail(403, 'Аккаунт заблокирован администратором');
    const uname = user.username.toLowerCase();

    if (route === 'GET /api/inbox') {
      const box = (await store('inbox').get(uname, { type: 'json' })) || [];
      return json({ items: box });
    }
    if (route === 'POST /api/inbox/claim') {
      const ids = (await readBody(req)).ids || [], inbox = store('inbox'), box = (await inbox.get(uname, { type: 'json' })) || [];
      await inbox.setJSON(uname, box.filter(x => !ids.includes(x.id)));
      return json({ ok: true });
    }
    if (route === 'GET /api/me') {
      const save = await store('saves').get(uname, { type: 'json' });
      return json({ user: pub(user), save: save ? { data: save.data, tot: save.tot, stars: save.stars } : null, ...(await sync(user)) });
    }
    if (route === 'POST /api/logout') {
      await store('sessions').delete(sha(req.headers.get('authorization').slice(7)));
      return json({ ok: true });
    }
    if (route === 'PUT /api/nick') {
      const nick = cleanNick((await readBody(req)).nick);
      if (nick.length < 2) throw fail(400, 'Ник: минимум 2 символа');
      await store('users').setJSON('u:' + uname, { ...user, nick });
      const lb = store('lb'), e = (await lb.get(user.public_id, { type: 'json' })) || { tot: 0, stars: 0 };
      await lb.setJSON(user.public_id, { ...e, nick, t: Date.now() });
      return json({ ok: true, nick });
    }
    /* ---------- кланы ---------- */
    if (route.startsWith('GET /api/clan') || route.startsWith('POST /api/clan/')) {
      const CL = store('clans'), lbs = store('lb'), meta = store('meta');
      const cleanClan = s => String(s || '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, 20);
      const info = async (c, id) => {
        const cl = id && await CL.get(id, { type: 'json' }); if (!cl) return null;
        const mem = (c.cl[id] || []).slice().sort((x, y) => y.b - x.b);
        return { id: cl.id, name: cl.name, owner: cl.owner, count: mem.length, total: mem.reduce((s, m) => s + m.b, 0), members: mem.slice(0, 30).map(m => ({ public_id: m.p, nick: m.n, bal: m.b })) };
      };
      const standings = async c => (await Promise.all(Object.keys(c.cl).map(id => info(c, id)))).filter(Boolean).sort((x, y) => y.total - x.total);
      const e = (await lbs.get(user.public_id, { type: 'json' })) || {};
      if (route === 'GET /api/clan') {
        const c = await board(), st = await standings(c), my = e.clan ? await info(c, e.clan) : null;
        if (my) my.rank = st.findIndex(x => x.id === my.id) + 1;
        return json({ clan: my, top: st.slice(0, 20).map((x, i) => ({ rank: i + 1, id: x.id, name: x.name, count: x.count, total: x.total })) });
      }
      if (route === 'POST /api/clan/create') {
        const name = cleanClan((await readBody(req)).name);
        if (name.length < 3) throw fail(400, 'Название клана: минимум 3 символа');
        if (e.clan) throw fail(400, 'Вы уже состоите в клане');
        const nk = 'n:' + name.toLowerCase(); if (await CL.get(nk)) throw fail(409, 'Клан с таким названием уже существует');
        let id = ''; for (let i = 0; i < 20 && !id; i++) { const b = crypto.randomBytes(6); let x = ''; for (let j = 0; j < 6; j++) x += ALPHA[b[j] % ALPHA.length]; if (!(await CL.get(x))) id = x; }
        await CL.setJSON(id, { id, name, owner: user.public_id, created: Date.now() }); await CL.set(nk, id);
        await lbs.setJSON(user.public_id, { ...e, clan: id }); await meta.delete('top');
        return json({ ok: true, id });
      }
      if (route === 'POST /api/clan/join') {
        const id = String((await readBody(req)).id || '').trim().toUpperCase();
        if (e.clan) throw fail(400, 'Сначала выйдите из текущего клана');
        const cl = /^[A-Z0-9]{6}$/.test(id) ? await CL.get(id, { type: 'json' }) : null; if (!cl) throw fail(404, 'Клан с таким кодом не найден');
        if (((await board()).cl[id] || []).length >= 50) throw fail(400, 'В клане уже 50 участников');
        await lbs.setJSON(user.public_id, { ...e, clan: id }); await meta.delete('top');
        return json({ ok: true });
      }
      if (route === 'POST /api/clan/leave') {
        if (!e.clan) throw fail(400, 'Вы не состоите в клане');
        const id = e.clan, cl = await CL.get(id, { type: 'json' });
        await lbs.setJSON(user.public_id, { ...e, clan: undefined }); await meta.delete('top');
        if (cl && cl.owner === user.public_id) {
          const rest = ((await board()).cl[id] || []).filter(m => m.p !== user.public_id).sort((x, y) => y.b - x.b);
          if (rest.length) await CL.setJSON(id, { ...cl, owner: rest[0].p });
          else { await CL.delete(id); await CL.delete('n:' + cl.name.toLowerCase()); }
        }
        return json({ ok: true });
      }
    }

    if (route === 'PUT /api/save') {
      const b = await readBody(req);
      if (typeof b.data !== 'string' || b.data.length > 200 * 1024) throw fail(400, 'Неверные данные');
      let obj; try { obj = JSON.parse(b.data); } catch { throw fail(400, 'Неверный JSON сохранения'); }
      const tot = Number(obj && obj.tot), stars = Math.max(0, Math.min(1e6, Math.floor(Number(obj && obj.stars) || 0)));
      if (!Number.isFinite(tot) || tot < 0 || tot > 1e18) throw fail(400, 'Неверное значение рейтинга');
      const sy = await sync(user);
      if (sy.ops.length) return json({ ok: true, skipped: true, ...sy });
      const now = Date.now(), meta = store('meta'), lbs = store('lb');
      const t = Math.floor(tot), bal = Math.max(0, Math.min(1e18, Math.floor(Number(obj && obj.c) || 0)));
      const e = (await lbs.get(user.public_id, { type: 'json' })) || {};
      const clicks = Math.max(0, Math.floor(Number(obj.clicks) || 0)), gifts = Number(await meta.get('giftSum')) || 0;
      const flags = cheatFlags(e, now, { tot: t, bal, clicks, gifts, maxHit: Number(obj.maxHit) || 0, maxIps: Number(obj.maxIps) || 0 });
      let sus = (e.sus || []).filter(x => now - x.t < 864e5);
      if (flags.length) sus.push({ t: now, f: flags.join(', ') });
      await ensureSeason();
      const sid = sidOf(now), sb = e.sid === sid && e.sb !== undefined ? e.sb : (e.tot || 0);
      await store('saves').setJSON(uname, { data: b.data, tot: t, bal, stars, t: now });
      await lbs.setJSON(user.public_id, { ...e, nick: user.nick, un: uname, tot: t, bal, stars, plv: Math.max(1, Math.min(9999, Math.floor(Number(obj.plv) || 1))), clicks, t: now, n: (e.n || 0) + 1, sid, sb, sus: sus.slice(-10), susHide: sus.length >= 3 || undefined });
      return json({ ok: true, ...sy });
    }
    throw fail(404, 'Не найдено');
  } catch (e) {
    if (e && e.status) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: 'Ошибка сервера' }, 500);
  }
};

export const config = { path: '/api/*' };
