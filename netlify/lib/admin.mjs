import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { makeBackup, restoreBackup } from './backup.mjs';

const ADM_MS = 12 * 3600 * 1000;
let cache = { t: 0, rows: null };
const eqs = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
const ITEMS = { skin: ['neon', 'gold', 'ice', 'ruby', 'toxic', 'sakura', 'sunset', 'mint'], boost: ['x3', 'a5', 'bn'], chest: ['c1', 'c2', 'c3'], card: ['gold', 'plat', 'black'] };
const cleanItems = arr => (Array.isArray(arr) ? arr : []).map(i => ({ k: String((i && i.k) || ''), id: String((i && i.id) || ''), n: Math.max(1, Math.min(100, Math.round(Number(i && i.n) || 1))) })).filter(i => ITEMS[i.k] && ITEMS[i.k].includes(i.id)).slice(0, 10);
const day = t => { const d = new Date(t); return String(d.getDate()).padStart(2, '0') + '.' + String(d.getMonth() + 1).padStart(2, '0'); };

export async function adminRoute(route, req, url, c) {
  const { store, json, fail, sha, hashPw, cleanNick, readBody, limited, ip, dropPub } = c;
  const meta = store('meta'), users = store('users'), lb = store('lb'), saves = store('saves'), asess = store('asess');
  const audit = async (a, x) => { const l = (await meta.get('audit', { type: 'json' })) || []; l.push({ t: Date.now(), a, x: x || '' }); await meta.setJSON('audit', l.slice(-200)); };
  const drop = async () => { cache.t = 0; try { await meta.delete('top'); } catch {} dropPub(); };

  /* Пароль администратора НЕ хранится в коде. Источники по приоритету:
     1) пароль, сохранённый через панель («Безопасность»), лежит в хранилище в виде хеша scrypt;
     2) переменная окружения ADMIN_PASSWORD_HASH формата scrypt$соль$хеш (см. tools/make-hash.mjs);
     3) переменная окружения ADMIN_PASSWORD (обычный текст, задаётся только в настройках Netlify).
     Если ничего не задано, вход закрыт. ADMIN_FORCE_ENV=1 игнорирует пароль из панели (восстановление). */
  async function checkPw(pw) {
    const rec = process.env.ADMIN_FORCE_ENV === '1' ? null : await meta.get('adminpw', { type: 'json' });
    if (rec) return eqs(await hashPw(pw, rec.salt), rec.hash);
    const h = process.env.ADMIN_PASSWORD_HASH || '';
    if (h.startsWith('scrypt$')) { const [, salt, hash] = h.split('$'); return !!salt && !!hash && eqs(await hashPw(pw, salt), hash); }
    if (process.env.ADMIN_PASSWORD) return eqs(pw, process.env.ADMIN_PASSWORD);
    return null; // не настроен
  }
  const b32 = s => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = []; for (const ch of s.toUpperCase().replace(/[^A-Z2-7]/g, '')) bits += A.indexOf(ch).toString(2).padStart(5, '0'); for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
  const totp = (secret, step) => { const cnt = Buffer.alloc(8); cnt.writeBigUInt64BE(BigInt(step)); const h = crypto.createHmac('sha1', b32(secret)).update(cnt).digest(), o = h[19] & 15; return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0'); };
  const checkTotp = code => { const sec = process.env.ADMIN_TOTP_SECRET; if (!sec) return true; const st = Math.floor(Date.now() / 30000); return [-1, 0, 1].some(d => eqs(totp(sec, st + d), String(code || '').replace(/\s/g, ''))); };
  const hsh = x => sha('adm-fail:' + x).slice(0, 24);
  async function failState(k) { const r = (await meta.get('af:' + k, { type: 'json' })) || { n: 0, t: 0 }; if (Date.now() - r.t > 15 * 60000) return { n: 0, t: Date.now() }; return r; }

  if (route === 'POST /api/admin/login') {
    const allow = (process.env.ADMIN_IPS || '').split(',').map(x => x.trim()).filter(Boolean);
    if (allow.length && !allow.includes(ip)) throw fail(403, 'Доступ с этого адреса запрещён');
    if (limited('adm' + ip, 8)) throw fail(429, 'Слишком много попыток. Подождите 15 минут.');
    const kIp = hsh(ip), fIp = await failState(kIp), fAll = await failState('all');
    if (fIp.n >= 5 || fAll.n >= 40) throw fail(429, 'Слишком много попыток. Подождите 15 минут.');
    const b = await readBody(req), ok = await checkPw(String(b.password || ''));
    if (ok === null) throw fail(503, 'Пароль администратора не задан. В Netlify: Site configuration → Environment variables → ADMIN_PASSWORD.');
    if (!ok || !checkTotp(b.code)) {
      if (ok && !b.code) throw fail(401, 'Нужен код 2FA');
      fIp.n++; fIp.t = Date.now(); fAll.n++; fAll.t = Date.now();
      await meta.setJSON('af:' + kIp, fIp); await meta.setJSON('af:all', fAll);
      await audit('Неудачная попытка входа', ip);
      await new Promise(r => setTimeout(r, 700));
      throw fail(401, ok ? 'Неверный код 2FA' : 'Неверный пароль');
    }
    await meta.setJSON('af:' + kIp, { n: 0, t: Date.now() });
    const token = crypto.randomBytes(32).toString('hex');
    await asess.setJSON(sha(token), { exp: Date.now() + ADM_MS });
    await audit('Вход в панель', ip);
    return json({ token });
  }

  const tok = req.headers.get('x-admin-token') || '';
  const sess = tok ? await asess.get(sha(tok), { type: 'json' }) : null;
  if (!sess || sess.exp < Date.now()) throw fail(401, 'Сессия администратора истекла');

  async function rows() {
    if (cache.rows && Date.now() - cache.t < 8000) return cache.rows;
    const { blobs } = await users.list();
    const out = (await Promise.all(blobs.map(async b => {
      const u = await users.get(b.key, { type: 'json' }); if (!u) return null;
      const e = (await lb.get(u.public_id, { type: 'json' })) || {};
      return { public_id: u.public_id, username: u.username, nick: u.nick, created: u.created || 0, banned: !!u.banned, bal: e.bal || 0, tot: e.tot || 0, stars: e.stars || 0, plv: e.plv || 1, clicks: e.clicks || 0, seen: e.t || u.created || 0, sus: e.sus || [], susHide: !!e.susHide, clan: e.clan || '' };
    }))).filter(Boolean);
    cache = { t: Date.now(), rows: out };
    return out;
  }
  async function findUser(id) {
    const r = (await rows()).find(x => x.public_id === id);
    if (!r) throw fail(404, 'Игрок не найден');
    const key = 'u:' + r.username.toLowerCase();
    return { r, key, u: await users.get(key, { type: 'json' }) };
  }
  const pushOp = async (u, key, op) => { u.ops = [...(u.ops || []), op].slice(-20); await users.setJSON(key, u); };

  if (route === 'POST /api/admin/logout') { await asess.delete(sha(tok)); return json({ ok: true }); }

  if (route === 'GET /api/admin/overview') {
    const R = await rows(), now = Date.now(), DAY = 864e5;
    const sum = k => R.reduce((s, r) => s + (r[k] || 0), 0);
    const reg = [], act = [];
    for (let i = 13; i >= 0; i--) {
      const t0 = new Date(); t0.setHours(0, 0, 0, 0); const a = t0.getTime() - i * DAY, b = a + DAY;
      reg.push({ d: day(a), n: R.filter(r => r.created >= a && r.created < b).length });
      act.push({ d: day(a), n: R.filter(r => r.seen >= a && r.seen < b).length });
    }
    const bk = [[0, 100, '< $100'], [100, 1e3, '$100–1K'], [1e3, 1e4, '$1K–10K'], [1e4, 1e5, '$10K–100K'], [1e5, 1e6, '$100K–1M'], [1e6, Infinity, '> $1M']];
    const lv = [[1, 5, '1–4'], [5, 10, '5–9'], [10, 20, '10–19'], [20, 50, '20–49'], [50, Infinity, '50+']];
    const settings = (await meta.get('settings', { type: 'json' })) || { regOpen: true };
    let ev = await meta.get('event', { type: 'json' }); if (ev && ev.until && ev.until < now) ev = null;
    const ann = (await meta.get('ann', { type: 'json' })) || [];
    return json({
      players: R.length, online: R.filter(r => now - r.seen < 5 * 60e3).length, active24: R.filter(r => now - r.seen < DAY).length,
      new24: R.filter(r => now - r.created < DAY).length, new7: R.filter(r => now - r.created < 7 * DAY).length, banned: R.filter(r => r.banned).length,
      totalBal: sum('bal'), totalEarned: sum('tot'), totalStars: sum('stars'), totalClicks: sum('clicks'), avgLvl: R.length ? sum('plv') / R.length : 0,
      top: R.filter(r => !r.banned).sort((a, b) => b.bal - a.bal).slice(0, 5).map((r, i) => ({ rank: i + 1, nick: r.nick, public_id: r.public_id, bal: r.bal, tot: r.tot, plv: r.plv })),
      reg, act,
      buckets: bk.map(([a, b, l]) => ({ l, n: R.filter(r => r.bal >= a && r.bal < b).length })),
      levels: lv.map(([a, b, l]) => ({ l, n: R.filter(r => r.plv >= a && r.plv < b).length })),
      recent: R.slice().sort((a, b) => b.seen - a.seen).slice(0, 8).map(r => ({ nick: r.nick, public_id: r.public_id, seen: r.seen, created: r.created, bal: r.bal })),
      event: ev, settings, ann: ann.length, now, sus: R.filter(r => r.sus.length || r.susHide).length,
      funnel: [['Регистрация', R.length], ['Играли', R.filter(r => r.clicks > 0).length], ['Ур. 5+', R.filter(r => r.plv >= 5).length], ['Ур. 10+', R.filter(r => r.plv >= 10).length], ['Престиж', R.filter(r => r.stars >= 1).length]],
      retention: { d1: { n: R.filter(r => now - r.created > DAY && r.seen - r.created > 20 * 36e5).length, of: R.filter(r => now - r.created > DAY).length }, d7: { n: R.filter(r => now - r.created > 7 * DAY && r.seen - r.created > 6.5 * DAY).length, of: R.filter(r => now - r.created > 7 * DAY).length } },
    });
  }

  if (route === 'GET /api/admin/suspects') {
    cache.t = 0; const R = await rows();
    return json({ rows: R.filter(r => r.sus.length || r.susHide).map(r => ({ public_id: r.public_id, nick: r.nick, bal: r.bal, tot: r.tot, hidden: r.susHide, banned: r.banned, flags: r.sus.map(x => ({ t: x.t, f: x.f })) })).sort((a, b) => b.flags.length - a.flags.length) });
  }
  if (route === 'GET /api/admin/backups') { const { blobs } = await store('backup').list(); return json({ list: blobs.map(b => b.key).sort().reverse() }); }
  if (route === 'POST /api/admin/backup') { const r = await makeBackup(store); await audit('Создана резервная копия', r.key); return json({ ok: true, ...r }); }
  if (route === 'GET /api/admin/backup/download') {
    const key = url.searchParams.get('key') || '', raw = await store('backup').get(key); if (!raw) throw fail(404, 'Копия не найдена');
    return new Response(zlib.gunzipSync(Buffer.from(raw, 'base64')), { headers: { 'content-type': 'application/json; charset=utf-8', 'content-disposition': 'attachment; filename="backup ' + key.replace(/[^0-9 -:]/g, '').replace(/:/g, '-') + '.json"', 'cache-control': 'no-store' } });
  }
  if (route === 'POST /api/admin/backup/restore') {
    const b = await readBody(req); if (b.confirm !== 'ВОССТАНОВИТЬ') throw fail(400, 'Нужно подтверждение');
    const r = await restoreBackup(store, String(b.key || '')); cache.t = 0; dropPub(); await audit('Восстановление из копии', String(b.key)); return json({ ok: true, ...r });
  }
  if (route === 'GET /api/admin/users') {
    const q = (url.searchParams.get('q') || '').toLowerCase().trim(), f = url.searchParams.get('filter') || 'all', sort = url.searchParams.get('sort') || 'seen';
    const page = Math.max(1, +url.searchParams.get('page') || 1), per = 15, now = Date.now();
    let R = (await rows()).filter(r => (!q || (r.nick + ' ' + r.username + ' ' + r.public_id).toLowerCase().includes(q)) &&
      (f === 'all' || (f === 'online' && now - r.seen < 5 * 60e3) || (f === 'banned' && r.banned) || (f === 'sus' && (r.sus.length || r.susHide)) || (f === 'new' && now - r.created < 864e5)));
    const key = { bal: 'bal', tot: 'tot', seen: 'seen', created: 'created', lvl: 'plv' }[sort] || 'seen';
    R = R.slice().sort((a, b) => b[key] - a[key]);
    return json({ rows: R.slice((page - 1) * per, page * per), total: R.length, page, pages: Math.max(1, Math.ceil(R.length / per)), now });
  }

  if (route === 'GET /api/admin/user') {
    const { r, u } = await findUser(url.searchParams.get('id') || '');
    const sv = await saves.get(r.username.toLowerCase(), { type: 'json' });
    let s = null; try { if (sv) { const o = JSON.parse(sv.data); s = { c: o.c, tot: o.tot, clicks: o.clicks, crits: o.crits, u: o.u, pet: o.pet, stars: o.stars, streak: o.streak, bosses: o.bosses, golds: o.golds, plv: o.plv, tk: o.tk, prem: o.prem, skin: o.skin, play: o.play, maxMul: o.maxMul }; } } catch {}
    return json({ row: r, save: s, ops: (u && u.ops || []).length });
  }

  if (route === 'POST /api/admin/user') {
    const b = await readBody(req), id = String(b.id || ''), a = String(b.action || '');
    const { r, key, u } = await findUser(id);
    if (!u) throw fail(404, 'Игрок не найден');
    const e = (await lb.get(id, { type: 'json' })) || { nick: u.nick };
    const tag = r.nick + ' #' + id;
    if (a === 'give') {
      const dc = Math.round(Number(b.c) || 0), tk = Math.round(Number(b.tk) || 0);
      const items = cleanItems(b.items);
      if (!dc && !tk && !items.length) throw fail(400, 'Укажите сумму, билеты или предмет магазина');
      await pushOp(u, key, { t: 'add', c: dc, tk, items, msg: String(b.msg || '').slice(0, 200) || 'Администратор отправил вам подарок' });
      await lb.setJSON(id, { ...e, bal: Math.max(0, (e.bal || 0) + dc), gr: (e.gr || 0) + Math.max(0, dc) });
      await audit('Начисление ' + (dc ? '$' + dc : '') + (tk ? ' +' + tk + ' билетов' : '') + (items.length ? ' · предметов: ' + items.map(i => i.k + ':' + i.id + '×' + i.n).join(', ') : ''), tag);
    } else if (a === 'ach') {
      const mode = ['unlock', 'reset'].includes(b.mode) ? b.mode : 'unlock', cat = ['all', 'money', 'upg', 'boss', 'misc'].includes(b.cat) ? b.cat : 'all';
      await pushOp(u, key, { t: 'ach', mode, cat, msg: mode === 'unlock' ? 'Администратор выдал вам награды за достижения' : 'Администратор сбросил ваши достижения' });
      await audit((mode === 'unlock' ? 'Выданы достижения' : 'Сброшены достижения') + ' (' + cat + ')', tag);
    } else if (a === 'setbal') {
      const v = Math.max(0, Math.round(Number(b.c)));
      if (!Number.isFinite(v)) throw fail(400, 'Неверная сумма');
      await pushOp(u, key, { t: 'set', c: v, msg: 'Администратор изменил ваш баланс' });
      await lb.setJSON(id, { ...e, bal: v, gr: (e.gr || 0) + Math.max(0, v - (e.bal || 0)) });
      await audit('Баланс установлен: $' + v, tag);
    } else if (a === 'clearsus') {
      await lb.setJSON(id, { ...e, sus: [], susHide: undefined }); await audit('Подозрения сняты', tag);
    } else if (a === 'ban' || a === 'unban') {
      u.banned = a === 'ban'; await users.setJSON(key, u);
      await lb.setJSON(id, { ...e, hidden: a === 'ban' });
      await audit(a === 'ban' ? 'Блокировка' : 'Разблокировка', tag);
    } else if (a === 'reset') {
      await pushOp(u, key, { t: 'reset', msg: 'Ваш прогресс был сброшен администратором' });
      await lb.setJSON(id, { ...e, tot: 0, bal: 0, stars: 0, plv: 1, clicks: 0, gr: 0, sus: [], susHide: undefined });
      await saves.delete(r.username.toLowerCase());
      await audit('Сброс прогресса', tag);
    } else if (a === 'delete') {
      await users.delete(key); await lb.delete(id); await saves.delete(r.username.toLowerCase());
      await audit('Удаление аккаунта', tag);
    } else if (a === 'nick') {
      const n = cleanNick(b.nick); if (n.length < 2) throw fail(400, 'Ник: минимум 2 символа');
      u.nick = n; await users.setJSON(key, u); await lb.setJSON(id, { ...e, nick: n });
      await audit('Смена ника на «' + n + '»', tag);
    } else if (a === 'password') {
      const p = String(b.password || ''); if (!p || p.length > 200) throw fail(400, 'Введите пароль (до 200 символов)');
      const salt = crypto.randomBytes(16).toString('hex'); u.salt = salt; u.hash = await hashPw(p, salt); await users.setJSON(key, u);
      await audit('Смена пароля игрока', tag);
    } else if (a === 'msg') {
      const m = String(b.msg || '').trim().slice(0, 200); if (!m) throw fail(400, 'Введите сообщение');
      await pushOp(u, key, { t: 'msg', msg: m }); await audit('Личное сообщение', tag);
    } else throw fail(400, 'Неизвестное действие');
    await drop();
    return json({ ok: true });
  }

  if (route === 'GET /api/admin/announcements') return json({ list: ((await meta.get('ann', { type: 'json' })) || []).slice().reverse() });
  if (route === 'POST /api/admin/announce') {
    const b = await readBody(req), title = String(b.title || '').trim().slice(0, 60), text = String(b.text || '').trim().slice(0, 500);
    const cc = Math.max(0, Math.min(1e12, Math.round(Number(b.c) || 0))), tk = Math.max(0, Math.min(1e4, Math.round(Number(b.tk) || 0)));
    const items = cleanItems(b.items);
    if (!title && !text && !cc && !tk && !items.length) throw fail(400, 'Введите заголовок, текст или подарок');
    const hours = Math.max(0, Math.min(24 * 90, Number(b.hours) || ((cc || tk || items.length) ? 72 : 168)));
    const list = (await meta.get('ann', { type: 'json' })) || [];
    const a = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5), title: title || 'Сообщение от администрации', text, c: cc, tk, items, t: Date.now(), exp: Date.now() + hours * 36e5 };
    list.push(a); await meta.setJSON('ann', list.slice(-30)); dropPub();
    if (cc) await meta.set('giftSum', String((Number(await meta.get('giftSum')) || 0) + cc));
    await audit((cc || tk) ? 'Подарок всем: ' + (cc ? '$' + cc : '') + (tk ? ' +' + tk + ' билетов' : '') : 'Рассылка', title || text.slice(0, 40));
    return json({ ok: true, a });
  }
  if (route === 'POST /api/admin/announce/delete') {
    const b = await readBody(req); const list = ((await meta.get('ann', { type: 'json' })) || []).filter(x => x.id !== b.id);
    await meta.setJSON('ann', list); dropPub(); await audit('Удалено объявление', String(b.id)); return json({ ok: true });
  }

  if (route === 'GET /api/admin/events') {
    let ev = await meta.get('event', { type: 'json' }); if (ev && ev.until && ev.until < Date.now()) ev = null;
    return json({ current: ev, history: ((await meta.get('evhist', { type: 'json' })) || []).slice().reverse() });
  }
  if (route === 'POST /api/admin/event') {
    const b = await readBody(req), hist = (await meta.get('evhist', { type: 'json' })) || [];
    if (b.stop) { await meta.delete('event'); await audit('Событие остановлено', ''); }
    else {
      const name = String(b.name || '').trim().slice(0, 40) || 'Событие', mult = Math.max(1, Math.min(100, Number(b.mult) || 2)), hours = Math.max(0.1, Math.min(24 * 30, Number(b.hours) || 24));
      const ev = { name, mult, until: Date.now() + hours * 36e5, start: Date.now() };
      await meta.setJSON('event', ev); hist.push({ name, mult, hours, t: Date.now() }); await meta.setJSON('evhist', hist.slice(-30));
      await audit('Событие «' + name + '» ×' + mult, hours + ' ч');
    }
    dropPub(); return json({ ok: true });
  }

  const cfgGet = async () => ({ clickMul: 1, incomeMul: 1, priceMul: 1, shopSale: 0, maintenance: false, maintText: 'Идут технические работы. Скоро вернёмся!', ...((await meta.get('cfg', { type: 'json' })) || {}) });
  if (route === 'GET /api/admin/config') { const c = await cfgGet(); return json({ cfg: { clickMul: c.clickMul, incomeMul: c.incomeMul, priceMul: c.priceMul, shopSale: c.shopSale || 0, maintenance: !!c.maintenance, maintText: c.maintText } }); }
  if (route === 'POST /api/admin/config') {
    const b = await readBody(req), c = await cfgGet(), notes = [];
    for (const [k, n] of [['clickMul', 'доход за клик'], ['incomeMul', 'пассивный доход'], ['priceMul', 'цены улучшений']]) {
      if (b[k] === undefined) continue;
      const v = Number(b[k]); if (!Number.isFinite(v) || v < 0.1 || v > 100) throw fail(400, 'Множитель должен быть от 0.1 до 100');
      if (v !== c[k]) notes.push(n + ' ×' + v); c[k] = v;
    }
    if (b.shopSale !== undefined) { const v = Number(b.shopSale); if (!Number.isFinite(v) || v < 0 || v > 90) throw fail(400, 'Скидка: от 0 до 90%'); if (v !== (c.shopSale || 0)) notes.push('скидка в магазине ' + v + '%'); c.shopSale = v; }
    if (typeof b.maintenance === 'boolean') { if (b.maintenance !== !!c.maintenance) notes.push(b.maintenance ? 'техработы ВКЛ' : 'техработы ВЫКЛ'); c.maintenance = b.maintenance; }
    if (typeof b.maintText === 'string' && b.maintText.trim()) c.maintText = b.maintText.trim().slice(0, 200);
    await meta.setJSON('cfg', c); dropPub();
    if (notes.length) await audit('Экономика: ' + notes.join(', '), '');
    return json({ ok: true, cfg: { clickMul: c.clickMul, incomeMul: c.incomeMul, priceMul: c.priceMul, shopSale: c.shopSale || 0, maintenance: !!c.maintenance, maintText: c.maintText } });
  }
  if (route === 'GET /api/admin/settings') return json({ settings: (await meta.get('settings', { type: 'json' })) || { regOpen: true } });
  if (route === 'POST /api/admin/settings') {
    const b = await readBody(req), s = (await meta.get('settings', { type: 'json' })) || { regOpen: true };
    if (typeof b.regOpen === 'boolean') s.regOpen = b.regOpen;
    await meta.setJSON('settings', s); await audit('Регистрация ' + (s.regOpen ? 'открыта' : 'закрыта'), ''); return json({ ok: true, settings: s });
  }

  if (route === 'POST /api/admin/password') {
    const b = await readBody(req), np = String(b.new || '');
    if ((await checkPw(String(b.old || ''))) !== true) throw fail(401, 'Текущий пароль неверный');
    if (np.length < 8 || np.length > 100) throw fail(400, 'Новый пароль: от 8 до 100 символов');
    const salt = crypto.randomBytes(16).toString('hex'); await meta.setJSON('adminpw', { salt, hash: await hashPw(np, salt) });
    await audit('Смена пароля администратора', ''); return json({ ok: true });
  }
  if (route === 'GET /api/admin/audit') return json({ list: ((await meta.get('audit', { type: 'json' })) || []).slice().reverse().slice(0, 100) });
  if (route === 'POST /api/admin/revoke') {
    const { blobs } = await asess.list(); for (const b of blobs) if (b.key !== sha(tok)) await asess.delete(b.key);
    await audit('Завершены все другие сессии', ''); return json({ ok: true, n: blobs.length - 1 });
  }
  return null;
}
