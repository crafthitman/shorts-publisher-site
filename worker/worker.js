// Shorts Publisher API (Cloudflare Worker).
// Holds the TikTok client secret, does the TikTok login (Login Kit) and posting (Content Posting API, Direct Post).
// The website (https://crafthitman.github.io/shorts-publisher-site/) is the user interface; this Worker is its backend.
//
// Bindings (Cloudflare dashboard > Worker > Settings):
//   KV namespace  STORE                 tokens, login states, queued videos
//   Secret        TIKTOK_CLIENT_KEY      from the TikTok app (Sandbox key for the demo, Production key after approval)
//   Secret        TIKTOK_CLIENT_SECRET
//   Secret        ADMIN_KEY              a password only the owner knows; every owner action must send it
// Optional variable SITE_ORIGIN (default https://crafthitman.github.io) and REDIRECT_URI (default below).

const SITE_ORIGIN_DEFAULT = 'https://crafthitman.github.io';
const REDIRECT_DEFAULT = 'https://crafthitman.github.io/shorts-publisher-site/callback.html';
const ACCOUNTS = ['history', 'deen'];
const SCOPES = 'user.info.basic,video.publish,video.upload';
const TT = 'https://open.tiktokapis.com/v2';

export default {
  async fetch(req, env) {
    const origin = env.SITE_ORIGIN || SITE_ORIGIN_DEFAULT;
    const cors = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Admin-Key',
      'Access-Control-Max-Age': '86400',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    try {
      const res = await route(req, env);
      const h = new Headers(res.headers);
      for (const [k, v] of Object.entries(cors)) h.set(k, v);
      return new Response(res.body, { status: res.status, headers: h });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: String(e && e.message || e) }), {
        status: 500, headers: { 'Content-Type': 'application/json', ...cors } });
    }
  },
};

const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });

function isAdmin(req, env) {
  const k = req.headers.get('X-Admin-Key') || '';
  if (!env.ADMIN_KEY || k.length !== env.ADMIN_KEY.length) return false;
  let diff = 0;
  for (let i = 0; i < k.length; i++) diff |= k.charCodeAt(i) ^ env.ADMIN_KEY.charCodeAt(i);
  return diff === 0;
}

async function route(req, env) {
  const url = new URL(req.url);
  const p = url.pathname.replace(/\/+$/, '');
  const m = req.method;

  if (p === '' || p === '/api/health') return json({ ok: true, service: 'shorts-publisher' });

  // Login step 2 (public): the callback page sends back the code TikTok gave it. Only states created by the owner work.
  if (p === '/api/auth/exchange' && m === 'POST') return authExchange(req, env);

  if (!isAdmin(req, env)) return json({ ok: false, error: 'wrong or missing admin password' }, 401);

  if (p === '/api/auth/start' && m === 'POST') return authStart(req, env);
  if (p === '/api/accounts' && m === 'GET') return accounts(env);
  if (p.startsWith('/api/accounts/') && m === 'DELETE') {
    await env.STORE.delete('tok:' + p.split('/').pop()); return json({ ok: true });
  }
  if (p === '/api/items' && m === 'GET') return listItems(env);
  if (p === '/api/items' && m === 'POST') return createItem(req, env);
  const im = p.match(/^\/api\/items\/([\w-]+)(?:\/(video|approve|post|status))?$/);
  if (im) {
    const [, id, action] = im;
    if (!action && m === 'DELETE') { await env.STORE.delete('item:' + id); await env.STORE.delete('vid:' + id); return json({ ok: true }); }
    if (action === 'video' && m === 'PUT') return putVideo(req, env, id);
    if (action === 'video' && m === 'GET') return getVideo(env, id);
    if (action === 'approve' && m === 'POST') return approve(req, env, id);
    if (action === 'post' && m === 'POST') return postItem(env, id);
    if (action === 'status' && m === 'GET') return status(env, id);
  }
  if (p === '/api/post-due' && m === 'POST') return postDue(env);
  return json({ ok: false, error: 'not found' }, 404);
}

// ---------------------------------------------------------------- login (Login Kit)
async function authStart(req, env) {
  const { account } = await req.json();
  if (!ACCOUNTS.includes(account)) return json({ ok: false, error: 'unknown account' }, 400);
  const nonce = crypto.randomUUID();
  await env.STORE.put('state:' + nonce, account, { expirationTtl: 600 });
  const q = new URLSearchParams({ client_key: env.TIKTOK_CLIENT_KEY, scope: SCOPES, response_type: 'code',
    redirect_uri: env.REDIRECT_URI || REDIRECT_DEFAULT, state: nonce });
  return json({ ok: true, url: 'https://www.tiktok.com/v2/auth/authorize/?' + q });
}

async function authExchange(req, env) {
  const { code, state } = await req.json();
  const account = state && await env.STORE.get('state:' + state);
  if (!account) return json({ ok: false, error: 'this login link expired or was not started from the dashboard' }, 400);
  await env.STORE.delete('state:' + state);
  const tok = await tokenCall(env, { code, grant_type: 'authorization_code', redirect_uri: env.REDIRECT_URI || REDIRECT_DEFAULT });
  await saveTok(env, account, tok);
  const info = await creatorInfo(env, account).catch(() => null);
  return json({ ok: true, account, creator: info });
}

async function tokenCall(env, params) {
  const body = new URLSearchParams({ client_key: env.TIKTOK_CLIENT_KEY, client_secret: env.TIKTOK_CLIENT_SECRET, ...params });
  const r = await fetch(TT + '/oauth/token/', { method: 'POST', body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Cache-Control': 'no-cache' } });
  const d = await r.json();
  if (!d.access_token) throw new Error('TikTok token error: ' + (d.error_description || d.error || JSON.stringify(d)));
  return d;
}

async function saveTok(env, account, d) {
  const now = Date.now();
  await env.STORE.put('tok:' + account, JSON.stringify({
    access_token: d.access_token, refresh_token: d.refresh_token, open_id: d.open_id, scope: d.scope,
    access_expires: now + (d.expires_in - 120) * 1000, refresh_expires: now + (d.refresh_expires_in || 0) * 1000 }));
}

async function accessToken(env, account) {
  const raw = await env.STORE.get('tok:' + account);
  if (!raw) throw new Error(account + ' is not connected to TikTok');
  const t = JSON.parse(raw);
  if (Date.now() < t.access_expires) return t.access_token;
  const d = await tokenCall(env, { grant_type: 'refresh_token', refresh_token: t.refresh_token });
  await saveTok(env, account, d);
  return d.access_token;
}

async function tt(env, account, path, body) {
  const r = await fetch(TT + path, { method: 'POST', body: JSON.stringify(body || {}),
    headers: { Authorization: 'Bearer ' + await accessToken(env, account), 'Content-Type': 'application/json; charset=UTF-8' } });
  const d = await r.json();
  if (d.error && d.error.code && d.error.code !== 'ok') throw new Error('TikTok: ' + d.error.code + ' ' + (d.error.message || ''));
  return d.data;
}

const creatorInfo = (env, account) => tt(env, account, '/post/publish/creator_info/query/');

async function accounts(env) {
  const out = {};
  for (const a of ACCOUNTS) {
    if (!await env.STORE.get('tok:' + a)) { out[a] = { connected: false }; continue; }
    try { out[a] = { connected: true, creator: await creatorInfo(env, a) }; }
    catch (e) { out[a] = { connected: true, error: String(e.message || e) }; }
  }
  return json({ ok: true, accounts: out });
}

// ---------------------------------------------------------------- queue
async function listItems(env) {
  const items = [];
  let cursor;
  do {
    const l = await env.STORE.list({ prefix: 'item:', cursor });
    for (const k of l.keys) { const v = await env.STORE.get(k.name); if (v) items.push(JSON.parse(v)); }
    cursor = l.list_complete ? null : l.cursor;
  } while (cursor);
  items.sort((a, b) => (a.slot || '').localeCompare(b.slot || ''));
  return json({ ok: true, items });
}

async function createItem(req, env) {
  const b = await req.json();
  if (!ACCOUNTS.includes(b.account)) return json({ ok: false, error: 'unknown account' }, 400);
  const id = b.id || crypto.randomUUID().slice(0, 12);
  const slot = b.slot ? new Date(b.slot).toISOString() : null;  // stored in UTC so time comparisons work
  if (b.slot && isNaN(Date.parse(b.slot))) return json({ ok: false, error: 'bad slot time' }, 400);
  const item = { id, account: b.account, caption: (b.caption || '').slice(0, 2200), slot,
    label: b.label || '', status: 'queued', created: new Date().toISOString() };
  await env.STORE.put('item:' + id, JSON.stringify(item));
  return json({ ok: true, item });
}

async function getItem(env, id) { const v = await env.STORE.get('item:' + id); if (!v) throw new Error('no such video'); return JSON.parse(v); }
const putItem = (env, it) => env.STORE.put('item:' + it.id, JSON.stringify(it));

async function putVideo(req, env, id) {
  const it = await getItem(env, id);
  const buf = await req.arrayBuffer();
  if (buf.byteLength > 24 * 1024 * 1024) return json({ ok: false, error: 'video larger than 24 MB' }, 400);
  await env.STORE.put('vid:' + id, buf);
  it.size = buf.byteLength; await putItem(env, it);
  return json({ ok: true, size: it.size });
}

async function getVideo(env, id) {
  const buf = await env.STORE.get('vid:' + id, { type: 'arrayBuffer' });
  if (!buf) return json({ ok: false, error: 'no video' }, 404);
  return new Response(buf, { headers: { 'Content-Type': 'video/mp4' } });
}

async function approve(req, env, id) {
  const it = await getItem(env, id);
  const s = await req.json();
  if (!s.privacy_level) return json({ ok: false, error: 'choose who can view this video' }, 400);
  if (s.brand_content_toggle && s.privacy_level === 'SELF_ONLY') return json({ ok: false, error: 'branded content cannot be private' }, 400);
  it.settings = { privacy_level: s.privacy_level, disable_comment: !!s.disable_comment, disable_duet: !!s.disable_duet,
    disable_stitch: !!s.disable_stitch, brand_content_toggle: !!s.brand_content_toggle,
    brand_organic_toggle: !!s.brand_organic_toggle, is_aigc: !!s.is_aigc };
  if (typeof s.caption === 'string') it.caption = s.caption.slice(0, 2200);
  it.status = 'approved'; it.approved_at = new Date().toISOString();
  await putItem(env, it);
  return json({ ok: true, item: it });
}

// ---------------------------------------------------------------- posting (Content Posting API, Direct Post, FILE_UPLOAD)
async function postItem(env, id) {
  const it = await getItem(env, id);
  if (!it.settings) return json({ ok: false, error: 'approve the post settings first' }, 400);
  if (it.status === 'posted' || it.status === 'posting') return json({ ok: true, item: it });
  const buf = await env.STORE.get('vid:' + id, { type: 'arrayBuffer' });
  if (!buf) return json({ ok: false, error: 'no video uploaded for this item' }, 400);
  const size = buf.byteLength;
  try {
    const init = await tt(env, it.account, '/post/publish/video/init/', {
      post_info: { title: it.caption, ...it.settings, video_cover_timestamp_ms: 1000 },
      source_info: { source: 'FILE_UPLOAD', video_size: size, chunk_size: size, total_chunk_count: 1 },
    });
    const up = await fetch(init.upload_url, { method: 'PUT', body: buf,
      headers: { 'Content-Type': 'video/mp4', 'Content-Length': String(size), 'Content-Range': `bytes 0-${size - 1}/${size}` } });
    if (!up.ok) throw new Error('upload failed: HTTP ' + up.status + ' ' + (await up.text()).slice(0, 200));
    it.publish_id = init.publish_id; it.status = 'posting'; it.posted_at = new Date().toISOString(); delete it.error;
  } catch (e) {
    it.status = 'failed'; it.error = String(e.message || e);
  }
  await putItem(env, it);
  return json({ ok: it.status !== 'failed', item: it });
}

async function status(env, id) {
  const it = await getItem(env, id);
  if (it.publish_id && it.status === 'posting') {
    const d = await tt(env, it.account, '/post/publish/status/fetch/', { publish_id: it.publish_id });
    it.tiktok_status = d.status;
    if (d.status === 'PUBLISH_COMPLETE') { it.status = 'posted'; it.post_ids = d.publicaly_available_post_id || d.publicly_available_post_id || []; await env.STORE.delete('vid:' + id); }
    if (d.status === 'FAILED') { it.status = 'failed'; it.error = d.fail_reason || 'TikTok reported FAILED'; }
    await putItem(env, it);
  }
  return json({ ok: true, item: it });
}

// Called by the owner's scheduler at each slot: posts approved videos whose time has come (max 2 per call).
async function postDue(env) {
  const now = new Date().toISOString();
  const { items } = await (await listItems(env)).json();
  const due = items.filter(i => i.status === 'approved' && i.slot && i.slot <= now).slice(0, 2);
  const done = [];
  for (const i of due) done.push((await (await postItem(env, i.id)).json()).item);
  return json({ ok: true, posted: done });
}
