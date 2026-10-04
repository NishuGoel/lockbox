// lockbox share links. Stores only ciphertext; the decryption key lives in the link's #fragment,
// which browsers never send. One Durable Object per share gives strongly consistent view counting,
// and its alarm deletes the share at expiry.
import { DurableObject } from 'cloudflare:workers';

const MAX_BYTES = 64 * 1024;
const MAX_TTL = 30 * 86400;
const MAX_VIEWS = 100;
const ID = /^[A-Za-z0-9_-]{22}$/; // 16 random bytes, base64url
const B64 = /^[A-Za-z0-9_-]+$/;

const SECURITY = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY' };
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export class Share extends DurableObject {
  async create(rec) {
    if (await this.ctx.storage.get('rec')) return false;
    await this.ctx.storage.put('rec', rec);
    await this.ctx.storage.setAlarm(rec.expiresAt);
    return true;
  }
  async peek() {
    const r = await this.live();
    return r && { viewsLeft: r.viewsLeft, expiresAt: r.expiresAt, passphrase: r.passphrase, verifier: r.verifier };
  }
  /** Hands out the ciphertext and counts the view; the last view deletes the share. */
  async open() {
    const r = await this.live();
    if (!r) return null;
    if (r.viewsLeft !== null) {
      r.viewsLeft -= 1;
      if (r.viewsLeft <= 0) await this.wipe();
      else await this.ctx.storage.put('rec', r);
    }
    return { ciphertext: r.ciphertext, viewsLeft: r.viewsLeft, expiresAt: r.expiresAt };
  }
  async revoke() { await this.wipe(); }
  async alarm() { await this.ctx.storage.deleteAll(); }
  async live() {
    const r = await this.ctx.storage.get('rec');
    if (!r) return null;
    if (Date.now() >= r.expiresAt) { await this.wipe(); return null; }
    return r;
  }
  async wipe() {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }
}

const json = (body, status = 200) => new Response(body === null ? null : JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...SECURITY },
});

function authorized(req, env) {
  if (!env.CREATE_TOKEN) return false;
  const enc = new TextEncoder();
  const got = enc.encode(req.headers.get('authorization') || '');
  const want = enc.encode('Bearer ' + env.CREATE_TOKEN);
  return got.byteLength === want.byteLength && crypto.subtle.timingSafeEqual(got, want);
}

const share = (env, id) => env.SHARES.get(env.SHARES.idFromName(id));

async function asset(req, env, path, extra = {}) {
  const res = await env.ASSETS.fetch(new Request(new URL(path, req.url), req));
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries({ ...SECURITY, ...extra })) out.headers.set(k, v);
  return out;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const parts = url.pathname.split('/').filter(Boolean);

    if (parts[0] === 'api') {
      const [, kind, id, action] = parts;
      if (kind === 'health') return json({ ok: true, authorized: authorized(req, env) });
      if (kind !== 'shares') return json({ error: 'not found' }, 404);

      if (!id && req.method === 'POST') {
        if (!authorized(req, env)) return json({ error: 'unauthorized' }, 401);
        const text = await req.text();
        if (text.length > MAX_BYTES) return json({ error: 'too large' }, 413);
        let b; try { b = JSON.parse(text); } catch { return json({ error: 'bad json' }, 400); }
        const minTtl = Number(env.MIN_TTL_SECONDS || 60);
        const views = b.views === null ? null : Number(b.views);
        const ttl = Number(b.ttl);
        if (!ID.test(b.id || '') || !B64.test(b.ciphertext || '') || !B64.test(b.verifier || '')) return json({ error: 'bad share' }, 400);
        if (views !== null && !(Number.isInteger(views) && views >= 1 && views <= MAX_VIEWS)) return json({ error: 'bad views' }, 400);
        if (!(Number.isInteger(ttl) && ttl >= minTtl && ttl <= MAX_TTL)) return json({ error: 'bad ttl' }, 400);
        const rec = { ciphertext: b.ciphertext, verifier: b.verifier, passphrase: !!b.passphrase, viewsLeft: views, expiresAt: Date.now() + ttl * 1000 };
        if (!(await share(env, b.id).create(rec))) return json({ error: 'exists' }, 409);
        return json({ id: b.id, expiresAt: rec.expiresAt }, 201);
      }
      if (!ID.test(id || '')) return json({ error: 'not found' }, 404);
      if (!action && req.method === 'GET') {
        const meta = await share(env, id).peek();
        return meta ? json(meta) : json({ error: 'gone' }, 404);
      }
      if (action === 'open' && req.method === 'POST') {
        const r = await share(env, id).open();
        return r ? json(r) : json({ error: 'gone' }, 404);
      }
      if (!action && req.method === 'DELETE') {
        if (!authorized(req, env)) return json({ error: 'unauthorized' }, 401);
        await share(env, id).revoke();
        return json(null, 204);
      }
      return json({ error: 'not found' }, 404);
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('method not allowed', { status: 405, headers: SECURITY });
    // link previews (Slack, iMessage) only ever get this static page; nothing is opened until "Reveal"
    if (parts[0] === 's' && ID.test(parts[1] || '')) {
      return asset(req, env, '/viewer.html', { 'content-security-policy': CSP, 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' });
    }
    if (url.pathname === '/') return asset(req, env, '/index.html', { 'content-security-policy': CSP });
    return asset(req, env, url.pathname, { 'content-security-policy': CSP });
  },
};
