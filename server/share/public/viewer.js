// Decrypts a lockbox share entirely in this browser. Key schedule (must match crates/platform/src/share.rs):
//   K = 32 random bytes from the #fragment
//   P = PBKDF2-SHA256(passphrase, salt = K, 600000 iterations, 32 bytes)      (only with a passphrase)
//   64 bytes = HKDF-SHA256(ikm = K || P, salt = "lockbox-share", info = "lockbox-share-v1")
//   aes key = bytes[0..32], verifier = base64url(SHA-256(bytes[32..64] || id))
//   blob = 0x01 | flags | nonce(12) | AES-256-GCM(ciphertext, aad = "lockbox-share-v1:" + id)
const card = document.getElementById('card');
const id = location.pathname.split('/').pop();
const keyText = location.hash.slice(1);
history.replaceState(null, '', location.pathname); // keep the key out of browser history

const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64 = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4)); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };
const concat = (...a) => { const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let o = 0; for (const x of a) { out.set(x, o); o += x.length; } return out; };

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v; else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v); else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c);
  return el;
}
const show = (...kids) => card.replaceChildren(h('div', { class: 'mark', 'aria-hidden': 'true' }), ...kids);
const gone = () => show(h('h1', {}, 'This link has expired'), h('p', { class: 'muted' }, 'It was already opened, it expired, or the sender revoked it. Ask them to share it again.'));

function when(ms) {
  const s = Math.max(0, Math.round((ms - Date.now()) / 1000));
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} days`;
}

async function keys(passphrase) {
  const k = unb64(keyText);
  if (k.length !== 32) throw new Error('incomplete');
  let ikm = k;
  if (passphrase !== null) {
    const pw = await crypto.subtle.importKey('raw', enc.encode(passphrase.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    ikm = concat(k, new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: k, iterations: 600000 }, pw, 256)));
  }
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode('lockbox-share'), info: enc.encode('lockbox-share-v1') }, base, 512));
  const aes = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['decrypt']);
  const verifier = b64(await crypto.subtle.digest('SHA-256', concat(bits.slice(32), enc.encode(id))));
  return { aes, verifier };
}

async function decrypt(aes, blobText) {
  const blob = unb64(blobText);
  if (blob[0] !== 1) throw new Error('unknown format');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(2, 14), additionalData: enc.encode('lockbox-share-v1:' + id) }, aes, blob.slice(14));
  return JSON.parse(new TextDecoder().decode(pt));
}

// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) from an otpauth:// URI or base32 secret
async function totp(secret) {
  let s = secret, digits = 6, period = 30, algo = 'SHA-1';
  if (s.startsWith('otpauth://')) {
    const u = new URL(s); s = u.searchParams.get('secret') || '';
    digits = Number(u.searchParams.get('digits') || 6); period = Number(u.searchParams.get('period') || 30);
    algo = { SHA256: 'SHA-256', SHA512: 'SHA-512' }[(u.searchParams.get('algorithm') || '').toUpperCase()] || 'SHA-1';
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.toUpperCase().replace(/[\s=]/g, '')) { const v = alphabet.indexOf(c); if (v < 0) return null; bits += v.toString(2).padStart(5, '0'); }
  const key = Uint8Array.from(bits.match(/.{8}/g) || [], (b) => parseInt(b, 2));
  const counter = Math.floor(Date.now() / 1000 / period);
  const msg = new Uint8Array(8); new DataView(msg.buffer).setUint32(4, counter);
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: algo }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  const o = mac[mac.length - 1] & 15;
  const n = ((mac[o] & 127) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3];
  return { code: String(n % 10 ** digits).padStart(digits, '0'), left: period - (Math.floor(Date.now() / 1000) % period) };
}

const copyBtn = (value, label) => h('button', { type: 'button', 'aria-label': 'Copy ' + label, onClick: async (e) => {
  await navigator.clipboard.writeText(value); e.target.textContent = 'Copied'; setTimeout(() => (e.target.textContent = 'Copy'), 1500);
} }, 'Copy');
const pw = (s) => h('span', {}, [...s].map((c) => (/[0-9]/.test(c) ? h('span', { class: 'd' }, c) : /[A-Za-z]/.test(c) ? c : h('span', { class: 'y' }, c))));

function render(item, res) {
  const rows = [];
  const row = (k, v, copy, cls = '') => rows.push(h('div', { class: 'f' }, h('div', { class: 'kv' }, h('span', { class: 'k' }, k), h('span', { class: 'v ' + cls }, v)), copy != null && copyBtn(copy, k)));
  if (item.username) row('username', item.username, item.username);
  if (item.password) row('password', pw(item.password), item.password, 'mono');
  for (const u of item.urls || []) row('website', u, u);
  if (item.totp) {
    const code = h('span', { class: 'v code' }, '––– –––');
    const left = h('span', { class: 'faint' }, '');
    const copy = h('button', { type: 'button', onClick: async () => { const t = await totp(item.totp); if (t) await navigator.clipboard.writeText(t.code); } }, 'Copy');
    rows.push(h('div', { class: 'f' }, h('div', { class: 'kv' }, h('span', { class: 'k' }, 'one-time code'), code, left), copy));
    const tick = async () => { const t = await totp(item.totp); if (t) { code.textContent = t.code.slice(0, 3) + ' ' + t.code.slice(3); left.textContent = `${t.left}s left · secret: ${item.totp.startsWith('otpauth://') ? 'otpauth link' : item.totp}`; } };
    tick(); setInterval(tick, 1000);
  }
  for (const f of item.fields || []) row(f.name, f.value, f.value);
  if (item.notes) row('notes', item.notes, null, 'notes');
  const after = res.viewsLeft === null ? `This link keeps working for ${when(res.expiresAt)}.` : res.viewsLeft === 0 ? 'This link is now used up. Save what you need before closing this page.' : `This link can be opened ${res.viewsLeft} more time${res.viewsLeft === 1 ? '' : 's'}.`;
  show(h('h1', {}, item.title || 'Shared login'), rows.length ? h('div', { class: 'fields' }, rows) : h('p', { class: 'muted' }, 'Nothing was included.'), h('p', { class: res.viewsLeft === 0 ? 'warn' : 'faint' }, after));
}

async function main() {
  if (!keyText) return show(h('h1', {}, 'This link is incomplete'), h('p', { class: 'muted' }, 'The part after # is missing. Copy the whole link the sender gave you.'));
  const r = await fetch(`/api/shares/${id}`, { cache: 'no-store' });
  if (!r.ok) return gone();
  const meta = await r.json();
  const pass = meta.passphrase ? h('input', { type: 'password', id: 'pp', autocomplete: 'off', placeholder: 'Passphrase from the sender' }) : null;
  const err = h('p', { class: 'warn', role: 'alert' });
  const btn = h('button', { class: 'primary', type: 'button' }, 'Reveal');
  const views = meta.viewsLeft === null ? 'Opens any number of times' : meta.viewsLeft === 1 ? 'Opens once' : `Opens ${meta.viewsLeft} more times`;
  show(
    h('h1', {}, 'A login was shared with you'),
    h('div', { class: 'chips' }, h('span', { class: 'chip' }, views), h('span', { class: 'chip' }, 'Expires in ' + when(meta.expiresAt))),
    h('p', { class: 'muted' }, meta.viewsLeft === 1 ? 'Revealing it uses up the link, so have somewhere ready to save it.' : 'Press Reveal to decrypt it here in your browser.'),
    pass && h('label', { for: 'pp' }, 'Passphrase'), pass, err, btn);
  (pass || btn).focus();
  const go = async () => {
    btn.disabled = true; btn.textContent = 'Decrypting…'; err.textContent = '';
    try {
      const k = await keys(pass ? pass.value : null);
      // checked before opening, so a typo never uses up the link
      if (k.verifier !== meta.verifier) { err.textContent = pass ? 'That passphrase isn’t right.' : 'This link looks damaged. Copy the whole link again.'; btn.disabled = false; btn.textContent = 'Reveal'; return; }
      const o = await fetch(`/api/shares/${id}/open`, { method: 'POST', cache: 'no-store' });
      if (!o.ok) return gone();
      const res = await o.json();
      render(await decrypt(k.aes, res.ciphertext), res);
    } catch (e) {
      err.textContent = e.message === 'incomplete' ? 'This link is incomplete. Copy the whole link again.' : 'Couldn’t decrypt this share.';
      btn.disabled = false; btn.textContent = 'Reveal';
    }
  };
  btn.addEventListener('click', go);
  pass?.addEventListener('keydown', (e) => e.key === 'Enter' && go());
}

main().catch((e) => { console.error(e); gone(); });
