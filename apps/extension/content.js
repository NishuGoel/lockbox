// lockbox content script. Two jobs, both quiet until you act:
//  1. when you submit a login form, send what you typed to lockbox so it can offer to save it
//  2. when you ask (⌘⇧L or the popup), fill the fields lockbox sends
// It never reads fields before you submit, and runs in an isolated world the page can't see.
(() => {
  if (window.__lockbox) return;
  window.__lockbox = true;

  const visible = (el) => !!el && !el.disabled && !el.readOnly && el.type !== 'hidden' && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  const inputs = (scope) => [...(scope || document).querySelectorAll('input')].filter(visible);
  const passwords = (scope) => inputs(scope).filter((i) => i.type === 'password');
  const USER_RE = /user|email|e-mail|login|account|phone|mobile|identifier|name/i;
  const OTP_RE = /otp|totp|2fa|mfa|one.?time|verif|security.?code|auth.?code|\bcode\b|token/i;
  const textLike = (i) => ['text', 'email', 'tel', ''].includes(i.type) || !i.getAttribute('type');
  const attrs = (i) => [i.name, i.id, i.autocomplete, i.placeholder, i.getAttribute('aria-label')].join(' ');
  const isOtp = (i) => (textLike(i) || i.type === 'number') && (i.autocomplete === 'one-time-code' || (OTP_RE.test(attrs(i)) && !/user|email/i.test(attrs(i))));
  const SUBMIT_RE = /log\s?in|sign\s?in|sign\s?up|continue|next|submit|register|create|join|save|update|change|verify|anmelden|weiter/i;
  const submitLike = (b) => b.type === 'submit' || (b.tagName === 'BUTTON' && !b.getAttribute('type') && !!b.form) || SUBMIT_RE.test(b.textContent + ' ' + (b.value || '') + ' ' + (b.getAttribute('aria-label') || ''));

  function usernameFor(pw, scope) {
    const cands = inputs(pw?.form || scope).filter((i) => textLike(i) && !isOtp(i));
    const before = pw ? cands.filter((i) => i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING) : cands;
    const pool = before.length ? before : cands;
    return pool.reverse().find((i) => /username|email/.test(i.autocomplete) || USER_RE.test(attrs(i))) || pool[0] || null;
  }

  function setValue(el, v) {
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // ---------- capture ----------
  let lastSent = '';
  function capture(scope) {
    const pws = passwords(scope).filter((p) => p.value);
    if (!pws.length) {
      // first step of a two-step login (username only)
      const u = usernameFor(null, scope);
      if (u?.value && !isOtp(u)) chrome.runtime.sendMessage({ type: 'username', username: u.value.trim() }).catch(() => {});
      return;
    }
    const fresh = pws.filter((p) => p.autocomplete === 'new-password');
    // sign-up / change-password forms: the new password is the last one (usually "confirm")
    const pw = (fresh.length ? fresh : pws).at(-1);
    const user = usernameFor(pws[0], scope)?.value?.trim() || '';
    const key = location.host + '\n' + user + '\n' + pw.value;
    if (key === lastSent) return;
    lastSent = key;
    chrome.runtime.sendMessage({ type: 'captured', url: location.href, username: user, password: pw.value }).catch(() => {});
  }
  const scopeOf = (el) => el?.closest?.('form') || document;
  document.addEventListener('submit', (e) => capture(e.target), true);
  document.addEventListener('click', (e) => {
    const b = e.target.closest?.('button, input[type=submit], input[type=button], [role=button]');
    if (b && submitLike(b)) capture(scopeOf(b));
  }, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.tagName === 'INPUT') capture(scopeOf(e.target)); }, true);

  // ---------- fill ----------
  function fillOtp(code) {
    const boxes = inputs().filter((i) => i.maxLength === 1 && textLike(i));
    if (boxes.length >= 4 && boxes.length <= 8) { boxes.slice(0, code.length).forEach((b, n) => setValue(b, code[n])); return true; }
    const f = inputs().find(isOtp);
    if (f) { setValue(f, code); return true; }
    return false;
  }

  function fill({ username, password, totp }) {
    const pw = passwords()[0];
    if (pw && password) {
      const u = usernameFor(pw, document);
      if (u && username) setValue(u, username);
      setValue(pw, password);
      return 'login';
    }
    if (totp && fillOtp(totp)) return 'totp';
    const u = usernameFor(null, document);
    if (u && username) { setValue(u, username); return 'username'; }
    return null;
  }

  function fillNewPassword(password) {
    const pws = passwords();
    const fresh = pws.filter((p) => p.autocomplete === 'new-password');
    const targets = fresh.length ? fresh : pws.filter((p) => !p.value);
    targets.forEach((p) => setValue(p, password));
    return targets.length ? 'new-password' : null;
  }

  // ---------- panel (save offers + passkey prompts) ----------
  // Closed shadow root: page scripts can't read or reach it, and every button ignores synthetic
  // (untrusted) clicks, so a page can't approve anything on your behalf.
  const CSS = `
    :host{all:initial;position:fixed;z-index:2147483647;top:16px;right:16px}
    .b{width:340px;box-sizing:border-box;padding:16px;border-radius:18px;background:rgba(18,21,28,.97);backdrop-filter:blur(24px) saturate(140%);
       border:1px solid rgba(255,255,255,.12);box-shadow:0 24px 60px rgba(0,0,0,.45);color:#ECEEF3;font:14px/1.45 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;animation:in .22s ease-out}
    @keyframes in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
    .top{display:flex;gap:12px;align-items:center}
    .mark{width:34px;height:34px;flex:none;border-radius:10px;display:flex;align-items:center;justify-content:center;background:rgba(94,234,212,.14);color:#5EEAD4}
    .t{font-weight:650}.s{color:#9BA3B4;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:250px}
    .row{display:flex;gap:8px;margin-top:14px;align-items:center}
    .list{display:flex;flex-direction:column;gap:4px;margin-top:12px}
    button{font:inherit;cursor:pointer;border-radius:10px;height:34px;padding:0 14px;border:1px solid rgba(255,255,255,.14);background:transparent;color:#ECEEF3}
    button:hover{background:rgba(255,255,255,.06)}
    button.p{background:#5EEAD4;color:#06201C;border-color:transparent;font-weight:600}
    button.l{border:0;padding:0 4px;color:#7C8497;font-size:12px;margin-left:auto;height:auto}
    button.acct{height:auto;padding:9px 12px;text-align:left;display:flex;flex-direction:column;border-color:rgba(255,255,255,.1)}
    button.acct span{color:#9BA3B4;font-size:12px}
    button:focus-visible{outline:2px solid #5EEAD4;outline-offset:2px}
    .msg{margin-top:10px;font-size:13px;color:#FDBA74}.msg:empty{display:none}
    .ok{color:#5EEAD4}`;
  const KEY_PATH = 'M14 10a4 4 0 1 0-3.5 4L9 16H7v2H5v2H3v-3l6.5-6.5A4 4 0 0 0 14 10zM15.5 8.5v.01';
  const LOCK_PATH = 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3';
  let current;

  function panel({ title, sub, icon = LOCK_PATH, buttons = [], accounts = [], message = '' }) {
    current?.close();
    const host = document.createElement('lockbox-offer');
    const root = host.attachShadow({ mode: 'closed' });
    const css = new CSSStyleSheet(); css.replaceSync(CSS); root.adoptedStyleSheets = [css];
    const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; };
    const trusted = (fn) => (e) => { if (e.isTrusted) fn(e); };
    const box = el('div', 'b'); box.setAttribute('role', 'dialog'); box.setAttribute('aria-label', 'lockbox');
    const mark = el('div', 'mark');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [k, v] of Object.entries({ width: 18, height: 18, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' })) svg.setAttribute(k, v);
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', icon); svg.append(path); mark.append(svg);
    const words = el('div'); words.append(el('div', 't', title), el('div', 's', sub || ''));
    const top = el('div', 'top'); top.append(mark, words);
    box.append(top);
    if (accounts.length) {
      const list = el('div', 'list');
      for (const a of accounts) {
        const b = el('button', 'acct', a.label); b.append(el('span', '', a.detail || ''));
        b.addEventListener('click', trusted(a.onClick)); list.append(b);
      }
      box.append(list);
    }
    const row = el('div', 'row');
    for (const b of buttons) { const e = el('button', b.kind || '', b.label); e.addEventListener('click', trusted(b.onClick)); row.append(e); }
    const msg = el('div', 'msg', message);
    box.append(row, msg);
    root.append(box);
    document.documentElement.append(host);
    (root.querySelector('button.acct, button.p') || root.querySelector('button'))?.focus({ preventScroll: true });
    const api = {
      say(text, ok) { msg.textContent = text; msg.className = ok ? 'msg ok' : 'msg'; },
      done(text) { row.remove(); box.querySelector('.list')?.remove(); api.say(text, true); setTimeout(api.close, 2200); },
      close() { host.remove(); if (current === api) current = null; },
    };
    current = api;
    return api;
  }

  function showOffer(offer) {
    if (window.top !== window) return;
    const changed = offer.status === 'changed';
    const decide = async (action) => {
      const r = await chrome.runtime.sendMessage({ type: 'decide', action });
      if (r?.error === 'locked') return p.say('lockbox is locked. Unlock it, then press Save again.');
      if (r?.error) return p.say(r.error === 'expired' ? 'This offer expired.' : r.error);
      if (action === 'save') p.done(r.result.action === 'updated' ? 'Password updated. The old one is kept in history.' : `Saved to ${r.result.vault || 'lockbox'}.`);
      else p.close();
    };
    const p = panel({
      title: changed ? 'Update password in lockbox?' : 'Save to lockbox?',
      sub: [offer.title, offer.username].filter(Boolean).join(' · '),
      message: offer.status === 'locked' ? 'lockbox is locked. Unlock it, then press Save.' : '',
      buttons: [
        { label: changed ? 'Update' : 'Save', kind: 'p', onClick: () => decide('save') },
        { label: 'Not now', onClick: () => decide('dismiss') },
        { label: 'Never for this site', kind: 'l', onClick: () => decide('never') },
      ],
    });
  }

  // ---------- passkeys: bridge from webauthn.js (page world) ----------
  const pending = new Map();
  const answer = (id, result) => { if (!pending.has(id)) return; pending.get(id)?.close(); pending.delete(id); window.postMessage({ __lockbox: 'res', id, result }, location.origin); };

  async function passkey(id, kind, data) {
    const pre = await chrome.runtime.sendMessage({ type: 'pk-pre', kind, data }).catch(() => ({ fallback: true }));
    if (!pending.has(id)) return; // aborted meanwhile
    if (pre.fallback) return answer(id, { fallback: true });
    const site = data.rpId;
    const other = { label: 'Other options', onClick: () => answer(id, { fallback: true }) };
    if (pre.locked) {
      const p = panel({ title: 'lockbox is locked', sub: kind === 'create' ? `Unlock to save a passkey for ${site}` : `Unlock to sign in to ${site}`, icon: KEY_PATH,
        buttons: [{ label: 'Open lockbox', kind: 'p', onClick: () => { chrome.runtime.sendMessage({ type: 'open_app' }); p.say('Unlock lockbox, then press Try again.'); } },
          { label: 'Try again', onClick: () => passkey(id, kind, data) }, other] });
      pending.set(id, p);
      return;
    }
    if (kind === 'create') {
      const p = panel({ title: 'Save passkey in lockbox?', sub: [site, data.userName].filter(Boolean).join(' · '), icon: KEY_PATH,
        buttons: [{ label: 'Save passkey', kind: 'p', onClick: async () => {
          const r = await chrome.runtime.sendMessage({ type: 'pk-create', data });
          if (r.fallback) return answer(id, { fallback: true });
          if (r.error) return p.say(String(r.error).replace(/^\w+Error: /, ''));
          p.done('Passkey saved in lockbox.'); pending.set(id, null); answer(id, { response: r.response });
        } }, other] });
      pending.set(id, p);
      return;
    }
    if (!pre.items.length) return answer(id, { fallback: true });
    const p = panel({ title: 'Sign in with a passkey', sub: `${site} · from lockbox`, icon: KEY_PATH,
      accounts: pre.items.map((a) => ({ label: a.userName || a.title, detail: a.displayName && a.displayName !== a.userName ? a.displayName : a.title, onClick: async () => {
        const r = await chrome.runtime.sendMessage({ type: 'pk-get', data: { ...data, id: a.id } });
        if (r.error) return p.say(String(r.error).replace(/^\w+Error: /, ''));
        pending.set(id, null); p.close(); answer(id, { response: r.response });
      } })),
      buttons: [other] });
    pending.set(id, p);
  }

  window.addEventListener('message', (e) => {
    if (e.source !== window || typeof e.data?.__lockbox !== 'string') return;
    const { __lockbox: kind, id, data } = e.data;
    if (kind === 'abort') { pending.get(id)?.close(); pending.delete(id); return; }
    if (kind !== 'req' || pending.has(id) || window.top !== window) return;
    window.postMessage({ __lockbox: 'ack', id }, location.origin);
    pending.set(id, null);
    passkey(id, e.data.kind, data);
  });

  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (msg.type === 'fill') reply({ filled: fill(msg.creds) });
    else if (msg.type === 'fill-new-password') reply({ filled: fillNewPassword(msg.password) });
    else if (msg.type === 'offer') showOffer(msg.offer);
  });

  if (window.top === window) {
    const ask = () => chrome.runtime.sendMessage({ type: 'offer?' }).then((r) => r?.offer && showOffer(r.offer)).catch(() => {});
    document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', ask) : ask();
  }
})();
