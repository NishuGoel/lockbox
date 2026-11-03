// lockbox content script. Quiet until you act:
//  1. when you submit a login form, send what you typed to lockbox so it can offer to save it
//  2. when you ask (⌘⇧L or the popup), fill the fields lockbox sends
//  3. when you focus a login field, suggest this site's logins right there
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
    const decide = async (action) => {
      const r = await chrome.runtime.sendMessage({ type: 'decide', action });
      if (r?.error === 'locked') return p.say('lockbox is locked. Unlock it, then try again.');
      if (r?.error) return p.say(r.error === 'expired' ? 'This offer expired.' : r.error);
      const a = r.result?.action;
      if (a === 'site_added') p.done(`Added ${offer.host} to ${r.result.title}. lockbox fills it here now.`);
      else if (a === 'updated') p.done('Password updated. The old one is kept in history.');
      else if (a === 'added') p.done(`Saved to ${r.result.vault || 'lockbox'}.`);
      else p.close();
    };
    const who = [offer.host, offer.username].filter(Boolean).join(' · ');
    const later = { label: 'Not now', onClick: () => decide('dismiss') };
    const p = offer.status === 'add_site'
      ? panel({ title: `Already saved as ${offer.title}`, sub: who, message: '',
          buttons: [{ label: 'Add this site', kind: 'p', onClick: () => decide('save') }, { label: 'Save as new', onClick: () => decide('save_new') }, later] })
      : panel({ title: offer.status === 'changed' ? 'Update password in lockbox?' : 'Save to lockbox?', sub: offer.status === 'changed' ? [offer.title, offer.username].filter(Boolean).join(' · ') : who,
          buttons: [{ label: offer.status === 'changed' ? 'Update' : 'Save', kind: 'p', onClick: () => decide('save') }, later,
            { label: 'Never for this site', kind: 'l', onClick: () => decide('never') }] });
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

  // ---------- inline suggestions in login fields ----------
  // Appears only when you focus a login / 2FA / sign-up field and lockbox has something for this
  // frame's own site. Hardened against DOM clickjacking: trusted clicks only, ignored for the first
  // 300 ms, refused if the page made our UI (or the page itself) transparent, clipped, filtered or covered.
  const SEARCHY = /search|query|^q$/i;
  function fieldKind(el) {
    if (!(el instanceof HTMLInputElement) || !visible(el) || SEARCHY.test(attrs(el)) || el.type === 'search') return null;
    const scope = el.form || document;
    if (el.type === 'password') return el.autocomplete === 'new-password' || passwords(scope).length >= 2 ? 'new-password' : 'password';
    if (isOtp(el)) return 'otp';
    if (textLike(el) && (/username|email/.test(el.autocomplete) || USER_RE.test(attrs(el))) && (passwords(scope).length || /username|email|webauthn/.test(el.autocomplete))) return 'username';
    return null;
  }

  const MENU_CSS = `
    :host{all:initial;position:fixed;z-index:2147483647}
    .icon{width:22px;height:22px;border-radius:6px;display:flex;align-items:center;justify-content:center;background:rgba(18,21,28,.92);color:#5EEAD4;cursor:pointer;border:1px solid rgba(255,255,255,.14)}
    .icon.locked{color:#9BA3B4}
    .menu{box-sizing:border-box;min-width:280px;max-width:420px;padding:6px;border-radius:14px;background:rgba(18,21,28,.97);border:1px solid rgba(255,255,255,.12);
          box-shadow:0 18px 48px rgba(0,0,0,.45);color:#ECEEF3;font:14px/1.4 -apple-system,BlinkMacSystemFont,system-ui,sans-serif}
    .row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:9px;cursor:pointer}
    .row.on,.row:hover{background:rgba(255,255,255,.08)}
    .tile{width:28px;height:28px;flex:none;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;background:rgba(94,234,212,.14);color:#5EEAD4}
    .t{font-weight:600}.s{color:#9BA3B4;font-size:12px}
    .txt{display:flex;flex-direction:column;min-width:0}.txt span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .foot{display:flex;justify-content:space-between;padding:6px 10px 2px;color:#7C8497;font-size:11px}`;
  const LOCK_SVG = 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3';
  let inline = null;

  function makeHost(tag) {
    const host = document.createElement(tag);
    const root = host.attachShadow({ mode: 'closed' });
    const css = new CSSStyleSheet(); css.replaceSync(MENU_CSS); root.adoptedStyleSheets = [css];
    document.documentElement.append(host);
    return { host, root };
  }

  // the page must not be able to hide, fade, clip or cover our UI and trick you into clicking it
  function untampered(host, e) {
    if (!host.isConnected || host.parentElement !== document.documentElement) return false;
    for (const el of [host, document.documentElement, document.body].filter(Boolean)) {
      const cs = getComputedStyle(el);
      if (cs.opacity !== '1' || cs.visibility !== 'visible' || cs.display === 'none' || cs.filter !== 'none' || cs.clipPath !== 'none' || (cs.mask && cs.mask !== 'none' && cs.maskImage !== 'none') || cs.mixBlendMode !== 'normal') return false;
    }
    return !e || document.elementFromPoint(e.clientX, e.clientY) === host;
  }

  function closeInline() {
    if (!inline) return;
    inline.icon.host.remove(); inline.menu?.host.remove();
    removeEventListener('scroll', inline.place, true); removeEventListener('resize', inline.place);
    inline.field.removeEventListener('keydown', inline.keys, true);
    inline.field.removeEventListener('input', inline.typing);
    inline = null;
  }

  function place() {
    if (!inline) return;
    const r = inline.field.getBoundingClientRect();
    if (!r.width || r.bottom < 0 || r.top > innerHeight) return closeInline();
    Object.assign(inline.icon.host.style, { left: `${r.right - 28}px`, top: `${r.top + (r.height - 22) / 2}px` });
    if (inline.menu) Object.assign(inline.menu.host.style, { left: `${r.left}px`, top: `${r.bottom + 4}px`, minWidth: `${Math.max(r.width, 280)}px` });
  }

  async function choose(opt) {
    if (opt.action === 'open') { chrome.runtime.sendMessage({ type: 'open_app' }); return closeInline(); }
    if (opt.action === 'generate') {
      const g = await chrome.runtime.sendMessage({ type: 'suggest-generate' });
      if (g?.password) fillNewPassword(g.password);
      return closeInline();
    }
    const creds = await chrome.runtime.sendMessage({ type: 'suggest-fill', id: opt.item.id });
    if (creds && !creds.error) {
      if (inline?.kind === 'otp') { if (creds.totp) fillOtp(creds.totp); } else fill(creds);
    }
    closeInline();
  }

  function openMenu(options) {
    if (!inline || inline.menu) return;
    const { host, root } = makeHost('lockbox-menu');
    const shownAt = performance.now();
    const box = document.createElement('div'); box.className = 'menu'; box.setAttribute('role', 'listbox');
    const rows = options.map((o, i) => {
      const row = document.createElement('div'); row.className = 'row'; row.setAttribute('role', 'option');
      const tile = document.createElement('span'); tile.className = 'tile'; tile.textContent = o.letter;
      const txt = document.createElement('span'); txt.className = 'txt';
      const t = document.createElement('span'); t.className = 't'; t.textContent = o.title;
      const s2 = document.createElement('span'); s2.className = 's'; s2.textContent = o.sub || '';
      txt.append(t, s2); row.append(tile, txt);
      row.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus in the field
      row.addEventListener('click', (e) => {
        if (!e.isTrusted || performance.now() - shownAt < 300 || !untampered(host, e)) return;
        choose(o);
      });
      row.addEventListener('mouseenter', () => select(i));
      box.append(row);
      return row;
    });
    const foot = document.createElement('div'); foot.className = 'foot';
    const a = document.createElement('span'); a.textContent = 'lockbox'; const b = document.createElement('span'); b.textContent = '↓ ↵ to fill · esc';
    foot.append(a, b); box.append(foot);
    root.append(box);
    inline.menu = { host, rows, options, sel: -1, shownAt };
    const select = (i) => { inline.menu.sel = i; rows.forEach((r, n) => r.classList.toggle('on', n === i)); };
    inline.select = select;
    place();
  }

  async function onFocus(e) {
    const field = e.target;
    const kind = fieldKind(field);
    if (inline && inline.field === field) return;
    closeInline();
    if (!kind) return;
    const res = await chrome.runtime.sendMessage({ type: 'suggest' }).catch(() => null);
    if (!res || document.activeElement !== field || res.state === 'unavailable' || res.state === 'no_vault') return;
    const items = res.items || [];
    let options = [];
    if (res.state === 'locked') options = [{ action: 'open', letter: 'L', title: 'lockbox is locked', sub: 'Open lockbox to unlock, then click here again' }];
    else if (kind === 'new-password') options = [{ action: 'generate', letter: '*', title: 'Use a strong password', sub: 'Fills both password fields; saved when you submit' }];
    else if (kind === 'otp') options = items.filter((i) => i.hasTotp).map((i) => ({ item: i, letter: (i.title[0] || '?').toUpperCase(), title: `2FA code · ${i.title}`, sub: i.username || i.host }));
    else options = items.filter((i) => i.hasPassword || kind === 'username').map((i) => ({ item: i, letter: (i.title[0] || '?').toUpperCase(), title: i.title, sub: i.username || i.host }));
    if (!options.length) return; // nothing useful: stay quiet

    const icon = makeHost('lockbox-icon');
    const btn = document.createElement('div'); btn.className = 'icon' + (res.state === 'locked' ? ' locked' : ''); btn.setAttribute('role', 'button'); btn.setAttribute('aria-label', 'lockbox');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [k, v] of Object.entries({ width: 13, height: 13, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2.2, 'stroke-linecap': 'round' })) svg.setAttribute(k, v);
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', LOCK_SVG); svg.append(path); btn.append(svg);
    btn.addEventListener('mousedown', (ev) => ev.preventDefault());
    btn.addEventListener('click', (ev) => { if (ev.isTrusted && untampered(icon.host, ev)) inline?.menu ? (inline.menu.host.remove(), (inline.menu = null)) : openMenu(options); });
    icon.root.append(btn);

    const keys = (ev) => {
      const m = inline?.menu;
      if (ev.key === 'Escape') { if (m) { m.host.remove(); inline.menu = null; ev.preventDefault(); } return; }
      if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
        if (!m) { openMenu(options); }
        const mm = inline.menu; const n = mm.rows.length;
        inline.select(ev.key === 'ArrowDown' ? (mm.sel + 1) % n : (mm.sel - 1 + n) % n);
        ev.preventDefault(); ev.stopPropagation();
        return;
      }
      // Enter only fills once you've picked a row with the arrows, and only if our UI is intact
      if (ev.key === 'Enter' && m && m.sel >= 0 && ev.isTrusted && untampered(m.host)) { ev.preventDefault(); ev.stopPropagation(); choose(m.options[m.sel]); }
    };
    inline = { field, kind, icon, menu: null, place, keys };
    const typing = () => { if (inline?.menu) { inline.menu.host.remove(); inline.menu = null; } }; // you're typing it yourself: get out of the way
    inline.typing = typing;
    field.addEventListener('keydown', keys, true);
    field.addEventListener('input', typing);
    addEventListener('scroll', place, true); addEventListener('resize', place);
    place();
    // open right away on an empty field when there's exactly what you'd expect (saved logins / 2FA / sign-up)
    if (res.state === 'unlocked' && !field.value) openMenu(options);
  }

  document.addEventListener('focusin', (e) => { onFocus(e).catch(() => {}); }, true);
  document.addEventListener('focusout', (e) => {
    if (inline && e.target === inline.field) setTimeout(() => { if (inline && document.activeElement !== inline.field) closeInline(); }, 150);
  }, true);

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
