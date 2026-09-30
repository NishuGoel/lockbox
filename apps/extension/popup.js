// Popup: logins for this site (click = fill), search everything (other sites = copy only), generate.
const main = document.getElementById('main');
const send = (msg) => chrome.runtime.sendMessage(msg);

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'hue') el.style.setProperty('--hue', v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c);
  return el;
}
const HUES = ['#A78BFA', '#FB923C', '#34D399', '#F472B6', '#60A5FA', '#FACC15', '#818CF8', '#F87171', '#4ADE80', '#22D3EE'];
const hue = (s) => { let n = 0; for (const c of s) n = (n * 31 + c.charCodeAt(0)) >>> 0; return HUES[n % HUES.length]; };

function note(text) {
  document.querySelector('.toast')?.remove();
  main.append(h('div', { class: 'toast', role: 'status' }, text));
}

function row(item) {
  const act = item.matches
    ? async () => { const r = await send({ type: 'fill', item }); if (r.filled) window.close(); else note('No login fields found on this page.'); }
    : async () => { const r = await send({ type: 'copy', id: item.id, field: 'password' }); note(r.error ? r.error : `Copied ${item.title}'s password · clears in 90s`); };
  return h('button', { class: 'row', onClick: act, title: item.matches ? 'Fill' : `Saved for ${item.host || 'another site'}: copy instead of fill` },
    h('span', { class: 'tile', hue: hue(item.title) }, (item.title[0] || '?').toUpperCase()),
    h('span', { class: 'txt' }, h('span', {}, item.title), h('span', { class: 's' }, item.username || item.host || '')),
    h('span', { class: 'act' + (item.matches ? '' : ' copy') }, item.matches ? (item.hasTotp ? 'Fill · 2FA' : 'Fill') : 'Copy'));
}

function stateCard(title, text, button) {
  main.replaceChildren(h('div', { class: 'state' }, h('b', {}, title), h('p', {}, text), button));
}

async function init() {
  const s = await send({ type: 'popup' });
  document.getElementById('host').textContent = s.host || '';
  if (s.state === 'no_connector') return stateCard('Connect this browser', 'Open the lockbox app once. It sets up the connection for Dia and Chrome automatically, then reopen this popup.');
  if (s.state === 'no_vault') return stateCard('Set up lockbox first', 'Create your lockbox in the app, then come back.', h('button', { class: 'btn p', onClick: () => send({ type: 'open_app' }) }, 'Open lockbox'));
  if (s.state === 'locked') return stateCard('lockbox is locked', 'Unlock it in the app, then click here again.', h('button', { class: 'btn p', onClick: async () => { await send({ type: 'open_app' }); window.close(); } }, 'Open lockbox'));
  if (s.state !== 'unlocked') return stateCard('Something went wrong', String(s.state || 'No response from lockbox.'));

  const results = h('div', { class: 'list' });
  const here = s.items || [];
  const showHere = () => results.replaceChildren(...(here.length ? here.map(row) : [h('p', { class: 'faint pad' }, `No logins saved for ${s.host || 'this page'} yet. Log in normally and lockbox will offer to save it.`)]));
  showHere();
  let t;
  const search = h('input', { class: 'search', placeholder: 'Search all items…', 'aria-label': 'Search all items', spellcheck: 'false',
    onInput: (e) => { clearTimeout(t); const q = e.target.value.trim(); t = setTimeout(async () => {
      if (!q) { secTitle.textContent = 'For this site'; return showHere(); }
      const r = await send({ type: 'search', q });
      secTitle.textContent = 'Search';
      results.replaceChildren(...((r.items || []).length ? r.items.map(row) : [h('p', { class: 'faint pad' }, 'No matches.')]));
    }, 120); } });
  const secTitle = h('div', { class: 'sec' }, 'For this site');
  const gen = h('button', { class: 'btn', onClick: async () => {
    const r = await send({ type: 'generate' });
    if (r.error) return note(r.error);
    note(r.filled ? 'Strong password filled. Submit the form and lockbox will offer to save it.' : 'No password field here. Open the sign-up or change-password form first.');
  } }, 'Generate password');
  main.replaceChildren(search, secTitle, results, h('footer', {}, gen, h('span', { class: 'faint' }, h('span', { class: 'kbd' }, '⌘⇧L'), ' fills without opening this')));
  (results.querySelector('.row') || search).focus();
}

init();
