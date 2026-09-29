const root = document.getElementById('root');
const LEN = { random: [8, 64, 20], memorable: [3, 12, 5], pin: [4, 12, 6] };
const S = {
  screen: 'loading', items: [], vaults: [], filter: 'all', view: 'items', sel: null, revealed: {}, needSk: false, sk: null,
  palette: null, editor: null, gen: { mode: 'random', len: 20, digits: true, symbols: true, easy: false, value: '' },
};
let focusAfter = null;

async function boot() {
  const st = await invoke('status');
  if (!st.exists) S.screen = 'setup';
  else if (st.unlocked) { await load(); S.screen = 'app'; }
  else { S.needSk = !st.hasSecretKey; S.screen = 'unlock'; }
  render();
}

async function load() {
  [S.items, S.vaults] = await Promise.all([invoke('items'), invoke('vaults')]);
  if (!visible().some((i) => i.id === S.sel)) S.sel = visible()[0]?.id ?? null;
}

function visible() {
  const f = S.filter;
  return S.items
    .filter((i) => f === 'all' || (f === 'fav' && i.favorite) || i.vaultId === f || (f.startsWith('tag:') && i.tags.includes(f.slice(4))))
    .sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: 'base' }));
}
const selected = () => S.items.find((i) => i.id === S.sel);
const vaultName = (id) => S.vaults.find((v) => v.id === id)?.name ?? '';

function render() {
  const screens = { loading: () => [], setup, kit, unlock: unlockScreen, app };
  const gate = S.screen !== 'app';
  root.replaceChildren(...(gate ? [h('div', { class: 'dragbar', 'data-tauri-drag-region': true })] : []), ...screens[S.screen]());
  if (S.palette) root.append(palette());
  if (S.editor) root.append(editor());
  if (focusAfter) { document.getElementById(focusAfter)?.focus(); focusAfter = null; }
}

// ---------- gate screens ----------

function gateCard(wide, ...kids) {
  return h('div', { class: 'gate fade' }, h('div', { class: 'card' + (wide ? ' wide' : '') }, h('div', { class: 'logo-tile' }, icon('lock', 30)), ...kids));
}

function setup() {
  const pw = h('input', { class: 'input', type: 'password', id: 'pw1', autocomplete: 'new-password' });
  const pw2 = h('input', { class: 'input', type: 'password', id: 'pw2', autocomplete: 'new-password', onKeydown: (e) => e.key === 'Enter' && go() });
  const err = h('p', { class: 'error', role: 'alert' });
  const btn = h('button', { class: 'btn primary', onClick: () => go() }, 'Create lockbox');
  async function go() {
    if (pw.value.length < 10) return (err.textContent = 'Use at least 10 characters. A long phrase is easiest to remember.');
    if (pw.value !== pw2.value) return (err.textContent = "Those passwords don't match.");
    btn.disabled = true; btn.textContent = 'Creating…';
    try { S.sk = await invoke('create', { password: pw.value }); S.screen = 'kit'; render(); }
    catch (e) { err.textContent = e; btn.disabled = false; btn.textContent = 'Create lockbox'; }
  }
  focusAfter = 'pw1';
  return [gateCard(false,
    h('h1', {}, 'Create your lockbox'),
    h('p', { class: 'sub' }, "Choose a master password. Nobody can reset it, so make it a phrase you'll remember."),
    h('div', { class: 'field' }, h('label', { for: 'pw1' }, 'Master password'), pw),
    h('div', { class: 'field' }, h('label', { for: 'pw2' }, 'Repeat it'), pw2),
    err, btn)];
}

function kit() {
  const btn = h('button', { class: 'btn primary', disabled: true, onClick: async () => { S.sk = null; await load(); S.screen = 'app'; render(); } }, 'Open lockbox');
  const box = h('input', { type: 'checkbox', id: 'saved', onChange: (e) => (btn.disabled = !e.target.checked) });
  return [gateCard(true,
    h('h1', {}, 'Your Secret Key'),
    h('p', { class: 'sub' }, 'You need this and your master password to sign in on a new device. It never leaves your devices, so lockbox can’t recover it.'),
    h('div', { class: 'secret-key' }, S.sk),
    h('button', { class: 'btn', onClick: async () => { await invoke('copy_text', { text: S.sk }); toast('Secret Key copied'); } }, icon('copy'), 'Copy Secret Key'),
    h('label', { class: 'check', for: 'saved' }, box, "I've written it down or saved it somewhere safe and offline."),
    btn)];
}

function unlockScreen() {
  const pw = h('input', { class: 'input mono', type: 'password', id: 'mp', autocomplete: 'current-password', onKeydown: (e) => e.key === 'Enter' && go() });
  const sk = S.needSk && h('input', { class: 'input mono', id: 'sk', placeholder: 'LB1-XXXXXX-XXXXX-…', spellcheck: 'false', onKeydown: (e) => e.key === 'Enter' && go() });
  const err = h('p', { class: 'error', role: 'alert' });
  const btn = h('button', { class: 'btn primary', onClick: () => go() }, 'Unlock');
  let card;
  async function go() {
    btn.disabled = true; btn.textContent = 'Unlocking…'; err.textContent = '';
    try {
      await invoke('unlock', { password: pw.value, secretKey: sk ? sk.value : null });
      await load(); S.screen = 'app'; S.needSk = false; render();
    } catch (e) {
      if (e === 'need_secret_key') { S.needSk = true; render(); return; }
      err.textContent = e; btn.disabled = false; btn.textContent = 'Unlock';
      card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake'); pw.select();
    }
  }
  focusAfter = S.needSk ? 'sk' : 'mp';
  const g = gateCard(false,
    h('div', { class: 'field' }, h('h1', {}, 'Welcome back'), h('p', { class: 'sub' }, 'Unlock lockbox to continue.')),
    sk && h('div', { class: 'field' }, h('label', { for: 'sk' }, 'Secret Key (from your Emergency Kit)'), sk),
    h('div', { class: 'field' }, h('label', { for: 'mp' }, 'Master password'), pw),
    err, btn,
    h('p', { class: 'note' }, icon('shield', 13), S.needSk ? 'The Secret Key is saved to this Mac’s Keychain after you unlock' : 'Secret Key is stored in this Mac’s Keychain'));
  card = g.firstChild;
  return [g];
}

// ---------- app ----------

function app() {
  const top = h('header', { class: 'top', 'data-tauri-drag-region': true },
    h('div', { class: 'brand', 'data-tauri-drag-region': true }, h('span', { class: 'mark' }, icon('lock', 16)), 'lockbox'),
    h('button', { class: 'search', onClick: openPalette }, icon('search'), h('span', {}, 'Search or jump to…'), h('span', { class: 'kbd' }, '⌘K')),
    h('div', { class: 'spacer', 'data-tauri-drag-region': true }),
    h('button', { class: 'btn primary sm', onClick: () => openEditor() }, icon('plus'), 'New item'),
    h('button', { class: 'icon-btn', 'aria-label': 'Lock lockbox', title: 'Lock (⌘L)', onClick: () => invoke('lock') }, icon('lock', 17)));
  const gen = S.view === 'generator';
  return [h('div', { class: 'app fade' }, top, h('div', { class: 'body' + (gen ? ' wide' : '') }, side(), ...(gen ? [generator()] : [list(), detail()])))];
}

function side() {
  const nav = (id, label, ic, count) => h('button', {
    class: 'nav' + ((id === 'generator' ? S.view === 'generator' : S.view === 'items' && S.filter === id) ? ' on' : ''),
    onClick: () => { if (id === 'generator') { S.view = 'generator'; if (!S.gen.value) regen(); } else { S.view = 'items'; S.filter = id; S.sel = null; load().then(render); return; } render(); },
  }, icon(ic, 17), label, count != null && h('span', { class: 'count' }, count));
  const tags = [...new Set(S.items.flatMap((i) => i.tags))].sort();
  return h('nav', { class: 'side', 'aria-label': 'Sidebar' },
    nav('all', 'All items', 'grid', S.items.length),
    nav('fav', 'Favorites', 'star', S.items.filter((i) => i.favorite).length),
    nav('generator', 'Generator', 'spark'),
    h('div', { class: 'section' }, 'Vaults'),
    S.vaults.map((v) => h('button', { class: 'nav' + (S.view === 'items' && S.filter === v.id ? ' on' : ''), onClick: () => { S.view = 'items'; S.filter = v.id; S.sel = null; load().then(render); } },
      h('span', { class: 'dot', hue: hue(v.name) }), v.name, h('span', { class: 'count' }, S.items.filter((i) => i.vaultId === v.id).length))),
    tags.length > 0 && h('div', { class: 'section' }, 'Tags'),
    tags.length > 0 && h('div', { class: 'tags' }, tags.map((t) => h('button', { class: 'tag' + (S.filter === 'tag:' + t ? ' on' : ''), onClick: () => { S.view = 'items'; S.filter = S.filter === 'tag:' + t ? 'all' : 'tag:' + t; S.sel = null; load().then(render); } }, '#' + t))),
    h('div', { class: 'side-foot' }, h('i'), 'Auto-locks after 10 idle minutes'));
}

function list() {
  const rows = visible();
  const titles = { all: 'All items', fav: 'Favorites' };
  const title = titles[S.filter] ?? (S.filter.startsWith('tag:') ? '#' + S.filter.slice(4) : vaultName(S.filter));
  return h('section', { class: 'list', 'aria-label': 'Items' },
    h('div', { class: 'list-head' }, h('h2', {}, title), h('span', { class: 'faint' }, `${rows.length} item${rows.length === 1 ? '' : 's'}`)),
    rows.length
      ? h('div', { class: 'rows' }, rows.map((i) => h('button', { class: 'row' + (i.id === S.sel ? ' on' : ''), onClick: () => select(i.id) },
          tile(i.title, 's'),
          h('span', { class: 'txt' }, h('span', { class: 't' }, i.title), h('span', { class: 's' }, i.username || host(i.urls[0] || '') || (i.kind === 'secure_note' ? 'Secure note' : ''))),
          i.favorite && h('span', { class: 'star' }, icon('star', 14, true)))))
      : h('div', { class: 'empty' }, h('p', {}, 'Nothing here yet.'), h('button', { class: 'btn sm', onClick: () => openEditor() }, icon('plus'), 'Add an item')));
}

function select(id) {
  S.sel = id; S.revealed = {};
  render();
  tick();
}

function fieldRow(k, v, ...btns) {
  return h('div', { class: 'f' }, h('div', { class: 'kv' }, h('span', { class: 'k' }, k), v), ...btns);
}
const copyBtn = (label, fn) => h('button', { class: 'icon-btn', 'aria-label': label, title: label, onClick: fn }, icon('copy', 17));
async function copyField(id, field, msg) {
  try { await invoke('copy', { id, field }); toast(msg); } catch (e) { toast(String(e), null); }
}

function detail() {
  const it = selected();
  if (!it) return h('section', { class: 'detail' }, h('div', { class: 'empty' },
    h('h2', {}, S.items.length ? 'Pick an item' : 'Your lockbox is empty'),
    h('p', {}, S.items.length ? 'Or press ⌘K to search.' : 'Add your first login, or import from another password manager later.'),
    !S.items.length && h('button', { class: 'btn primary', onClick: () => openEditor() }, icon('plus'), 'New item')));

  const rows = [];
  if (it.username) rows.push(fieldRow('username', h('span', { class: 'v' }, it.username), copyBtn('Copy username', () => copyField(it.id, 'username', 'Username copied'))));
  if (it.hasPassword) {
    const shown = S.revealed.password;
    rows.push(fieldRow('password', shown != null ? h('span', { class: 'v pw' }, pwChars(shown)) : h('span', { class: 'v masked' }, '••••••••••••'),
      h('button', { class: 'icon-btn', 'aria-label': shown != null ? 'Hide password' : 'Reveal password', title: shown != null ? 'Hide' : 'Reveal', onClick: () => toggleReveal(it.id, 'password') }, icon('eye', 18)),
      copyBtn('Copy password (⌘C)', () => copyField(it.id, 'password', 'Password copied'))));
  }
  if (it.hasTotp) {
    const svg = document.createElementNS(SVG, 'svg');
    for (const [k, v] of Object.entries({ width: 36, height: 36, viewBox: '0 0 36 36', 'aria-hidden': 'true' })) svg.setAttribute(k, v);
    for (const cls of ['bg', 'fg']) {
      const c = document.createElementNS(SVG, 'circle');
      for (const [k, v] of Object.entries({ class: cls, cx: 18, cy: 18, r: 15, fill: 'none', 'stroke-width': 3, 'stroke-linecap': 'round', 'stroke-dasharray': 94.25, 'stroke-dashoffset': cls === 'fg' ? 94.25 : 0 })) c.setAttribute(k, v);
      svg.append(c);
    }
    const ring = h('div', { class: 'ring', id: 'totp-ring' }, svg, h('span', {}, ''));
    rows.push(fieldRow('one-time code', h('span', { class: 'v code', id: 'totp-code' }, '––– –––'), ring, copyBtn('Copy code', () => copyField(it.id, 'totp', 'Code copied'))));
  }
  for (const u of it.urls) rows.push(fieldRow('website', h('span', { class: 'v' }, u), copyBtn('Copy website', async () => { await invoke('copy_text', { text: u }); toast('Website copied', null); })));
  for (const [name, value] of it.fields) {
    const shown = value ?? S.revealed[name];
    rows.push(fieldRow(name, shown != null ? h('span', { class: 'v' }, shown) : h('span', { class: 'v masked' }, '••••••••'),
      value == null && h('button', { class: 'icon-btn', 'aria-label': 'Reveal ' + name, onClick: () => toggleReveal(it.id, name) }, icon('eye', 18)),
      copyBtn('Copy ' + name, () => copyField(it.id, name, name + ' copied'))));
  }
  if (it.notes) rows.push(fieldRow('notes', h('span', { class: 'v notes' }, it.notes)));

  const del = h('button', { class: 'btn sm', onClick: async () => {
    if (!del.classList.contains('danger')) { del.classList.add('danger'); del.textContent = 'Click again to delete'; setTimeout(() => { del.classList.remove('danger'); del.replaceChildren(icon('trash'), 'Delete'); }, 3000); return; }
    await invoke('delete_item', { id: it.id }); S.sel = null; await load(); render(); toast('Deleted ' + it.title, null);
  } }, icon('trash'), 'Delete');

  return h('section', { class: 'detail' }, h('div', { class: 'detail-in fade' },
    h('div', { class: 'head' }, tile(it.title, 'l'),
      h('div', { class: 'grow' }, h('h1', {}, it.title), h('div', { class: 'chips' },
        h('span', { class: 'chip' }, h('span', { class: 'dot', hue: hue(vaultName(it.vaultId)) }), vaultName(it.vaultId)),
        it.tags.map((t) => h('span', { class: 'chip' }, '#' + t)))),
      h('button', { class: 'icon-btn' + (it.favorite ? ' star' : ''), 'aria-label': it.favorite ? 'Remove from favorites' : 'Add to favorites', 'aria-pressed': String(it.favorite), onClick: () => toggleFav(it.id) }, icon('star', 18, it.favorite)),
      h('button', { class: 'btn sm', onClick: () => openEditor(it.id) }, icon('edit'), 'Edit')),
    rows.length ? h('div', { class: 'fields' }, rows) : h('p', { class: 'muted' }, 'This item has no fields yet.'),
    h('div', { class: 'foot' }, h('span', { class: 'faint' }, 'Edited ' + ago(it.updatedAt) + ' · end-to-end encrypted'), del)));
}

async function toggleReveal(id, field) {
  if (S.revealed[field] != null) delete S.revealed[field];
  else S.revealed[field] = await invoke('reveal', { id, field });
  render();
}

async function toggleFav(id) {
  const item = await invoke('get_item', { id });
  item.favorite = !item.favorite;
  await invoke('save_item', { id, vaultId: null, item });
  await load(); render();
}

async function tick() {
  const it = selected();
  const code = document.getElementById('totp-code');
  if (S.screen !== 'app' || S.view !== 'items' || !it?.hasTotp || !code) return;
  try {
    const c = await invoke('totp_code', { id: it.id });
    code.textContent = c.code.slice(0, c.code.length / 2) + ' ' + c.code.slice(c.code.length / 2);
    const ring = document.getElementById('totp-ring');
    ring.querySelector('.fg').setAttribute('stroke-dashoffset', String(94.25 * (1 - c.remaining / 30)));
    ring.querySelector('span').textContent = c.remaining;
    ring.classList.toggle('low', c.remaining <= 5);
  } catch { /* locked mid-tick */ }
}
setInterval(tick, 1000);

// ---------- generator ----------

function bits() {
  const g = S.gen;
  if (g.mode === 'pin') return g.len * Math.log2(10);
  if (g.mode === 'memorable') return g.len * Math.log2(7776);
  const pool = 52 + (g.digits ? 10 : 0) + (g.symbols ? 25 : 0) - (g.easy ? 3 + (g.digits ? 2 : 0) : 0);
  return g.len * Math.log2(pool);
}

async function regen() {
  const g = S.gen;
  g.value = await invoke('generate', { o: { mode: g.mode, length: g.len, digits: g.digits, symbols: g.symbols, easy: g.easy } });
  paintGen();
}

function paintGen() {
  const b = Math.round(bits());
  const out = document.getElementById('gen-pw');
  if (!out) return;
  out.replaceChildren(pwChars(S.gen.value));
  document.getElementById('gen-meter').style.width = Math.min(100, b / 1.28) + '%';
  document.getElementById('gen-bits').textContent = `~${b} bits of entropy · ${b >= 100 ? 'far beyond brute force' : b >= 64 ? 'strong' : b >= 40 ? 'fine for low-value accounts' : 'too weak for most sites'}`;
  document.getElementById('len-n').textContent = S.gen.len;
}

function generator() {
  const g = S.gen;
  const [min, max] = LEN[g.mode];
  const modes = [['random', 'Random'], ['memorable', 'Memorable'], ['pin', 'PIN']];
  const check = (key, label) => h('label', {}, h('input', { type: 'checkbox', checked: g[key], onChange: (e) => { g[key] = e.target.checked; regen(); } }), label);
  setTimeout(paintGen);
  return h('section', { class: 'gen' }, h('div', { class: 'gen-in fade' },
    h('div', {}, h('h1', {}, 'Generator'), h('p', { class: 'muted' }, "Uses the system's secure random source. Nothing is saved until you add it to an item.")),
    h('div', { class: 'seg', role: 'group', 'aria-label': 'Password type' }, modes.map(([m, l]) => h('button', {
      class: g.mode === m ? 'on' : '', 'aria-pressed': String(g.mode === m), onClick: () => { g.mode = m; g.len = LEN[m][2]; render(); regen(); },
    }, l))),
    h('div', { class: 'out' },
      h('div', { class: 'pw', id: 'gen-pw', 'aria-live': 'polite' }),
      h('div', { class: 'meter' }, h('i', { id: 'gen-meter' })),
      h('span', { class: 'faint', id: 'gen-bits' }),
      h('div', { class: 'with-btns' },
        h('button', { class: 'btn', onClick: regen }, icon('refresh'), 'Regenerate'),
        h('button', { class: 'btn primary', onClick: async () => { await invoke('copy_text', { text: g.value }); toast('Generated password copied'); } }, icon('copy'), 'Copy'))),
    h('div', { class: 'opts' },
      h('div', { class: 'opt-row' }, h('label', { for: 'len' }, g.mode === 'memorable' ? 'Words' : g.mode === 'pin' ? 'Digits' : 'Length'),
        h('input', { type: 'range', id: 'len', min, max, value: g.len, onInput: (e) => { g.len = Number(e.target.value); regen(); } }),
        h('span', { class: 'n', id: 'len-n' }, g.len)),
      g.mode === 'random' && h('div', { class: 'checks' }, check('digits', 'Numbers'), check('symbols', 'Symbols'), check('easy', 'Easy to type')))));
}

// ---------- ⌘K palette ----------

function openPalette() {
  if (S.screen !== 'app') return;
  S.palette = { q: '', idx: 0 };
  focusAfter = 'pal-q';
  render();
}
function closePalette() { S.palette = null; render(); }

function paletteResults() {
  const q = S.palette.q.trim();
  const items = S.items.filter((i) => matches(i, q)).slice(0, 6).map((i) => ({ kind: 'item', i, run: () => { S.view = 'items'; S.filter = 'all'; S.palette = null; select(i.id); } }));
  const actions = [
    ['New item', '⌘N', 'plus', () => { S.palette = null; openEditor(); }],
    ['Generate a password', 'Generator', 'spark', () => { S.palette = null; S.view = 'generator'; render(); regen(); }],
    ['All items', 'View', 'grid', () => { S.palette = null; S.view = 'items'; S.filter = 'all'; render(); }],
    ['Lock lockbox', '⌘L', 'lock', () => { S.palette = null; invoke('lock'); }],
  ].filter(([l]) => !q || l.toLowerCase().includes(q.toLowerCase())).map(([label, hint, ic, run]) => ({ kind: 'action', label, hint, ic, run }));
  return [...items, ...actions];
}

function palette() {
  const results = paletteResults();
  S.palette.idx = Math.min(S.palette.idx, Math.max(0, results.length - 1));
  const listEl = h('div', { class: 'pal-list', role: 'listbox' });
  const paint = () => {
    const rs = paletteResults();
    S.palette.idx = Math.min(S.palette.idx, Math.max(0, rs.length - 1));
    const row = (r, n) => h('button', { class: 'pal-row' + (n === S.palette.idx ? ' on' : ''), role: 'option', 'aria-selected': String(n === S.palette.idx), onClick: r.run },
      ...(r.kind === 'item'
        ? [tile(r.i.title, 'm'), h('span', { class: 'grow' }, r.i.title, h('span', { class: 'faint' }, r.i.username ? ' · ' + r.i.username : '')), h('span', { class: 'faint' }, vaultName(r.i.vaultId))]
        : [h('span', { class: 'ic' }, icon(r.ic)), h('span', { class: 'grow' }, r.label), h('span', { class: 'faint' }, r.hint)]));
    const its = rs.filter((r) => r.kind === 'item');
    listEl.replaceChildren(...[
      its.length > 0 && h('div', { class: 'pal-sec' }, 'Items'), ...its.map((r) => row(r, rs.indexOf(r))),
      rs.some((r) => r.kind === 'action') && h('div', { class: 'pal-sec' }, 'Actions'), ...rs.filter((r) => r.kind === 'action').map((r) => row(r, rs.indexOf(r))),
      !rs.length && h('div', { class: 'empty' }, 'No matches.')].filter(Boolean));
    listEl.querySelector('.on')?.scrollIntoView({ block: 'nearest' });
  };
  const input = h('input', { id: 'pal-q', placeholder: 'Search items, or type a command…', 'aria-label': 'Search items and actions', value: S.palette.q,
    onInput: (e) => { S.palette.q = e.target.value; S.palette.idx = 0; paint(); },
    onKeydown: (e) => {
      const n = paletteResults().length;
      if (e.key === 'ArrowDown') { S.palette.idx = (S.palette.idx + 1) % n; paint(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { S.palette.idx = (S.palette.idx - 1 + n) % n; paint(); e.preventDefault(); }
      else if (e.key === 'Enter') paletteResults()[S.palette.idx]?.run();
    } });
  paint();
  const scrim = h('div', { class: 'scrim', onMousedown: (e) => e.target === scrim && closePalette() },
    h('div', { class: 'sheet fade', role: 'dialog', 'aria-label': 'Search' },
      h('div', { class: 'pal-in' }, icon('search', 18), input, h('button', { class: 'kbd', onClick: closePalette }, 'esc')), listEl));
  return scrim;
}

// ---------- item editor ----------

async function openEditor(id) {
  const item = id ? await invoke('get_item', { id }) : { kind: 'login', title: '', username: null, password: null, urls: [], notes: null, totp: null, tags: [], fields: [], favorite: false };
  S.editor = { id: id ?? null, item, vaultId: S.vaults.find((v) => v.id === S.filter)?.id ?? S.vaults[0]?.id };
  focusAfter = 'ed-title';
  render();
}
function closeEditor() { S.editor = null; render(); }

function editor() {
  const { id, item } = S.editor;
  const inp = (fid, label, value, extra = {}) => {
    const el = h('input', { class: 'input' + (extra.mono ? ' mono' : ''), id: fid, value: value ?? '', spellcheck: 'false', autocomplete: 'off', type: extra.type || 'text', placeholder: extra.placeholder, onKeydown: (e) => e.key === 'Enter' && save() });
    return [el, h('div', { class: 'field' }, h('label', { for: fid }, label), extra.wrap ? extra.wrap(el) : el)];
  };
  const [title, titleF] = inp('ed-title', 'Title', item.title, { placeholder: 'e.g. GitHub' });
  const [user, userF] = inp('ed-user', 'Username or email', item.username);
  const [pw, pwF] = inp('ed-pw', 'Password', item.password, { mono: true, type: 'password', wrap: (el) => h('div', { class: 'with-btns' }, el,
    h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Show password', onClick: () => (el.type = el.type === 'password' ? 'text' : 'password') }, icon('eye', 18)),
    h('button', { class: 'btn sm', type: 'button', onClick: async () => { el.value = await invoke('generate', { o: { mode: 'random', length: 24, digits: true, symbols: true, easy: false } }); el.type = 'text'; } }, icon('spark'), 'Generate')) });
  const [url, urlF] = inp('ed-url', 'Website', item.urls[0], { placeholder: 'https://' });
  const [otp, otpF] = inp('ed-totp', '2FA secret (optional)', item.totp, { mono: true, placeholder: 'Setup key or otpauth:// link' });
  const [tags, tagsF] = inp('ed-tags', 'Tags', item.tags.join(', '), { placeholder: 'work, finance' });
  const notes = h('textarea', { class: 'input', id: 'ed-notes', value: item.notes ?? '' });
  const vault = !id && S.vaults.length > 1 && h('select', { class: 'input', id: 'ed-vault', onChange: (e) => (S.editor.vaultId = e.target.value) },
    S.vaults.map((v) => { const o = h('option', { value: v.id }, v.name); o.selected = v.id === S.editor.vaultId; return o; }));
  const err = h('p', { class: 'error', role: 'alert' });
  const opt = (s) => (s.trim() ? s.trim() : null);

  async function save() {
    const next = {
      ...item, title: title.value.trim(), username: opt(user.value), password: pw.value || null,
      urls: url.value.trim() ? [url.value.trim(), ...item.urls.slice(1)] : item.urls.slice(1),
      totp: opt(otp.value), notes: opt(notes.value), tags: tags.value.split(',').map((t) => t.trim()).filter(Boolean),
    };
    try {
      const saved = await invoke('save_item', { id, vaultId: S.editor.vaultId ?? null, item: next });
      S.editor = null; S.view = 'items'; await load(); S.sel = saved; S.revealed = {};
      if (!visible().some((i) => i.id === saved)) S.filter = 'all';
      render(); tick(); toast(id ? 'Saved' : 'Added ' + next.title, null);
    } catch (e) { err.textContent = e; }
  }

  const scrim = h('div', { class: 'scrim', onMousedown: (e) => e.target === scrim && closeEditor() },
    h('div', { class: 'sheet fade', role: 'dialog', 'aria-label': id ? 'Edit item' : 'New item' }, h('div', { class: 'editor' },
      h('h2', {}, id ? 'Edit ' + item.title : 'New login'),
      vault ? h('div', { class: 'pair' }, titleF, h('div', { class: 'field' }, h('label', { for: 'ed-vault' }, 'Vault'), vault)) : titleF,
      userF, pwF, h('div', { class: 'pair' }, urlF, tagsF), otpF,
      h('div', { class: 'field' }, h('label', { for: 'ed-notes' }, 'Notes'), notes),
      err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeEditor }, 'Cancel'), h('button', { class: 'btn primary', onClick: save }, id ? 'Save' : 'Add item')))));
  return scrim;
}

// ---------- keyboard + lifecycle ----------

let lastPing = 0;
document.addEventListener('keydown', (e) => {
  if (Date.now() - lastPing > 15000 && S.screen === 'app') { lastPing = Date.now(); invoke('activity'); }
  if (S.screen !== 'app') return;
  const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
  if (e.key === 'Escape') { if (S.editor) closeEditor(); else if (S.palette) closePalette(); return; }
  if (e.metaKey && e.key === 'k') { e.preventDefault(); S.palette ? closePalette() : openPalette(); return; }
  if (e.metaKey && e.key === 'n') { e.preventDefault(); openEditor(); return; }
  if (e.metaKey && e.key === 'l') { e.preventDefault(); invoke('lock'); return; }
  if (S.palette || S.editor || inField || S.view !== 'items') return;
  if (e.metaKey && e.key === 'c' && !window.getSelection().toString() && selected()?.hasPassword) { e.preventDefault(); copyField(S.sel, 'password', 'Password copied'); return; }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    const v = visible(); const n = v.findIndex((i) => i.id === S.sel);
    const next = v[Math.max(0, Math.min(v.length - 1, n + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (next) { e.preventDefault(); select(next.id); }
  }
});
document.addEventListener('mousedown', () => { if (Date.now() - lastPing > 15000 && S.screen === 'app') { lastPing = Date.now(); invoke('activity'); } });

listen('locked', () => {
  Object.assign(S, { screen: 'unlock', items: [], vaults: [], revealed: {}, palette: null, editor: null, needSk: false });
  S.gen.value = '';
  render();
});

boot();
