const root = document.getElementById('root');
const LEN = { random: [8, 64, 20], memorable: [3, 12, 5], pin: [4, 12, 6] };
const S = {
  screen: 'loading', items: [], vaults: [], trash: [], filter: 'all', view: 'items', sel: null, revealed: {}, needSk: false, sk: null,
  palette: null, editor: null, importer: null, settings: null, sheet: null, nudged: false, restore: null, gen: { mode: 'random', len: 20, digits: true, symbols: true, easy: false, value: '' },
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
  [S.items, S.vaults, S.settings, S.trash] = await Promise.all([invoke('items'), invoke('vaults'), invoke('settings_get'), invoke('trash_list')]);
  if (!S.nudged) {
    // one gentle prompt per unlock: backups first, then the monthly Emergency Kit check
    S.nudged = true;
    if (!S.settings.backupAsked) S.sheet = { kind: 'backup' };
    else if (S.settings.recoveryDue) S.sheet = { kind: 'recovery' };
  }
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
  const screens = { loading: () => [], setup, kit, unlock: unlockScreen, restore: restoreScreen, app };
  const gate = S.screen !== 'app';
  root.replaceChildren(...(gate ? [h('div', { class: 'dragbar', 'data-tauri-drag-region': true })] : []), ...screens[S.screen]());
  if (S.palette) root.append(palette());
  if (S.editor) root.append(editor());
  if (S.importer) root.append(importer());
  if (S.sheet) root.append(sheet());
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
    err, btn,
    h('button', { class: 'link', onClick: () => { S.restore = {}; S.screen = 'restore'; render(); } }, 'Restore from a backup instead'))];
}

function restoreScreen() {
  const R = S.restore;
  const sk = h('input', { class: 'input mono', id: 'rs-sk', placeholder: 'LB1-XXXXXX-XXXXX-…', spellcheck: 'false', value: R.sk ?? '' });
  const pw = h('input', { class: 'input mono', type: 'password', id: 'rs-pw', onKeydown: (e) => e.key === 'Enter' && go() });
  const err = h('p', { class: 'error', role: 'alert' }, R.error || '');
  const btn = h('button', { class: 'btn primary', disabled: !R.path, onClick: () => go() }, 'Restore and unlock');
  async function go() {
    btn.disabled = true; btn.textContent = 'Restoring…'; err.textContent = '';
    try { await invoke('restore', { path: R.path, password: pw.value, secretKey: sk.value || null }); S.restore = null; await load(); S.screen = 'app'; render(); }
    catch (e) { err.textContent = e === 'need_secret_key' ? 'Enter the Secret Key from your Emergency Kit.' : String(e); btn.disabled = false; btn.textContent = 'Restore and unlock'; }
  }
  const choose = async () => { R.sk = sk.value; const p = await invoke('restore_pick'); if (p) R.path = p; render(); };
  return [gateCard(false,
    h('h1', {}, 'Restore a backup'),
    h('p', { class: 'sub' }, 'Use a .lockbox backup from iCloud Drive or wherever you kept it. You need the Secret Key and master password it was made with.'),
    h('button', { class: 'btn', onClick: choose }, icon('download'), R.path ? R.path.split('/').pop() : 'Choose backup file…'),
    h('div', { class: 'field' }, h('label', { for: 'rs-sk' }, 'Secret Key'), sk),
    h('div', { class: 'field' }, h('label', { for: 'rs-pw' }, 'Master password'), pw),
    err, btn,
    h('button', { class: 'link', onClick: () => { S.restore = null; S.screen = 'setup'; render(); } }, 'Create a new lockbox instead'))];
}

function kit() {
  const btn = h('button', { class: 'btn primary', disabled: true, onClick: async () => { S.sk = null; S.screen = 'app'; await load(); render(); } }, 'Open lockbox');
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
  const wide = ['generator', 'settings', 'trash'].includes(S.view);
  const main = S.view === 'generator' ? [generator()] : S.view === 'settings' ? [settingsView()] : S.view === 'trash' ? [trashView()] : [list(), detail()];
  return [h('div', { class: 'app fade' }, top, h('div', { class: 'body' + (wide ? ' wide' : '') }, side(), ...main))];
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
    h('button', { class: 'nav' + (S.view === 'trash' ? ' on' : ''), onClick: async () => { S.view = 'trash'; await load(); render(); } },
      icon('trash', 17), 'Recently deleted', S.trash.length > 0 && h('span', { class: 'count' }, S.trash.length)),
    h('button', { class: 'nav', onClick: openImporter }, icon('download', 17), 'Import'),
    h('button', { class: 'nav' + (S.view === 'settings' ? ' on' : ''), onClick: async () => { S.view = 'settings'; S.settings = await invoke('settings_get'); render(); } }, icon('gear', 17), 'Settings'),
    h('div', { class: 'section-row' }, h('div', { class: 'section' }, 'Vaults'),
      h('button', { class: 'add', 'aria-label': 'New vault', title: 'New vault', onClick: () => { S.sheet = { kind: 'vault-new' }; render(); } }, icon('plus', 14))),
    S.vaults.map((v) => h('div', { class: 'vrow' },
      h('button', { class: 'nav' + (S.view === 'items' && S.filter === v.id ? ' on' : ''), onClick: () => { S.view = 'items'; S.filter = v.id; S.sel = null; load().then(render); } },
        h('span', { class: 'dot', hue: hue(v.name) }), v.name, h('span', { class: 'count' }, S.items.filter((i) => i.vaultId === v.id).length)),
      h('button', { class: 'vmore', 'aria-label': 'Edit vault ' + v.name, title: 'Rename or delete', onClick: () => { S.sheet = { kind: 'vault-edit', vault: v }; render(); } }, icon('more', 16)))),
    tags.length > 0 && h('div', { class: 'section' }, 'Tags'),
    tags.length > 0 && h('div', { class: 'tags' }, tags.map((t) => h('button', { class: 'tag' + (S.filter === 'tag:' + t ? ' on' : ''), onClick: () => { S.view = 'items'; S.filter = S.filter === 'tag:' + t ? 'all' : 'tag:' + t; S.sel = null; load().then(render); } }, '#' + t))),
    backupFoot());
}

function backupFoot() {
  const st = S.settings;
  const bad = !st || !st.autoBackup || st.lastBackupError;
  const text = !st ? '' : st.lastBackupError ? 'Last backup failed' : !st.autoBackup ? 'Backups are off' : st.lastBackup ? 'Backed up ' + ago(st.lastBackup) : 'First backup running…';
  return h('button', { class: 'side-foot' + (bad ? ' warn' : ''), onClick: async () => { S.view = 'settings'; S.settings = await invoke('settings_get'); render(); } }, h('i'), text);
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
    !S.items.length && h('div', { class: 'with-btns' },
      h('button', { class: 'btn primary', onClick: openImporter }, icon('download'), 'Import from 1Password or a browser'),
      h('button', { class: 'btn', onClick: () => openEditor() }, icon('plus'), 'New item'))));

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
  if (it.passkey) rows.push(fieldRow('passkey', h('span', { class: 'v' }, `${it.passkey.userName || 'account'} · ${it.passkey.rpId}`),
    h('span', { class: 'faint' }, 'added ' + ago(it.passkey.createdAt))));
  if (it.historyCount) rows.push(h('div', { class: 'f link-row', role: 'button', tabindex: '0', onClick: () => openHistory(it.id), onKeydown: (e) => e.key === 'Enter' && openHistory(it.id) },
    h('div', { class: 'kv' }, h('span', { class: 'k' }, 'previous passwords'), h('span', { class: 'v muted' }, `${it.historyCount} older password${it.historyCount === 1 ? '' : 's'}`)),
    h('span', { class: 'faint' }, 'View ›')));
  for (const u of it.urls) rows.push(fieldRow('website', h('span', { class: 'v' }, u), copyBtn('Copy website', async () => { await invoke('copy_text', { text: u }); toast('Website copied', null); })));
  for (const [name, value] of it.fields) {
    const shown = value ?? S.revealed[name];
    rows.push(fieldRow(name, shown != null ? h('span', { class: 'v' }, shown) : h('span', { class: 'v masked' }, '••••••••'),
      value == null && h('button', { class: 'icon-btn', 'aria-label': 'Reveal ' + name, onClick: () => toggleReveal(it.id, name) }, icon('eye', 18)),
      copyBtn('Copy ' + name, () => copyField(it.id, name, name + ' copied'))));
  }
  if (it.notes) rows.push(fieldRow('notes', h('span', { class: 'v notes' }, it.notes)));

  const del = h('button', { class: 'btn sm', onClick: async () => {
    await invoke('delete_item', { id: it.id }); S.sel = null; await load(); render(); toast(`Moved ${it.title} to Recently deleted`, 'restorable for 30 days');
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
    ['Import passwords', '1Password, Chrome, Safari', 'download', () => { S.palette = null; openImporter(); }],
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
  const own = id && S.items.find((i) => i.id === id)?.vaultId;
  S.editor = { id: id ?? null, item, vaultId: own || S.vaults.find((v) => v.id === S.filter)?.id || S.vaults[0]?.id };
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
  const vault = S.vaults.length > 1 && h('select', { class: 'input', id: 'ed-vault', onChange: (e) => (S.editor.vaultId = e.target.value) },
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

// ---------- import ----------

function openImporter() { S.importer = { step: 'intro', error: '' }; render(); }
async function closeImporter() { const done = S.importer?.step === 'done'; S.importer = null; if (done) await load(); render(); }

function importer() {
  const I = S.importer;
  const body = [];
  if (I.step === 'intro') {
    const pick = async () => {
      I.error = '';
      try {
        const p = await invoke('import_pick');
        if (!p) return;
        // 1Password business accounts: default to just your Employee vault, never the company's shared ones
        const employee = p.vaults.filter(([n]) => n.toLowerCase() === 'employee');
        Object.assign(I, { step: 'preview', preview: p, selected: new Set((employee.length ? employee : p.vaults).map(([n]) => n)), target: '' });
      } catch (e) { I.error = String(e); }
      render();
    };
    body.push(
      h('h2', {}, 'Import passwords'),
      h('p', { class: 'muted' }, 'Export from the app you use now, then choose the file here. Everything stays on this Mac.'),
      h('div', { class: 'srcs' },
        h('div', { class: 'src' }, h('b', {}, '1Password'), 'File › Export, choose your account, pick the 1PUX format. You choose which vaults come across.'),
        h('div', { class: 'src' }, h('b', {}, 'Chrome, Arc, Brave, Edge'), 'Open chrome://password-manager/settings and choose Export passwords.'),
        h('div', { class: 'src' }, h('b', {}, 'Safari'), 'Open the Passwords app, then File › Export All Passwords….'),
        h('p', { class: 'faint' }, 'Firefox and Bitwarden CSV exports work too.')),
      h('p', { class: 'error', role: 'alert' }, I.error || ''),
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeImporter }, 'Cancel'), h('button', { class: 'btn primary', onClick: pick }, icon('download'), 'Choose export file…')));
  } else if (I.step === 'preview') {
    const p = I.preview;
    const count = p.vaults.length ? p.vaults.filter(([n]) => I.selected.has(n)).reduce((a, [, c]) => a + c, 0) : p.count;
    const run = async () => {
      try { I.result = await invoke('import_run', { onlyVaults: [...I.selected], vaultId: I.target || null }); I.step = 'done'; }
      catch (e) { I.error = String(e); }
      render();
    };
    const targets = h('select', { class: 'input', id: 'imp-target', onChange: (e) => (I.target = e.target.value) },
      h('option', { value: '' }, p.vaults.length ? 'Vaults with the same names (created if needed)' : `${S.vaults[0]?.name ?? 'Personal'} (default)`),
      S.vaults.map((v) => h('option', { value: v.id }, v.name)));
    targets.value = I.target;
    body.push(
      h('h2', {}, 'Import from ' + p.fileName),
      p.vaults.length
        ? h('div', { class: 'field' }, h('span', { class: 'label' }, 'Which 1Password vaults?'), h('div', { class: 'pick' }, p.vaults.map(([name, c]) => {
            const on = I.selected.has(name);
            return h('label', { class: on ? 'on' : '' }, h('input', { type: 'checkbox', checked: on, onChange: () => { on ? I.selected.delete(name) : I.selected.add(name); render(); } }), name, h('span', { class: 'faint' }, `${c} item${c === 1 ? '' : 's'}`));
          })))
        : h('p', { class: 'muted' }, `${p.count} items found.`),
      h('div', { class: 'field' }, h('label', { for: 'imp-target' }, 'Put them in'), targets),
      p.skipped.length > 0 && h('p', { class: 'faint' }, 'Won’t import: ' + p.skipped.slice(0, 3).join('; ') + (p.skipped.length > 3 ? `; and ${p.skipped.length - 3} more` : '')),
      h('p', { class: 'error', role: 'alert' }, I.error || ''),
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeImporter }, 'Cancel'),
        h('button', { class: 'btn primary', disabled: count === 0, onClick: run }, `Import ${count} item${count === 1 ? '' : 's'}`)));
  } else {
    const { summary: r, skipped } = I.result;
    const del = h('button', { class: 'btn sm danger', disabled: I.deleted, onClick: async () => {
      try { await invoke('delete_import_file'); I.deleted = true; } catch (e) { I.error = String(e); }
      render();
    } }, icon('trash'), I.deleted ? 'Deleted' : 'Delete ' + I.preview.fileName);
    body.push(
      h('h2', {}, `Imported ${r.added} item${r.added === 1 ? '' : 's'}`),
      h('div', { class: 'stats' },
        r.vaultsCreated.length > 0 && h('span', {}, 'New vaults: ' + r.vaultsCreated.join(', ')),
        r.duplicates > 0 && h('span', {}, `${r.duplicates} already in lockbox, skipped`),
        skipped.map((x) => h('span', { class: 'faint' }, 'Skipped ' + x))),
      I.deleted
        ? h('p', { class: 'note' }, icon('check', 13), 'Export file deleted.')
        : h('div', { class: 'callout' }, icon('shield', 20), h('p', {}, 'The export file still holds every password in plain text. Delete it now.'), del),
      h('p', { class: 'error', role: 'alert' }, I.error || ''),
      h('div', { class: 'actions' }, h('button', { class: 'btn primary', onClick: closeImporter }, 'Done')));
  }
  const scrim = h('div', { class: 'scrim', onMousedown: (e) => e.target === scrim && I.step !== 'done' && closeImporter() },
    h('div', { class: 'sheet fade', role: 'dialog', 'aria-label': 'Import passwords' }, h('div', { class: 'editor' }, ...body)));
  return scrim;
}

// ---------- settings ----------

async function refreshSettings() { S.settings = await invoke('settings_get'); render(); }

function settingsView() {
  const st = S.settings;
  const backupNow = async () => { try { const f = await invoke('backup_run'); toast('Backed up: ' + f, null); } catch (e) { toast(String(e), null); } refreshSettings(); };
  return h('section', { class: 'gen' }, h('div', { class: 'gen-in fade' },
    h('div', {}, h('h1', {}, 'Settings'), h('p', { class: 'muted' }, 'Backups, your Secret Key, and getting your data out.')),

    h('div', { class: 'sec' }, h('h2', {}, 'Backups'),
      h('label', { class: 'toggle' }, h('input', { type: 'checkbox', checked: st.autoBackup, onChange: async (e) => { await invoke('backup_set', { auto: e.target.checked }); refreshSettings(); } }), 'Back up every day'),
      h('div', { class: 'sec-row' }, icon(st.icloud ? 'cloud' : 'download', 16), h('span', { class: 'grow path' }, st.backupDirShown),
        h('button', { class: 'btn sm', onClick: async () => { if (await invoke('backup_choose_dir')) refreshSettings(); } }, 'Change…'),
        h('button', { class: 'btn sm', onClick: backupNow }, 'Back up now')),
      h('p', { class: st.lastBackupError ? 'warn-text' : 'faint' }, st.lastBackupError ? 'Last backup failed: ' + st.lastBackupError : (st.lastBackup ? 'Last backup ' + ago(st.lastBackup) : 'No backups yet') + ' · keeps the newest 14'),
      h('p', { class: 'faint' }, 'Backups are the same encrypted file as your vault. Without your Secret Key and master password they’re useless to anyone, so iCloud Drive is a safe place for them.')),

    h('div', { class: 'sec' }, h('h2', {}, 'Secret Key & Emergency Kit'),
      h('p', { class: 'muted' }, 'You need the Secret Key and your master password to restore a backup or set up a new device. Nobody can recover them for you.'),
      h('div', { class: 'sec-row' },
        h('button', { class: 'btn sm', onClick: () => { S.sheet = { kind: 'recovery' }; render(); } }, icon('shield'), 'Check my Emergency Kit'),
        h('button', { class: 'btn sm', onClick: () => { S.sheet = { kind: 'reveal' }; render(); } }, icon('key'), 'Show Secret Key')),
      h('p', { class: 'faint' }, st.lastRecoveryCheck ? 'Last checked ' + ago(st.lastRecoveryCheck) + ' · lockbox asks again every 30 days' : 'Not checked yet')),

    h('div', { class: 'sec' }, h('h2', {}, 'Master password'),
      h('div', { class: 'sec-row' },
        h('span', { class: 'grow muted' }, 'Change it any time. Your Secret Key stays the same, and lockbox uses today’s recommended encryption strength for the new one.'),
        h('button', { class: 'btn sm', onClick: () => { S.sheet = { kind: 'passwd' }; render(); } }, icon('key'), 'Change…'))),

    h('div', { class: 'sec' }, h('h2', {}, 'Export & restore'),
      h('div', { class: 'sec-row' },
        h('span', { class: 'grow muted' }, 'A CSV that Apple Passwords, Chrome, Bitwarden, 1Password or lockbox can import. It’s plain text: delete it once you’re done.'),
        h('button', { class: 'btn sm', onClick: () => { S.sheet = { kind: 'export' }; render(); } }, 'Export CSV…')),
      h('div', { class: 'sec-row' },
        h('span', { class: 'grow muted' }, 'Replace this vault with a backup. Your current vault is kept aside, not deleted.'),
        h('button', { class: 'btn sm', onClick: () => { S.sheet = { kind: 'restore' }; render(); } }, 'Restore…'))),

    h('div', { class: 'sec' }, h('h2', {}, 'How your data is protected'),
      h('div', { class: 'faq' },
        h('div', {}, h('b', {}, 'Where is it?'), 'In one encrypted file on this Mac, plus the backups above. Nothing is sent anywhere else.'),
        h('div', {}, h('b', {}, 'If this Mac is stolen'), 'The file can’t be opened without your master password and Secret Key. lockbox locks when the screen locks.'),
        h('div', {}, h('b', {}, 'If a backup leaks'), 'Useless without the Secret Key, even with a weak master password. That’s what cracked LastPass vaults lacked.'),
        h('div', {}, h('b', {}, 'If you forget the master password'), 'Your data is gone for good. That’s the price of nobody else being able to get in. Keep your Emergency Kit safe.')))));
}

// ---------- recently deleted ----------

function trashView() {
  const DAY = 86400;
  const left = (t) => Math.max(0, 30 - Math.floor((Date.now() / 1000 - t) / DAY));
  const empty = h('button', { class: 'btn sm', onClick: async () => {
    if (!empty.classList.contains('danger')) { empty.classList.add('danger'); empty.textContent = 'Click again to wipe everything here'; setTimeout(() => { empty.classList.remove('danger'); empty.textContent = 'Empty'; }, 3000); return; }
    const n = await invoke('empty_trash'); await load(); render(); toast(`Wiped ${n} item${n === 1 ? '' : 's'} for good`, null);
  } }, 'Empty');
  return h('section', { class: 'gen' }, h('div', { class: 'gen-in fade' },
    h('div', { class: 'head-row' }, h('div', {}, h('h1', {}, 'Recently deleted'), h('p', { class: 'muted' }, 'Deleted items wait here for 30 days, then their data is wiped for good.')), S.trash.length > 0 && empty),
    S.trash.length
      ? h('div', { class: 'trows' }, S.trash.map((t) => {
          const wipe = h('button', { class: 'btn sm', onClick: async () => {
            if (!wipe.classList.contains('danger')) { wipe.classList.add('danger'); wipe.textContent = 'Click again'; setTimeout(() => { wipe.classList.remove('danger'); wipe.textContent = 'Delete now'; }, 3000); return; }
            await invoke('purge_item', { id: t.id }); await load(); render(); toast(`${t.title} wiped for good`, null);
          } }, 'Delete now');
          return h('div', { class: 'trow' }, tile(t.title, 's'),
            h('div', { class: 'grow' }, h('span', {}, t.title), h('span', { class: 'faint' }, `${t.username ? t.username + ' · ' : ''}deleted ${ago(t.deletedAt)} · wiped in ${left(t.deletedAt)} day${left(t.deletedAt) === 1 ? '' : 's'}`)),
            h('button', { class: 'btn sm', onClick: async () => { await invoke('restore_item', { id: t.id }); await load(); render(); toast(`Restored ${t.title}`, null); } }, icon('undo'), 'Restore'),
            wipe);
        }))
      : h('div', { class: 'empty' }, h('p', {}, 'Nothing here. Deleted items show up here for 30 days.'))));
}

async function openHistory(id) {
  S.sheet = { kind: 'history', id, dates: await invoke('history_list', { id }), shown: {} };
  render();
}

function closeSheet() { S.sheet = null; render(); }

function sheet() {
  const K = S.sheet;
  const err = h('p', { class: 'error', role: 'alert' }, K.error || '');
  const fail = (e) => { K.error = String(e); render(); };
  const pwField = (id, onEnter) => h('input', { class: 'input mono', type: 'password', id, autocomplete: 'current-password', onKeydown: (e) => e.key === 'Enter' && onEnter() });
  let body;
  if (K.kind === 'backup') {
    const on = async () => { try { await invoke('backup_set', { auto: true }); closeSheet(); await refreshSettings(); toast('Backups on', null); } catch (e) { fail(e); } };
    body = [h('h2', {}, 'Keep a backup?'),
      h('p', { class: 'muted' }, `Right now your passwords live in one file on this Mac. lockbox can save an encrypted copy to ${S.settings.backupDirShown} every day and keep the last 14.`),
      h('p', { class: 'faint' }, 'Backups can only be opened with your master password and Secret Key.'),
      err,
      h('div', { class: 'actions' },
        h('button', { class: 'btn', onClick: async () => { await invoke('backup_set', { auto: false }); closeSheet(); refreshSettings(); } }, 'Not now'),
        h('button', { class: 'btn', onClick: async () => { if (await invoke('backup_choose_dir')) { S.settings = await invoke('settings_get'); render(); } } }, 'Choose folder…'),
        h('button', { class: 'btn primary', onClick: on }, icon('cloud'), 'Turn on daily backups'))];
  } else if (K.kind === 'recovery') {
    const input = h('input', { class: 'input mono', id: 'rc-sk', placeholder: 'LB1-XXXXXX-XXXXX-…', spellcheck: 'false', onKeydown: (e) => e.key === 'Enter' && check() });
    async function check() {
      try {
        if (await invoke('recovery_verify', { secretKey: input.value })) { closeSheet(); refreshSettings(); toast('Emergency Kit checked', 'next check in 30 days'); }
        else fail('That Secret Key doesn’t match. If you can’t find the right one, use “I can’t find it”.');
      } catch (e) { fail(e); }
    }
    focusAfter = 'rc-sk';
    body = [h('h2', {}, 'Monthly Emergency Kit check'),
      h('p', { class: 'muted' }, 'Type the Secret Key from wherever you saved it: paper, a safe, another device. This makes sure you could get back in if this Mac died today.'),
      h('div', { class: 'field' }, h('label', { for: 'rc-sk' }, 'Secret Key'), input),
      err,
      h('div', { class: 'actions' },
        h('button', { class: 'btn', onClick: () => { S.sheet = { kind: 'reveal', lost: true }; render(); } }, 'I can’t find it'),
        h('button', { class: 'btn', onClick: async () => { await invoke('recovery_snooze'); closeSheet(); } }, 'Remind me next week'),
        h('button', { class: 'btn primary', onClick: check }, 'Check'))];
  } else if (K.kind === 'reveal') {
    if (K.key) {
      body = [h('h2', {}, 'Your Secret Key'),
        h('div', { class: 'secret-key' }, K.key),
        h('p', { class: 'muted' }, K.lost ? 'Write it down now and keep it somewhere safe and offline, away from this Mac.' : 'Keep it somewhere safe and offline.'),
        h('div', { class: 'actions' },
          h('button', { class: 'btn', onClick: async () => { await invoke('copy_text', { text: K.key }); toast('Secret Key copied'); } }, icon('copy'), 'Copy'),
          h('button', { class: 'btn primary', onClick: async () => { if (K.lost) await invoke('recovery_verify', { secretKey: K.key }); K.key = null; closeSheet(); refreshSettings(); } }, 'I’ve saved it'))];
    } else {
      const pw = pwField('rv-pw', () => go());
      async function go() { try { K.key = await invoke('reveal_secret_key', { password: pw.value }); K.error = ''; render(); } catch (e) { fail(e); } }
      focusAfter = 'rv-pw';
      body = [h('h2', {}, 'Show Secret Key'), h('p', { class: 'muted' }, 'Enter your master password to see it.'),
        h('div', { class: 'field' }, h('label', { for: 'rv-pw' }, 'Master password'), pw), err,
        h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeSheet }, 'Cancel'), h('button', { class: 'btn primary', onClick: go }, 'Show'))];
    }
  } else if (K.kind === 'export') {
    const pw = pwField('ex-pw', () => go());
    async function go() {
      try { const p = await invoke('export_csv', { password: pw.value }); if (!p) return; closeSheet(); toast('Exported to ' + p.split('/').pop(), 'plain text: delete it when done'); }
      catch (e) { fail(e); }
    }
    focusAfter = 'ex-pw';
    body = [h('h2', {}, 'Export all items'),
      h('p', { class: 'muted' }, 'The CSV holds every password in plain text. Anyone who gets the file can read them. Passkeys can’t go in a CSV; your backups include them.'),
      h('div', { class: 'field' }, h('label', { for: 'ex-pw' }, 'Master password'), pw), err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeSheet }, 'Cancel'), h('button', { class: 'btn primary', onClick: go }, 'Export…'))];
  } else if (K.kind === 'vault-new' || K.kind === 'vault-edit') {
    const say = (m) => { err.textContent = String(m); };
    const editing = K.kind === 'vault-edit';
    const name = h('input', { class: 'input', id: 'vn-name', value: editing ? K.vault.name : '', placeholder: 'e.g. Work, Family, Finance', onKeydown: (e) => e.key === 'Enter' && save() });
    async function save() {
      try {
        if (editing) { await invoke('vault_rename', { id: K.vault.id, name: name.value }); toast('Vault renamed', null); }
        else { const id = await invoke('vault_create', { name: name.value }); S.view = 'items'; S.filter = id; toast('Vault created', null); }
        S.sheet = null; await load(); render();
      } catch (e) { say(e); }
    }
    const count = editing ? S.items.filter((i) => i.vaultId === K.vault.id).length + S.trash.filter((t) => t.vaultId === K.vault.id).length : 0;
    focusAfter = 'vn-name';
    body = [h('h2', {}, editing ? 'Edit vault' : 'New vault'),
      h('div', { class: 'field' }, h('label', { for: 'vn-name' }, 'Name'), name),
      editing && h('div', { class: 'sec-row' },
        h('span', { class: 'grow faint' }, count ? `Holds ${count} item${count === 1 ? '' : 's'} (incl. Recently deleted). Move or delete them to remove this vault.` : S.vaults.length < 2 ? 'lockbox always keeps at least one vault.' : 'This vault is empty.'),
        h('button', { class: 'btn sm danger', disabled: !!count || S.vaults.length < 2, onClick: async () => {
          try { await invoke('vault_delete', { id: K.vault.id }); if (S.filter === K.vault.id) S.filter = 'all'; S.sheet = null; await load(); render(); toast('Vault deleted', null); } catch (e) { say(e); }
        } }, icon('trash'), 'Delete vault')),
      err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeSheet }, 'Cancel'), h('button', { class: 'btn primary', onClick: save }, editing ? 'Save' : 'Create vault'))];
  } else if (K.kind === 'history') {
    const it = S.items.find((i) => i.id === K.id);
    body = [h('h2', {}, 'Previous passwords'), h('p', { class: 'muted' }, `Older passwords for ${it?.title ?? 'this item'}, newest first. Handy if a password change didn’t go through.`),
      h('div', { class: 'trows' }, K.dates.map((d, n) => h('div', { class: 'trow' },
        h('div', { class: 'grow' }, K.shown[n] != null ? h('span', { class: 'mono' }, pwChars(K.shown[n])) : h('span', { class: 'muted' }, '••••••••••••'), h('span', { class: 'faint' }, 'replaced ' + ago(d))),
        h('button', { class: 'icon-btn', 'aria-label': K.shown[n] != null ? 'Hide' : 'Reveal', onClick: async () => { if (K.shown[n] != null) delete K.shown[n]; else K.shown[n] = await invoke('history_reveal', { id: K.id, index: n }); render(); } }, icon('eye', 18)),
        h('button', { class: 'icon-btn', 'aria-label': 'Copy', onClick: async () => { await invoke('history_copy', { id: K.id, index: n }); toast('Old password copied'); } }, icon('copy', 17)),
        h('button', { class: 'btn sm', onClick: async () => {
          try { await invoke('history_restore', { id: K.id, index: n }); await load(); S.revealed = {}; S.sheet = null; render(); toast('Password restored', 'the replaced one is in history'); } catch (e) { say(e); }
        } }, 'Use this')))),
      err,
      h('div', { class: 'actions' }, h('button', { class: 'btn primary', onClick: closeSheet }, 'Done'))];
  } else if (K.kind === 'passwd') {
    const say = (m) => { err.textContent = String(m); };
    const cur = pwField('pw-cur', () => nw.focus());
    const nw = pwField('pw-new', () => rep.focus());
    const rep = pwField('pw-rep', () => go());
    const btn = h('button', { class: 'btn primary', onClick: () => go() }, 'Change password');
    async function go() {
      if (nw.value.length < 10) return say('Use at least 10 characters. A long phrase is easiest to remember.');
      if (nw.value !== rep.value) return say('The new passwords don’t match.');
      if (nw.value === cur.value) return say('That’s the same as your current password.');
      btn.disabled = true; btn.textContent = 'Changing…';
      try {
        const backedUp = await invoke('change_password', { current: cur.value, new: nw.value });
        S.sheet = null; render(); await refreshSettings();
        toast('Master password changed', backedUp ? 'fresh backup made' : 'back up now: old backups use the old password');
      } catch (e) { btn.disabled = false; btn.textContent = 'Change password'; say(e); }
    }
    focusAfter = 'pw-cur';
    body = [h('h2', {}, 'Change master password'),
      h('p', { class: 'muted' }, 'Your Secret Key stays the same. Backups made before today keep opening only with your old password, so lockbox makes a fresh one right after.'),
      h('div', { class: 'field' }, h('label', { for: 'pw-cur' }, 'Current master password'), cur),
      h('div', { class: 'field' }, h('label', { for: 'pw-new' }, 'New master password'), nw),
      h('div', { class: 'field' }, h('label', { for: 'pw-rep' }, 'Repeat new password'), rep),
      err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeSheet }, 'Cancel'), btn)];
  } else if (K.kind === 'restore') {
    const pw = pwField('rr-pw', () => go());
    async function go() {
      try { await invoke('restore', { path: K.path, password: pw.value, secretKey: null }); S.sheet = null; S.sel = null; await load(); S.view = 'items'; render(); toast('Backup restored', null); }
      catch (e) { fail(e); }
    }
    body = [h('h2', {}, 'Restore a backup'),
      h('p', { class: 'muted' }, 'This replaces the vault on this Mac with the backup. Your current vault is kept aside as a file, not deleted.'),
      h('button', { class: 'btn', onClick: async () => { const p = await invoke('restore_pick'); if (p) { K.path = p; render(); } } }, icon('download'), K.path ? K.path.split('/').pop() : 'Choose backup file…'),
      h('div', { class: 'field' }, h('label', { for: 'rr-pw' }, 'Master password for that backup'), pw), err,
      h('div', { class: 'actions' }, h('button', { class: 'btn', onClick: closeSheet }, 'Cancel'), h('button', { class: 'btn primary', disabled: !K.path, onClick: go }, 'Restore'))];
  }
  const scrim = h('div', { class: 'scrim', onMousedown: (e) => e.target === scrim && K.kind !== 'reveal' && closeSheet() },
    h('div', { class: 'sheet fade', role: 'dialog', 'aria-label': 'lockbox' }, h('div', { class: 'editor' }, ...body)));
  return scrim;
}

// ---------- keyboard + lifecycle ----------

let lastPing = 0;
document.addEventListener('keydown', (e) => {
  if (Date.now() - lastPing > 15000 && S.screen === 'app') { lastPing = Date.now(); invoke('activity'); }
  if (S.screen !== 'app') return;
  const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
  if (e.key === 'Escape') { if (S.sheet) closeSheet(); else if (S.importer) closeImporter(); else if (S.editor) closeEditor(); else if (S.palette) closePalette(); return; }
  if (e.metaKey && e.key === 'k') { e.preventDefault(); S.palette ? closePalette() : openPalette(); return; }
  if (e.metaKey && e.key === 'n') { e.preventDefault(); openEditor(); return; }
  if (e.metaKey && e.key === 'l') { e.preventDefault(); invoke('lock'); return; }
  if (S.palette || S.editor || S.importer || S.sheet || inField || S.view !== 'items') return;
  if (e.metaKey && e.key === 'c' && !window.getSelection().toString() && selected()?.hasPassword) { e.preventDefault(); copyField(S.sel, 'password', 'Password copied'); return; }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    const v = visible(); const n = v.findIndex((i) => i.id === S.sel);
    const next = v[Math.max(0, Math.min(v.length - 1, n + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (next) { e.preventDefault(); select(next.id); }
  }
});
document.addEventListener('mousedown', () => { if (Date.now() - lastPing > 15000 && S.screen === 'app') { lastPing = Date.now(); invoke('activity'); } });

listen('locked', () => {
  Object.assign(S, { screen: 'unlock', items: [], vaults: [], revealed: {}, palette: null, editor: null, importer: null, sheet: null, nudged: false, needSk: false });
  S.gen.value = '';
  render();
});

boot();
