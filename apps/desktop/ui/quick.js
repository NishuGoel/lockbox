// Quick Access (⌘⇧Space): ↵ password, ⌥↵ 2FA code, ⌘C username, esc closes. Copies happen in Rust.
const root = document.getElementById('root');
const Q = { items: [], q: '', idx: 0 };

const results = () => Q.items.filter((i) => matches(i, Q.q)).sort((a, b) => a.title.localeCompare(b.title)).slice(0, 8);

async function copyAndClose(field, what) {
  const it = results()[Q.idx];
  if (!it) return;
  try { await invoke('copy', { id: it.id, field }); invoke('hide_quick'); }
  catch (e) { toast(`${it.title} has no ${what}`, null); }
}

function paint(list) {
  const rs = results();
  Q.idx = Math.min(Q.idx, Math.max(0, rs.length - 1));
  list.replaceChildren(...(rs.length
    ? rs.map((it, n) => h('button', { class: 'pal-row' + (n === Q.idx ? ' on' : ''), onClick: () => { Q.idx = n; copyAndClose('password', 'password'); } },
        tile(it.title, 's'),
        h('span', { class: 'grow' }, h('span', {}, it.title), h('span', { class: 'faint' }, it.username ? ' · ' + it.username : '')),
        it.hasTotp && h('span', { class: 'faint mono' }, '2FA')))
    : [h('div', { class: 'empty' }, Q.items.length ? 'No matches.' : 'No items yet.')]));
  list.querySelector('.on')?.scrollIntoView({ block: 'nearest' });
}

async function show() {
  const st = await invoke('status');
  if (!st.unlocked) {
    root.replaceChildren(h('div', { class: 'q-locked' }, h('div', { class: 'logo-tile' }, icon('lock', 28)), h('p', {}, 'lockbox is locked.'),
      h('button', { class: 'btn primary', id: 'q-open', onClick: () => invoke('open_main') }, 'Open lockbox to unlock')));
    document.getElementById('q-open').focus();
    return;
  }
  Q.items = await invoke('items'); Q.q = ''; Q.idx = 0;
  const list = h('div', { class: 'q-list', role: 'listbox' });
  const input = h('input', { placeholder: 'Search lockbox…', 'aria-label': 'Search lockbox', spellcheck: 'false',
    onInput: (e) => { Q.q = e.target.value; Q.idx = 0; paint(list); },
    onKeydown: (e) => {
      const n = results().length || 1;
      if (e.key === 'ArrowDown') { Q.idx = (Q.idx + 1) % n; paint(list); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { Q.idx = (Q.idx - 1 + n) % n; paint(list); e.preventDefault(); }
      else if (e.key === 'Enter') copyAndClose(e.altKey ? 'totp' : 'password', e.altKey ? '2FA code' : 'password');
      else if (e.metaKey && e.key === 'c' && input.selectionStart === input.selectionEnd) { e.preventDefault(); copyAndClose('username', 'username'); }
    } });
  const k = (key, label) => h('span', {}, h('span', { class: 'kbd' }, key), label);
  root.replaceChildren(
    h('div', { class: 'q-in' }, h('span', { class: 'brand' }, h('span', { class: 'mark' }, icon('lock', 15))), input, h('span', { class: 'faint' }, '⌘⇧Space')),
    list,
    h('div', { class: 'q-foot' }, k('↵', 'Copy password'), k('⌘C', 'Copy username'), k('⌥↵', 'Copy 2FA code'), h('span', { class: 'spacer' }), k('esc', 'Close')));
  paint(list);
  input.focus();
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') invoke('hide_quick'); });
listen('quick-shown', show);
listen('locked', () => root.replaceChildren());
