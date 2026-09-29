// Shared by the main and Quick Access windows. All DOM goes through h() with textContent — never innerHTML —
// so item data can't inject markup.
const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);
const listen = (ev, fn) => window.__TAURI__.event.listen(ev, fn);

const SVG = 'http://www.w3.org/2000/svg';
const ICONS = {
  lock: 'M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
  plus: 'M12 5v14M5 12h14',
  grid: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  star: 'M12 3l2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9z',
  spark: 'M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8',
  copy: 'M9 9h11v11H9zM5 15V4h11',
  eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  shield: 'M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z',
  check: 'M5 12l5 5 9-10',
  refresh: 'M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
  key: 'M14 10a4 4 0 1 0-3.5 4L9 16H7v2H5v2H3v-3l6.5-6.5A4 4 0 0 0 14 10zM15.5 8.5v.01',
};

function icon(name, size = 16, fill = false) {
  const s = document.createElementNS(SVG, 'svg');
  for (const [k, v] of Object.entries({ width: size, height: size, viewBox: '0 0 24 24', fill: fill ? 'currentColor' : 'none', stroke: fill ? 'none' : 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) s.setAttribute(k, v);
  const p = document.createElementNS(SVG, 'path');
  p.setAttribute('d', ICONS[name]);
  s.append(p);
  return s;
}

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'hue') el.style.setProperty('--hue', v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

const HUES = ['#A78BFA', '#FB923C', '#34D399', '#F472B6', '#60A5FA', '#FACC15', '#818CF8', '#F87171', '#4ADE80', '#22D3EE'];
function hue(s) {
  let n = 0;
  for (const c of s) n = (n * 31 + c.charCodeAt(0)) >>> 0;
  return HUES[n % HUES.length];
}
const tile = (title, size) => h('span', { class: 'tile ' + size, hue: hue(title) }, (title.trim()[0] || '?').toUpperCase());

// digits blue, symbols orange: tells 0/O and l/1 apart at a glance
function pwChars(s) {
  return h('span', {}, [...s].map((ch) => /[0-9]/.test(ch) ? h('span', { class: 'd' }, ch) : /[A-Za-z]/.test(ch) ? ch : h('span', { class: 'y' }, ch)));
}

function ago(secs) {
  const d = Date.now() / 1000 - secs;
  const units = [[31536000, 'year'], [2592000, 'month'], [86400, 'day'], [3600, 'hour'], [60, 'minute']];
  for (const [n, u] of units) if (d >= n) { const k = Math.floor(d / n); return `${k} ${u}${k > 1 ? 's' : ''} ago`; }
  return 'just now';
}

function host(url) {
  try { return new URL(url.includes('://') ? url : 'https://' + url).host; } catch { return url; }
}

function matches(it, q) {
  if (!q) return true;
  q = q.toLowerCase();
  return [it.title, it.username || '', ...it.urls, ...it.tags].some((s) => s.toLowerCase().includes(q));
}

let toastTimer;
function toast(msg, sub = 'clears in 90s') {
  document.querySelector('.toast')?.remove();
  clearTimeout(toastTimer);
  const t = h('div', { class: 'toast fade', role: 'status' }, icon('check', 16), h('span', {}, msg), sub && h('span', { class: 'faint' }, '· ' + sub));
  document.getElementById('root').append(t);
  toastTimer = setTimeout(() => t.remove(), 2600);
}
