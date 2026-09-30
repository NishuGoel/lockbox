// lockbox service worker: talks to the lockbox app via native messaging, fills only frames on the
// saved site, and holds "save this login?" offers in session storage (memory only, never disk).
const HOST = 'dev.lockbox.connector';
const OFFER_TTL = 3 * 60 * 1000;

function native(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, msg, (reply) => {
      if (chrome.runtime.lastError) resolve({ error: 'no_connector', detail: chrome.runtime.lastError.message });
      else resolve(reply ?? { error: 'no reply' });
    });
  });
}

function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, '').replace(/\.$/, '').toLowerCase(); } catch { return ''; }
}
// cheap pre-filter only; the app re-checks every fill with the real rule (site_matches)
const couldMatch = (frameUrl, itemHost) => { const h = hostOf(frameUrl); return !!itemHost && (h === itemHost || h.endsWith('.' + itemHost)); };

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  // tab.url needs the activeTab grant; the main frame's URL from webNavigation doesn't
  if (tab && !tab.url) tab.url = (await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 }).catch(() => null))?.url;
  return tab;
}

async function fillItem(tab, item) {
  const frames = (await chrome.webNavigation.getAllFrames({ tabId: tab.id })) || [];
  const targets = frames.filter((f) => /^https?:/.test(f.url) && couldMatch(f.url, item.host));
  let filled = null;
  for (const f of targets) {
    const creds = await native({ cmd: 'fill', id: item.id, url: f.url });
    if (creds.error) continue;
    try {
      const r = await chrome.tabs.sendMessage(tab.id, { type: 'fill', creds }, { frameId: f.frameId });
      filled = filled || r?.filled;
    } catch { /* frame without our content script (e.g. still loading) */ }
  }
  return filled;
}

// ⌘⇧L: one saved login for this site → fill it; otherwise open the popup to choose
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== 'fill') return;
  const tab = await activeTab();
  if (!tab?.url) return;
  const m = await native({ cmd: 'match', url: tab.url });
  if (m.items?.length === 1) {
    if (await fillItem(tab, m.items[0])) return;
  }
  chrome.action.openPopup().catch(() => {});
});

async function offers() { return (await chrome.storage.session.get('offers')).offers || {}; }
async function setOffer(tabId, offer) {
  const all = await offers();
  if (offer) all[tabId] = offer; else delete all[tabId];
  await chrome.storage.session.set({ offers: all });
}
async function neverHosts() { return (await chrome.storage.local.get('never')).never || []; }

chrome.tabs.onRemoved.addListener((tabId) => setOffer(tabId, null));

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    const tabId = sender.tab?.id;
    switch (msg.type) {
      // ---- from content scripts ----
      case 'username': { // step 1 of a two-step login: remember who, for the password step
        const all = (await chrome.storage.session.get('users')).users || {};
        all[tabId] = { username: msg.username, host: hostOf(sender.url), at: Date.now() };
        await chrome.storage.session.set({ users: all });
        return reply({});
      }
      case 'captured': {
        const host = hostOf(msg.url);
        if (!host || (await neverHosts()).includes(host)) return reply({});
        let username = msg.username;
        if (!username) {
          const u = ((await chrome.storage.session.get('users')).users || {})[tabId];
          if (u && u.host === host && Date.now() - u.at < 10 * 60 * 1000) username = u.username;
        }
        const check = await native({ cmd: 'check', url: msg.url, username, password: msg.password });
        const status = check.status || (check.error === 'no_connector' ? 'no_connector' : null);
        if (!['new', 'changed', 'locked'].includes(status)) return reply({});
        const offer = { url: msg.url, host, username, password: msg.password, status, id: check.id || null, title: check.title || host, at: Date.now() };
        await setOffer(tabId, offer);
        chrome.tabs.sendMessage(tabId, { type: 'offer', offer: publicOffer(offer) }, { frameId: 0 }).catch(() => {});
        return reply({});
      }
      case 'offer?': { // a freshly loaded page (after the login navigated) asks for a pending offer
        const o = (await offers())[tabId];
        if (o && Date.now() - o.at < OFFER_TTL && hostOf(sender.url) === o.host) return reply({ offer: publicOffer(o) });
        if (o && Date.now() - o.at >= OFFER_TTL) await setOffer(tabId, null);
        return reply({});
      }
      case 'decide': {
        const o = (await offers())[tabId];
        if (!o) return reply({ error: 'expired' });
        if (msg.action === 'never') {
          await chrome.storage.local.set({ never: [...new Set([...(await neverHosts()), o.host])] });
          await setOffer(tabId, null);
          return reply({ done: true });
        }
        if (msg.action !== 'save') { await setOffer(tabId, null); return reply({ done: true }); }
        const r = await native({ cmd: 'save', url: o.url, username: o.username, password: o.password, id: o.status === 'changed' ? o.id : null });
        if (r.error === 'locked') { native({ cmd: 'open_app' }); return reply({ error: 'locked' }); }
        if (r.error) return reply({ error: r.error === 'no_connector' ? 'Open the lockbox app once to connect this browser.' : r.error });
        await setOffer(tabId, null);
        return reply({ done: true, result: r });
      }
      // ---- from the popup ----
      case 'popup': {
        const tab = await activeTab();
        const status = await native({ cmd: 'status' });
        const state = status.state || status.error;
        const res = { state, url: tab?.url || '', host: hostOf(tab?.url || '') };
        if (state === 'unlocked' && tab?.url) res.items = (await native({ cmd: 'match', url: tab.url })).items || [];
        return reply(res);
      }
      case 'search': {
        const tab = await activeTab();
        return reply(await native({ cmd: 'search', q: msg.q, url: tab?.url || '' }));
      }
      case 'fill': {
        const tab = await activeTab();
        return reply({ filled: await fillItem(tab, msg.item) });
      }
      case 'copy': return reply(await native({ cmd: 'copy', id: msg.id, field: msg.field }));
      case 'open_app': return reply(await native({ cmd: 'open_app' }));
      case 'generate': {
        const tab = await activeTab();
        const g = await native({ cmd: 'generate', length: 20 });
        if (g.error) return reply(g);
        const r = await chrome.tabs.sendMessage(tab.id, { type: 'fill-new-password', password: g.password }, { frameId: 0 }).catch(() => null);
        return reply({ password: g.password, filled: r?.filled });
      }
      case 'never-list': return reply({ never: await neverHosts() });
      case 'never-remove': {
        await chrome.storage.local.set({ never: (await neverHosts()).filter((h) => h !== msg.host) });
        return reply({});
      }
    }
  })();
  return true; // async reply
});

// the page never gets the password back, only what the banner shows
const publicOffer = (o) => ({ host: o.host, username: o.username, status: o.status, title: o.title });
