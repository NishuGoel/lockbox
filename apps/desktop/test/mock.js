// Browser stand-in for the lockbox app backend (same command names as src-tauri/src/main.rs),
// so the UI can be driven in a normal browser: ./serve.sh, then open http://127.0.0.1:8765
// Unlock password: correct horse battery
(() => {
  const L = {}; const emit = (ev) => (L[ev] || []).forEach((f) => f({ payload: null }));
  const now = Date.now() / 1000;
  const V = [{ id: 'v1', name: 'Personal' }, { id: 'v2', name: 'Work' }];
  const db = [
    ['GitHub', 'v1', 'me@example.com', 'k7#Rm-vQ2p!xWz9LbT4$', 'https://github.com', 'GEZDGNBVGY3TQOJQ', ['dev'], true],
    ['AWS Console', 'v2', 'root-admin', 'Summer2024!', 'https://console.aws.amazon.com', null, ['infra'], false],
    ['Online banking', 'v1', '[CUSTOMER NO.]', 'q9$Lx-2mV!rP7hZc', 'https://bank.example', 'GEZDGNBVGY3TQOJQ', ['finance'], true],
    ['Linear', 'v2', 'me@example.com', 'Vb3!nQ8#tLm2Wx7r', 'https://linear.app', null, ['dev'], false],
    ['Home Wi-Fi', 'v1', 'lockbox-5G', 'maple-orbit-quiet-lantern', null, null, [], false],
  ].map(([title, vault, username, password, url, totp, tags, favorite], n) => ({ id: 'i' + n, vault, item: { kind: 'login', title, username, password, urls: url ? [url] : [], notes: n === 4 ? 'Router is in the hallway cupboard.' : null, totp, tags, fields: [], favorite, created_at: now - 86400 * (n + 2), updated_at: now - 86400 * (n + 1), password_history: n === 0 ? [{ password: 'older-pass-1', replaced_at: now - 86400 * 40 }] : [], passkey: null } }));
  const trash = []; let unlocked = false; let n = 100;
  const agentQ = []; const agentLog = []; let agentVaults = null; window.__decisions = [];
  // simulate `lockbox run` asking: __mock.ask('Claude Code', 'npm run deploy', ['AWS Console › password (Work)'])
  const ask = (agent, command, labels) => { agentQ.push({ id: 'a' + n++, agent, command, cwd: '/Users/you/projects/shop', refs: [], labels, status: 'pending', created: Date.now() / 1000 }); emit('agent-approval'); };
  const st = { autoBackup: true, backupDir: null, lastBackup: now - 3600, lastBackupError: null, backupAsked: true, lastRecoveryCheck: now, shareUrl: null, shares: [] };
  const ver = { describe: '0.1.0 (2a78a23, 2026-11-04)', version: '0.1.0', commit: '2a78a23', date: '2026-11-04', dirty: false, repoDir: '/Users/you/projects/lockbox', updateCheck: true, behind: null, lastCheck: 0 };
  const view = (r) => ({ id: r.id, vaultId: r.vault, kind: r.item.kind, title: r.item.title, username: r.item.username, urls: r.item.urls, notes: r.item.notes, tags: r.item.tags, favorite: r.item.favorite, hasPassword: !!r.item.password, hasTotp: !!r.item.totp, fields: [], updatedAt: r.item.updated_at, passkey: r.item.passkey, historyCount: r.item.password_history.length });
  const C = {
    status: () => ({ exists: true, unlocked, hasSecretKey: true }),
    unlock: ({ password }) => { if (password !== 'correct horse battery') throw 'wrong master password or Secret Key'; unlocked = true; },
    lock: () => { unlocked = false; emit('locked'); },
    activity: () => {}, vaults: () => V, items: () => db.map(view), trash_list: () => trash.map((r) => ({ id: r.id, vaultId: r.vault, title: r.item.title, username: r.item.username, deletedAt: r.deletedAt })),
    get_item: ({ id }) => structuredClone(db.find((r) => r.id === id).item),
    reveal: ({ id, field }) => db.find((r) => r.id === id).item[field],
    totp_code: () => { const s = Math.floor(Date.now() / 1000); return { code: String((Math.floor(s / 30) * 7919) % 1000000).padStart(6, '0'), remaining: 30 - (s % 30) }; },
    copy: () => {}, copy_text: () => {}, generate: () => 'Gen3rated-Pass!word42',
    save_item: ({ id, vaultId, item }) => { if (!item.title) throw 'Give the item a title.'; if (id) { const r = db.find((r) => r.id === id); r.item = { ...item, updated_at: Date.now() / 1000 }; if (vaultId) r.vault = vaultId; return id; } const nid = 'i' + n++; db.push({ id: nid, vault: vaultId, item: { ...item, updated_at: Date.now() / 1000, password_history: [] } }); return nid; },
    delete_item: ({ id }) => { const r = db.splice(db.findIndex((r) => r.id === id), 1)[0]; r.deletedAt = Date.now() / 1000; trash.push(r); },
    restore_item: ({ id }) => db.push(trash.splice(trash.findIndex((r) => r.id === id), 1)[0]),
    purge_item: ({ id }) => trash.splice(trash.findIndex((r) => r.id === id), 1), empty_trash: () => trash.splice(0).length,
    settings_get: () => ({ ...st, backupDirShown: 'iCloud Drive/lockbox Backups', icloud: true, recoveryDue: false }),
    version_info: () => ({ ...ver }),
    check_update: () => { Object.assign(ver, { behind: window.__behind ?? 0, lastCheck: Date.now() / 1000 }); return { behind: ver.behind, compareUrl: 'https://github.com/x/y/compare/a...main' }; },
    set_update_check: ({ on }) => { ver.updateCheck = on; },
    share_state: () => ({ url: st.shareUrl, links: st.shares }),
    hide_quick: () => {}, open_main: () => {},
    agent_pending: () => agentQ.filter((a) => a.status === 'pending'),
    agent_decide: ({ id, decision }) => { const a = agentQ.find((x) => x.id === id); a.status = decision === 'deny' ? 'denied' : 'approved'; agentLog.unshift({ at: Date.now() / 1000, agent: a.agent, command: a.command, cwd: a.cwd, labels: a.labels, outcome: { deny: 'denied', once: 'approved once', hour: 'approved for 1 hour' }[decision] }); window.__decisions.push(decision); },
    agent_settings: () => ({ vaults: agentVaults, log: agentLog }),
    agent_set_vaults: ({ vaults }) => { agentVaults = vaults; },
    agent_revoke_all: () => { window.__revoked = true; },
  };
  window.__TAURI__ = {
    core: { invoke: async (cmd, args) => { await new Promise((r) => setTimeout(r, cmd === 'unlock' ? 200 : 5)); if (!C[cmd]) throw 'mock: no command ' + cmd; return C[cmd](args || {}); } },
    event: { listen: async (ev, f) => { (L[ev] ||= []).push(f); } },
  };
  window.__mock = { emit, ver, st, db, ask };
})();
