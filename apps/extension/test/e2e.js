// Real-Chromium check of the extension + connector. Setup (see scripts in the PR description):
//   1. a test vault in /tmp/lbx, unlocked:  LOCKBOX_DIR=/tmp/lbx lockbox init && lockbox unlock
//   2. cargo build -p lockbox-desktop  (the connector) and --release -p lockbox-cli
//   3. /tmp/lbx-chrome/NativeMessagingHosts/dev.lockbox.connector.json -> target/debug/lockbox-desktop
//   4. python3 -m http.server 8766 --bind 127.0.0.1  in ./site
// Run: NODE_PATH=$(npm root -g)/@playwright/cli/node_modules node e2e.js
const path = require('path');
const ROOT = path.resolve(__dirname, '../../..');
const { chromium } = require('playwright-core');
const { execFileSync } = require('child_process');
const EXT = '' + ROOT + '/apps/extension';
const LB = (...a) => execFileSync('' + ROOT + '/target/release/lockbox', a, { env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' } }).toString();
const SITE = 'http://127.0.0.1:8766';
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const ctx = await chromium.launchPersistentContext('/tmp/lbx-chrome', {
    channel: 'chromium', headless: true, env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' },
    args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT],
  });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent('serviceworker');
  ok(sw.url().startsWith('chrome-extension://ndlmdmhhecdngfpeehboklmiehkgbnpe/'), 'extension loaded with the fixed id');
  ok((await sw.evaluate(() => native({ cmd: 'status' }))).state === 'unlocked', 'connector reaches the unlocked vault');

  const page = await ctx.newPage();
  const login = async (email, pw) => {
    await page.goto(SITE + '/login.html');
    await page.fill('#email', email); await page.fill('#pw', pw);
    await page.click('#go'); await page.waitForURL('**/welcome.html');
  };
  const banner = () => page.waitForSelector('lockbox-offer', { timeout: 4000 }).then(() => true, () => false);

  // 1. new login → offer survives the navigation → Enter saves
  await login('me@example.com', 's3cret-pass-1');
  ok(await banner(), 'save offer shown on the page after login');
  await page.screenshot({ path: '/tmp/lockbox-banner.png', clip: { x: 800, y: 0, width: 480, height: 180 } });
  await page.keyboard.press('Enter'); await sleep(1200);
  ok(/127\.0\.0\.1\s+me@example\.com/.test(LB('ls')), 'login saved to lockbox (title = host)');

  // 2. same login again → no offer
  await login('me@example.com', 's3cret-pass-1');
  ok(!(await banner()), 'no offer when the login is already saved');

  // 3. fill on the right site
  await page.goto(SITE + '/login.html');
  const filled = await sw.evaluate(async () => { const tab = await activeTab(); const m = await native({ cmd: 'match', url: tab.url }); return fillItem(tab, m.items[0]); });
  ok(filled === 'login' && (await page.inputValue('#email')) === 'me@example.com' && (await page.inputValue('#pw')) === 's3cret-pass-1', 'fills username + password on the saved site');

  // 4. lookalike host → nothing filled
  await page.goto('http://localhost:8766/login.html');
  const phish = await sw.evaluate(async () => { const tab = await activeTab(); const m = await native({ cmd: 'search', q: '127', url: tab.url }); return [m.items[0].matches, await fillItem(tab, m.items[0])]; });
  ok(phish[0] === false && phish[1] === null && (await page.inputValue('#pw')) === '', 'refuses to fill a different host');

  // 5. changed password → Update offer → history kept
  await login('me@example.com', 'n3w-pass-2');
  ok(await banner(), 'update offer after logging in with a new password');
  await page.keyboard.press('Enter'); await sleep(1200);
  const item = JSON.parse(LB('get', '127.0.0.1', '-f', 'json'));
  ok(item.password === 'n3w-pass-2' && item.password_history[0].password === 's3cret-pass-1', 'password updated, old one in history');

  // 6. 2FA page
  LB('edit', '127.0.0.1', '--totp', 'GEZDGNBVGY3TQOJQ');
  await page.goto(SITE + '/otp.html');
  const otp = await sw.evaluate(async () => { const tab = await activeTab(); const m = await native({ cmd: 'match', url: tab.url }); return fillItem(tab, m.items[0]); });
  ok(otp === 'totp' && /^\d{6}$/.test(await page.inputValue('#code')), 'fills the 2FA code on a code page');

  // 7. "Never for this site" (reached by keyboard: the banner is a closed shadow root)
  await login('other@example.com', 'another-1');
  ok(await banner(), 'offer for a second account');
  await page.keyboard.press('Tab'); await page.keyboard.press('Tab'); await page.keyboard.press('Enter'); await sleep(500);
  const never = await sw.evaluate(() => chrome.storage.local.get('never'));
  ok(JSON.stringify(never.never) === '["127.0.0.1"]', 'site added to the never list');
  await login('third@example.com', 'another-2');
  ok(!(await banner()), 'no more offers on a never-site');
  ok(!/other@example/.test(LB('ls')), 'the dismissed login was not saved');

  // 8. the page can't see the password in the offer
  const leaked = await page.evaluate(() => document.documentElement.outerHTML.includes('another-2') || document.querySelector('lockbox-offer')?.shadowRoot !== null && !!document.querySelector('lockbox-offer')?.shadowRoot);
  ok(!leaked, 'banner is a closed shadow root and the page never sees the password');

  await ctx.close();
})().catch((e) => { console.error(e); process.exit(1); });
