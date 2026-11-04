// Captures the Chrome Web Store screenshots from the real extension on the demo site (store/demo,
// served at http://localhost:8767) against a demo vault in /tmp/lbx. See store/README.md.
const path = require('path');
const ROOT = path.resolve(__dirname, '../../..');
const { chromium } = require('playwright-core');
const EXT = ROOT + '/apps/extension';
const OUT = path.join(__dirname, 'images');
const DEMO = 'http://acme.example:8767';      // mapped to this Mac by --host-resolver-rules
const NORTHWIND = 'http://northwind.localhost:8767'; // passkeys need a secure context; *.localhost is one
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const ctx = await chromium.launchPersistentContext('/tmp/lbx-chrome', { channel: 'chromium', headless: true, env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' },
    args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT, '--host-resolver-rules=MAP acme.example 127.0.0.1'], viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
  if (!ctx.serviceWorkers().length) await ctx.waitForEvent('serviceworker');
  const page = await ctx.newPage();
  const shot = (name) => page.screenshot({ path: path.join(OUT, name) });
  const fresh = async (u) => { await page.goto('about:blank'); await page.goto(u); };

  // 1. suggestions right in the field
  await fresh(DEMO + '/login.html');
  await page.focus('#email');
  await page.waitForSelector('lockbox-menu'); await sleep(400);
  await shot('1-suggestions.png');

  // 2. save offer after signing in with a new account
  await fresh(DEMO + '/login.html');
  await page.fill('#email', 'jordan@acme.example'); await page.fill('#pw', 'Tr1ck-Lantern-Rocket');
  await page.click('#go'); await page.waitForURL('**/welcome.html');
  await page.waitForSelector('lockbox-offer'); await sleep(500);
  await shot('2-save.png');
  await page.keyboard.press('Tab'); await page.keyboard.press('Enter'); // not now

  // 3. passkeys: create one in lockbox, then sign in with it
  await fresh(NORTHWIND + '/passkey.html');
  await page.click('#reg'); await page.waitForSelector('lockbox-offer'); await sleep(300);
  await page.keyboard.press('Enter'); await sleep(2600);
  await fresh(NORTHWIND + '/passkey.html');
  await page.click('#login'); await page.waitForSelector('lockbox-offer'); await sleep(500);
  await shot('3-passkey.png');

  // 4. the toolbar popup (rendered on its own; composed onto the page by compose.py)
  await fresh(DEMO + '/login.html'); await sleep(300);
  await shot('4-base.png');
  const pop = await ctx.newPage();
  await pop.setViewportSize({ width: 360, height: 430 });
  await pop.goto('chrome-extension://ndlmdmhhecdngfpeehboklmiehkgbnpe/popup.html');
  await pop.waitForSelector('.search'); await pop.fill('.search', 'a'); await sleep(700);
  await pop.screenshot({ path: path.join(OUT, '4-popup.png') });

  // small promo tile 440x280
  const tile = await ctx.newPage();
  await tile.setViewportSize({ width: 440, height: 280 });
  await tile.setContent(`<body style="margin:0;width:440px;height:280px;display:flex;flex-direction:column;justify-content:center;gap:14px;padding:0 36px;box-sizing:border-box;
    background:radial-gradient(500px 300px at 20% 0%,rgba(94,234,212,.18),transparent),#0B0D12;color:#ECEEF3;font-family:-apple-system,system-ui,sans-serif">
    <div style="display:flex;align-items:center;gap:14px"><div style="width:56px;height:56px;border-radius:16px;background:rgba(94,234,212,.14);display:flex;align-items:center;justify-content:center">
    <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#5EEAD4" stroke-width="2" stroke-linecap="round"><path d="M6 11h12v9H6zM8 11V8a4 4 0 0 1 8 0v3"/></svg></div>
    <div style="font-size:40px;font-weight:800;letter-spacing:-.02em">lockbox</div></div>
    <div style="font-size:19px;line-height:1.35;color:#9BA3B4">Your passwords and passkeys,<br>right where you sign in.</div></body>`);
  await tile.screenshot({ path: path.join(OUT, 'promo-small-440x280.png') });

  await ctx.close();
})().catch((e) => { console.error(e); process.exit(1); });
