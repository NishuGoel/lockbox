// In-field suggestions, real Chromium + extension + connector. Same setup as e2e.js, plus an item:
//   lockbox add Example -u me@example.com --url http://127.0.0.1:8766 --totp GEZDGNBVGY3TQOJQ   (password: s3cret-pass-1)
// Run: NODE_PATH=$(npm root -g)/@playwright/cli/node_modules node inline.js
const path = require('path');
const ROOT = path.resolve(__dirname, '../../..');
const { chromium } = require('playwright-core');
const { execFileSync } = require('child_process');
const EXT = ROOT + '/apps/extension';
const LB = (...a) => execFileSync(ROOT + '/target/release/lockbox', a, { env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' } }).toString();
const SITE = 'http://127.0.0.1:8766';
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const ctx = await chromium.launchPersistentContext('/tmp/lbx-chrome', { channel: 'chromium', headless: true, env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' },
    args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT], viewport: { width: 1100, height: 800 } });
  if (!ctx.serviceWorkers().length) await ctx.waitForEvent('serviceworker');
  const page = await ctx.newPage();
  const menu = (p = page) => p.waitForSelector('lockbox-menu', { timeout: 4000 }).then(() => true, () => false);
  const fresh = async (u) => { await page.goto('about:blank'); await page.goto(u); };

  // 1. focus → this site's login offered → ↓ ↵ fills
  await fresh(SITE + '/login.html');
  await page.focus('#email');
  ok(await menu(), 'focusing the email field shows suggestions');
  await page.screenshot({ path: '/tmp/lockbox-inline.png', clip: { x: 0, y: 0, width: 700, height: 300 } });
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter'); await sleep(800);
  ok((await page.inputValue('#email')) === 'me@example.com' && (await page.inputValue('#pw')) === 's3cret-pass-1', '↓ ↵ fills username and password');
  ok(!(await page.$('lockbox-menu')), 'menu closes after filling');

  // 2. typing yourself gets it out of the way
  await fresh(SITE + '/login.html');
  await page.focus('#email'); await menu();
  await page.keyboard.type('x');
  await sleep(150);
  ok(!(await page.$('lockbox-menu')) && !!(await page.$('lockbox-icon')), 'typing closes the menu (icon stays)');

  // 3. clickjacking: an invisible menu must not act on a real click, nor on a scripted one
  await fresh(SITE + '/login.html');
  await page.focus('#email'); await menu();
  await sleep(400);
  const box = await (await page.$('lockbox-menu')).boundingBox();
  await page.addStyleTag({ content: 'lockbox-menu { opacity: 0 !important }' });
  await page.mouse.click(box.x + 40, box.y + 22);
  await sleep(600);
  ok((await page.inputValue('#pw')) === '', 'real click on a menu the page made transparent: refused');
  await page.evaluate(() => { const h = document.querySelector('lockbox-menu'); h?.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true })); });
  await sleep(300);
  ok((await page.inputValue('#pw')) === '', 'scripted click: ignored');
  await fresh(SITE + '/login.html');
  await page.addStyleTag({ content: 'body { opacity: 0.02 }' });
  await page.focus('#email'); await menu(); await sleep(400);
  const b2 = await (await page.$('lockbox-menu')).boundingBox();
  await page.mouse.click(b2.x + 40, b2.y + 22); await sleep(600);
  ok((await page.inputValue('#pw')) === '', 'page faded itself (opacity on body): refused');
  await fresh(SITE + '/login.html');
  await page.focus('#email'); await menu();
  const b3 = await (await page.$('lockbox-menu')).boundingBox();
  await page.mouse.click(b3.x + 40, b3.y + 22); await sleep(500);
  ok((await page.inputValue('#pw')) === '', 'click in the first 300 ms after the menu appears: ignored');
  await sleep(400);
  await page.mouse.click(b3.x + 40, b3.y + 22); await sleep(800);
  ok((await page.inputValue('#pw')) === 's3cret-pass-1', 'a normal click on the intact menu fills');

  // 4. sign-up: strong password into both fields
  await fresh(SITE + '/signup.html');
  await page.focus('#pw1');
  ok(await menu(), 'sign-up password field offers a strong password');
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter'); await sleep(800);
  const [p1, p2] = [await page.inputValue('#pw1'), await page.inputValue('#pw2')];
  ok(p1.length === 20 && p1 === p2, 'generated password filled into both fields');

  // 5. 2FA field
  await fresh(SITE + '/otp.html');
  await page.focus('#code');
  ok(await menu(), '2FA field offers the code');
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter'); await sleep(800);
  ok(/^\d{6}$/.test(await page.inputValue('#code')), '2FA code filled');

  // 6. a login frame from another site gets nothing from this site's logins
  await fresh(SITE + '/framed.html');
  const frame = await (await page.waitForSelector('#frame')).contentFrame();
  await frame.waitForSelector('#email');
  await frame.focus('#email'); await sleep(1500);
  ok(!(await frame.$('lockbox-menu')) && !(await page.$('lockbox-menu')), 'foreign-origin login frame: no suggestions');

  // 7. locked: a quiet icon, menu only on click
  LB('lock');
  await fresh(SITE + '/login.html');
  await page.focus('#email');
  ok(await page.waitForSelector('lockbox-icon', { timeout: 4000 }).then(() => true, () => false) && !(await page.$('lockbox-menu')), 'locked: just the icon, no menu');
  await sleep(400);
  const ib = await (await page.$('lockbox-icon')).boundingBox();
  await page.mouse.click(ib.x + 11, ib.y + 11);
  ok(await menu(), 'clicking the icon explains it is locked');

  await ctx.close();
})().catch((e) => { console.error(e); process.exit(1); });
