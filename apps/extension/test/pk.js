// Same setup as e2e.js (see its header). Run: NODE_PATH=$(npm root -g)/@playwright/cli/node_modules node pk.js
const ROOT = require('path').resolve(__dirname, '../../..');
const { chromium } = require('playwright-core');
const { execFileSync } = require('child_process');
const EXT = '' + ROOT + '/apps/extension';
const LB = (...a) => execFileSync('' + ROOT + '/target/release/lockbox', a, { env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' } }).toString();
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  const ctx = await chromium.launchPersistentContext('/tmp/lbx-chrome', { channel: 'chromium', headless: true, env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' },
    args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT] });
  if (!ctx.serviceWorkers().length) await ctx.waitForEvent('serviceworker');
  const page = await ctx.newPage();
  page.on('console', (m) => m.type() === 'error' && console.log('    [page]', m.text()));
  const gone = () => page.waitForSelector('lockbox-offer', { state: 'detached', timeout: 5000 }).catch(() => {});
  const out = async (prefix) => { await page.waitForFunction((p) => document.getElementById('out').textContent.startsWith(p), prefix, { timeout: 8000 }).catch(() => {}); return page.textContent('#out'); };
  await page.goto('http://localhost:8766/passkey.html');

  // create → our prompt → Enter (Save passkey)
  await page.click('#reg');
  ok(await page.waitForSelector('lockbox-offer', { timeout: 4000 }).then(() => true, () => false), 'lockbox offers to save the passkey');
  await page.screenshot({ path: '/tmp/lockbox-pk-save.png', clip: { x: 800, y: 0, width: 480, height: 170 } });
  await page.keyboard.press('Enter');
  const reg = await out('registered');
  console.log('   ', reg);
  ok(/"type":"webauthn.create","origin":"http:\/\/localhost:8766","challengeOk":true,"alg":-7,"isPKC":true,"rk":true,"json":"string"/.test(reg), 'site receives a valid credential (origin, challenge, ES256, credProps, toJSON)');
  const item = JSON.parse(LB('get', 'Local Test', '-f', 'json'));
  ok(item.passkey?.rp_id === 'localhost' && item.passkey.user_name === 'nishu@test' && item.urls[0] === 'https://localhost', 'passkey stored in lockbox as an item');

  // sign in → account list → Enter
  await gone();
  await page.click('#login');
  await page.waitForSelector('lockbox-offer', { timeout: 4000 });
  await page.screenshot({ path: '/tmp/lockbox-pk-signin.png', clip: { x: 800, y: 0, width: 480, height: 200 } });
  await page.keyboard.press('Enter');
  const login = await out('login');
  console.log('   ', login);
  ok(/"verified":true,"type":"webauthn.get","challengeOk":true,"user":"user-1"/.test(login), 'site verifies the signature with WebCrypto and gets the user handle');

  // a page script can't approve by clicking (untrusted events are ignored)
  await gone();
  await page.click('#login');
  await page.waitForSelector('lockbox-offer');
  await page.evaluate(() => { const h = document.querySelector('lockbox-offer'); h.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true })); h.click(); });
  await sleep(600);
  ok((await page.textContent('#out')).startsWith('login {"verified":true') && !!(await page.$('lockbox-offer')), 'synthetic clicks from the page do nothing; prompt still waiting');
  await page.keyboard.press('Tab'); await page.keyboard.press('Enter'); // "Other options"
  await sleep(300);
  ok(!(await page.$('lockbox-offer')), '"Other options" hands the request back to the browser');

  // declining a create hands it to the browser: lockbox's prompt goes away and the page is now
  // waiting on the browser's own dialog (headless has no UI to answer it), not failed by lockbox
  await page.reload();
  await page.click('#reg2');
  await page.waitForSelector('lockbox-offer'); await page.keyboard.press('Tab'); await page.keyboard.press('Enter');
  await sleep(600);
  ok(!(await page.$('lockbox-offer')) && (await page.textContent('#out')) === '', 'declining a create hands it to the browser (no lockbox error)');
  const items = LB('ls');
  ok((items.match(/Local Test/g) || []).length === 1, 'still exactly one passkey item for the account');

  await ctx.close();
})().catch((e) => { console.error(e); process.exit(1); });
