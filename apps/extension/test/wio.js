// Same setup as e2e.js (see its header). Run: NODE_PATH=$(npm root -g)/@playwright/cli/node_modules node wio.js
const ROOT = require('path').resolve(__dirname, '../../..');
const { chromium } = require('playwright-core');
const EXT = '' + ROOT + '/apps/extension';
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
(async () => {
  const ctx = await chromium.launchPersistentContext('/tmp/lbx-chrome', { channel: 'chromium', headless: true, env: { ...process.env, LOCKBOX_DIR: '/tmp/lbx' },
    args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT] });
  if (!ctx.serviceWorkers().length) await ctx.waitForEvent('serviceworker');
  const p = await ctx.newPage();
  const user = 'lockbox-e2e-' + Math.random().toString(36).slice(2, 8);
  await p.goto('https://webauthn.io', { waitUntil: 'networkidle' });
  await p.fill('#input-email', user);
  await p.click('#register-button');
  ok(await p.waitForSelector('lockbox-offer', { timeout: 8000 }).then(() => true, () => false), 'webauthn.io registration: lockbox prompt shown');
  await p.keyboard.press('Enter');
  const regMsg = await p.waitForFunction(() => /success|error|fail/i.test(document.body.innerText) && document.body.innerText, null, { timeout: 15000 }).then((h) => h.jsonValue()).catch(() => '');
  const line = (t, re) => (t.split('\n').find((l) => re.test(l)) || '').trim();
  console.log('    server said:', line(regMsg, /success|error|fail/i));
  ok(/success/i.test(line(regMsg, /success|error|fail/i)), 'webauthn.io server verified the new passkey');
  await p.waitForSelector('lockbox-offer', { state: 'detached', timeout: 5000 }).catch(() => {});

  await p.click('#login-button');
  ok(await p.waitForSelector('lockbox-offer', { timeout: 8000 }).then(() => true, () => false), 'webauthn.io sign-in: lockbox account list shown');
  await p.keyboard.press('Enter');
  const done = await p.waitForFunction(() => /logged in|error|fail/i.test(document.body.innerText) && document.body.innerText, null, { timeout: 15000 }).then((h) => h.jsonValue()).catch(() => '');
  console.log('    server said:', line(done, /logged in|error|fail/i));
  await p.screenshot({ path: '/tmp/lockbox-wio-done.png' });
  ok(/logged in/i.test(done), 'webauthn.io server verified the passkey signature: logged in');
  await ctx.close();
})().catch((e) => { console.error(e); process.exit(1); });
