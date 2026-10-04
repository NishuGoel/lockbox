// Recipient-side checks against a local server (npx wrangler dev --port 8787, .dev.vars as in README).
// First create the links with the lockbox CLI into /tmp/lbsh-{one,two,short,revoke,unlimited,pass}.txt:
//   one: --with-totp · two: --views 2 · short: --expires 2s · revoke: then `lockbox shares revoke <id>` · unlimited: --unlimited --expires 1h · pass: --passphrase (blue-heron)
// Run: NODE_PATH=$(npm root -g)/@playwright/cli/node_modules node recipient.js
const { chromium } = require('playwright-core');
const fs = require('fs');
const link = (n) => fs.readFileSync('/tmp/lbsh-' + n + '.txt', 'utf8').trim();
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const meta = async (l) => (await fetch(l.replace('/s/', '/api/shares/').split('#')[0])).status;
(async () => {
  const b = await chromium.launch({ channel: 'chromium', headless: true });
  const ctx = await b.newContext({ viewport: { width: 760, height: 900 } });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  const p = await ctx.newPage();
  const visit = async (l) => { await p.goto('about:blank'); await p.goto(l); await p.waitForFunction(() => !/Checking/.test(document.querySelector('h1').textContent)); return p.textContent('h1'); };
  const reveal = async () => { await p.click('button.primary'); await p.waitForFunction(() => !!document.querySelector('.fields') || /expired|isn’t right|damaged|incomplete/.test(document.body.innerText), null, { timeout: 15000 }); };

  // 1. link preview bots only GET the page: that must not use up a one-view link
  const one = link('one');
  await fetch(one.split('#')[0]); await fetch(one.split('#')[0]);
  ok((await meta(one)) === 200, 'link previews (plain GETs) do not consume the view');
  ok((await visit(one)) === 'A login was shared with you', 'recipient sees the intro first');
  ok(await p.evaluate(() => location.hash === ''), 'key removed from the address bar/history after load');
  ok(/Opens once/.test(await p.textContent('.chips')) && /Expires in/.test(await p.textContent('.chips')), 'shows "Opens once" and the expiry');
  await reveal();
  const txt = await p.textContent('.card');
  ok(txt.includes('guest') && txt.includes('maple-orbit-42!') && txt.includes('http://router.local') && txt.includes('2nd floor, the black box'), 'decrypted in the browser: username, password, website, notes');
  await sleep(1200);
  ok(/^\d{3} \d{3}$/.test((await p.textContent('.v.code')).trim()), 'shared 2FA shows a live code');
  ok(/used up/.test(await p.textContent('.card')), 'tells the recipient the link is now used up');
  await p.screenshot({ path: '/tmp/lockbox-share-revealed.png' });
  ok((await visit(one)) === 'This link has expired', 'second visit: gone');

  // 2. two views
  const two = link('two');
  await visit(two); await reveal(); ok(/1 more time/.test(await p.textContent('.card')), 'view 1 of 2 says one more left');
  await visit(two); await reveal(); ok(!!(await p.$('.fields')), 'view 2 of 2 works');
  ok((await visit(two)) === 'This link has expired', 'third view: gone');

  // 3. expiry, revoke, unlimited
  await sleep(2500);
  ok((await visit(link('short'))) === 'This link has expired', 'expired after its 2 seconds');
  ok((await visit(link('revoke'))) === 'This link has expired', 'revoked link is gone');
  const unl = link('unlimited');
  for (let i = 0; i < 3; i++) { await visit(unl); await reveal(); }
  ok(/keeps working/.test(await p.textContent('.card')), 'unlimited link opens repeatedly until expiry');

  // 4. damaged link is caught before it can use up a view
  const pass = link('pass');
  const [base, key] = pass.split('#');
  await visit(base + '#' + key.slice(0, -4) + 'AAAA'); 
  await p.fill('#pp', 'blue-heron'); await reveal();
  ok(/isn’t right|damaged/.test(await p.textContent('.card')) && (await meta(pass)) === 200, 'damaged key: error, view NOT used');

  // 5. passphrase: wrong one doesn't burn the link; right one opens it
  await visit(pass);
  ok(!!(await p.$('#pp')), 'asks for the passphrase');
  await p.fill('#pp', 'blue-herring'); await reveal();
  ok(/isn’t right/.test(await p.textContent('.card')) && (await meta(pass)) === 200, 'wrong passphrase: error, view NOT used');
  await p.fill('#pp', 'blue-heron'); await reveal();
  ok((await p.textContent('.card')).includes('maple-orbit-42!'), 'right passphrase decrypts');
  ok((await meta(pass)) === 404, 'and the one view is now used');

  // 6. no key at all
  await visit(base);
  ok((await p.textContent('h1')) === 'This link is incomplete', 'link without its key explains what is missing');
  await b.close();
})().catch((e) => { console.error(e); process.exit(1); });
