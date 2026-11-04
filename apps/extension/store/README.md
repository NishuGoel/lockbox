# Chrome Web Store kit

Everything for listing the lockbox extension. Build the upload with `./scripts/package-extension.sh` (→ `dist/lockbox-extension-<version>.zip`, tests excluded, manifest `key` removed).

## Listing

**Name:** lockbox: password manager

**Summary** (≤132 chars):
Fill and save logins and passkeys from the lockbox app on your Mac, right in the login field. Nothing leaves your computer.

**Description:**

lockbox fills your logins, 2FA codes and passkeys right where you sign in, and offers to save new ones. Everything stays in the lockbox app on your Mac, end-to-end encrypted.

• Suggestions in the field: click into a login field and pick your account. Press ↓ and ↵ if you like keyboards.
• Saves as you go: sign in anywhere and lockbox offers to save the login, or to update it when you change a password. The old one is kept in history.
• Passkeys: create and use passkeys stored in lockbox, with your browser's own options one click away.
• 2FA codes: fills the current one-time code on verification pages.
• Strong passwords on sign-up forms, in one click.
• Phishing-resistant: a login only fills on the site it was saved for, never on a look-alike address, and never into an http page when it was saved for https.
• Built against clickjacking: suggestions only react to real clicks and refuse to act if a page hides or covers them.
• Private: the extension talks only to the lockbox app on your Mac. No accounts, no servers, no analytics.

Requires the lockbox app for macOS (open source: https://github.com/NishuGoel/lockbox).

**Category:** Privacy & Security (or Tools if that's not offered). **Language:** English.

**Graphics** (`images/`): icon 128×128 (`../icons/128.png`), screenshots 1280×800 (`1-suggestions.png`, `2-save.png`, `3-passkey.png`, `4-popup.png`), small promo tile 440×280 (`promo-small-440x280.png`). Regenerate with `capture.js` + `compose.py` (setup below).

## Privacy practices tab

**Single purpose:** Fill, save and generate passwords, one-time codes and passkeys from the user's lockbox password manager.

**Permission justifications:**
- **nativeMessaging:** The extension's only way to reach the lockbox app on the user's Mac, where the encrypted vault lives. All lookups, fills and saves go through it.
- **storage:** Remembers the sites the user chose "Never for this site" / "Not now" for, and holds a pending "save this login?" offer in session memory across the page load that follows signing in.
- **webNavigation:** Lists the frames in the current tab so a login is filled only into frames whose address matches the site it was saved for (never into a third-party frame).
- **activeTab:** Fills the login when the user presses the keyboard shortcut or picks an account in the toolbar popup.
- **Host permission (content scripts on http/https pages):** Needed on every site the user signs into: to show login suggestions when the user focuses a login field, to notice when the user submits a login form so lockbox can offer to save it, and to handle passkey requests. The scripts stay idle until the user focuses a login field, submits a form, or a site asks for a passkey.

**Remote code:** No. All code is in the package.

**Data usage:** tick **Authentication information** and **Personally identifiable information** (usernames/emails in saved logins) and **Website content** (login form values when the user submits them). Then tick all three certifications: not sold to third parties; not used or transferred for purposes unrelated to the single purpose; not used or transferred to determine creditworthiness or for lending.

**Privacy policy URL:** https://github.com/NishuGoel/lockbox/blob/main/PRIVACY.md

## Notes for the reviewer (Test instructions field)

This extension is the browser companion of the open-source lockbox password manager app for macOS (https://github.com/NishuGoel/lockbox). It communicates only with that app via native messaging (host `dev.lockbox.connector`); without the app installed, the popup shows "Open the lockbox app once to connect this browser" and the extension stays inactive. Build instructions are in the repository README. No account or login is required.

## Distribution

**Visibility:** Unlisted (only people with the link can install). **Regions:** all.

## After the first upload

Copy the **item ID** from the dashboard (32 letters). The lockbox app must allow it as a connector origin (`EXTENSION_IDS` in `crates/platform/src/native.rs`), otherwise the store-installed extension can't reach the app.

## Regenerating the screenshots

Demo vault in `/tmp/lbx` with the items in `capture.js`'s comments, the extension connector registered in `/tmp/lbx-chrome/NativeMessagingHosts`, and the demo site served: `cd store/demo && python3 -m http.server 8767 --bind 127.0.0.1`. Then `NODE_PATH=$(npm root -g)/@playwright/cli/node_modules node capture.js && python3 compose.py`.
