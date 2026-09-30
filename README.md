# lockbox

A personal, end-to-end encrypted password manager in the spirit of 1Password. macOS desktop app + CLI + a self-hosted sync server that only ever sees ciphertext.

> ⚠️ Pre-alpha, unaudited. Don't trust it with real secrets yet.

Security design: [SPEC.md](./SPEC.md)

## Desktop app

```sh
cargo install tauri-cli --version '^2' --locked   # once
cd apps/desktop/src-tauri && cargo tauri build --bundles app
open ../../../target/release/bundle/macos/lockbox.app
```

- ⌘K search and actions · ⌘N new item · ⌘L lock · ⌘C copy password of the selected item · ↑↓ move through items
- **Quick Access:** ⌘⇧Space from anywhere. ↵ copies the password, ⌥↵ the 2FA code, ⌘C the username.
- Auto-locks after 10 idle minutes or when the Mac's screen locks. While unlocked, the app also serves the CLI, so `lockbox ls` works without a separate `lockbox unlock`.
- `LOCKBOX_DIR=/some/dir` points the app or CLI at a different lockbox (handy for trying it out).

## Browser extension (Dia, Chrome)

1. Open the lockbox app once. It connects Dia and Chrome automatically.
2. In the browser open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and pick `apps/extension`.
3. Pin the lockbox icon.

- **Saving:** log in anywhere as usual and lockbox offers **Save** / **Update password** (the old password goes to history). "Never for this site" silences a site.
- **Filling:** **⌘⇧L** fills the login for the page you're on (on a 2FA page it fills the code), or click the icon to choose.
- **Anti-phishing:** a login only fills on its own site or its subdomains, never on a lookalike, and never on an http downgrade.
- Works while lockbox is unlocked (the app or `lockbox unlock`).

## CLI

```sh
cargo install --path crates/cli     # installs `lockbox`

lockbox init                        # master password → prints your Secret Key once
lockbox add GitHub -u me@x.com --url https://github.com --totp <secret>
lockbox unlock                      # stays unlocked until 10 idle minutes
lockbox ls [query] [--vault Work]
lockbox get github                  # details, password masked
lockbox copy github                 # concealed from clipboard managers, cleared after 90s
lockbox totp github --copy
lockbox get github -f password      # raw field for scripts
lockbox edit github --generate      # rotate password
lockbox gen -l 32 --copy            # or --pin 6, --no-symbols, --easy-type
lockbox vaults add Work
lockbox import 1Password.1pux --from-vault Employee   # or a Chrome/Safari CSV
lockbox backup                      # encrypted copy (the app does this daily)
lockbox export ~/Desktop/all.csv    # plaintext, asks for your master password
lockbox restore <file.lockbox>
lockbox lock
```

## Layout

```
crates/core     Rust: crypto, vault model, local store, generator, TOTP
crates/cli      `lockbox` command-line client
crates/server   sync server (axum + SQLite, single binary)
apps/desktop    Tauri 2 macOS app (plain HTML/CSS/JS, no bundler)
crates/platform macOS Keychain, clipboard, agent socket, backups, browser connector
apps/extension  Dia/Chrome extension (Manifest V3, no build step)
```

## Roadmap

- [x] **M0** Security spec (this repo's SPEC.md)
- [x] **M1** Core: create/unlock account, vault + item CRUD, password generator, TOTP, known-answer tests
- [x] **M2** CLI: `init`, `unlock`, `add`, `get`, `ls`, `gen`, `totp`, `copy`
- [x] **M3** Desktop: unlock, ⌘K search, item detail + editor, generator, copy + clipboard clear, auto-lock (idle + screen lock), Quick Access
- [ ] **M3.1** Touch ID unlock (needs a signed build, see SPEC §6)
- [x] **M4** Import: 1Password `.1pux` (pick vaults, e.g. just Employee), Chrome/Safari/Firefox/Bitwarden CSV
- [x] **M4.5** Safety net: daily encrypted backups (iCloud Drive), restore, CSV export, monthly Emergency Kit check
- [x] **M5** Browser extension for Dia + Chrome: offers to save/update every login, fills on ⌘⇧L, 2FA codes, anti-phishing site matching, password history
- [ ] **M6** Sync server + iPhone app with AutoFill (needs Apple Developer Program)
- [ ] **M7** Watchtower: breached (HIBP k-anonymity), weak, reused, missing 2FA, one-click change via /.well-known/change-password
- [ ] **M8** Passkeys (Credential Exchange), Touch ID, SSH agent, share links
