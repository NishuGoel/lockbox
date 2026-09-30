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
lockbox lock
```

## Layout

```
crates/core     Rust: crypto, vault model, local store, generator, TOTP
crates/cli      `lockbox` command-line client
crates/server   sync server (axum + SQLite, single binary)
apps/desktop    Tauri 2 macOS app (plain HTML/CSS/JS, no bundler)
crates/platform macOS Keychain, concealed clipboard, unlock-agent socket (shared by CLI + app)
```

## Roadmap

- [x] **M0** Security spec (this repo's SPEC.md)
- [x] **M1** Core: create/unlock account, vault + item CRUD, password generator, TOTP, known-answer tests
- [x] **M2** CLI: `init`, `unlock`, `add`, `get`, `ls`, `gen`, `totp`, `copy`
- [x] **M3** Desktop: unlock, ⌘K search, item detail + editor, generator, copy + clipboard clear, auto-lock (idle + screen lock), Quick Access
- [ ] **M3.1** Touch ID unlock (needs a signed build, see SPEC §6)
- [x] **M4** Import: 1Password `.1pux` (pick vaults, e.g. just Employee), Chrome/Safari/Firefox/Bitwarden CSV
- [ ] **M5** Sync server + multi-device
- [ ] **M6** Watchtower: breached (HIBP k-anonymity), weak, reused, missing 2FA
- [ ] **M7** SSH agent, `.env` secret references, share links, passkeys
