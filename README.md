# lockbox

A personal, end-to-end encrypted password manager in the spirit of 1Password. macOS desktop app + CLI + a self-hosted sync server that only ever sees ciphertext.

> ⚠️ Pre-alpha, unaudited. Don't trust it with real secrets yet.

Security design: [SPEC.md](./SPEC.md)

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
lockbox lock
```

## Layout

```
crates/core     Rust: crypto, vault model, local store, generator, TOTP
crates/cli      `lockbox` command-line client
crates/server   sync server (axum + SQLite, single binary)
apps/desktop    Tauri 2 macOS app
```

## Roadmap

- [x] **M0** Security spec (this repo's SPEC.md)
- [x] **M1** Core: create/unlock account, vault + item CRUD, password generator, TOTP, known-answer tests
- [x] **M2** CLI: `init`, `unlock`, `add`, `get`, `ls`, `gen`, `totp`, `copy`
- [ ] **M3** Desktop: unlock, ⌘K search, item detail, copy + clipboard clear, auto-lock, Touch ID, Quick Access
- [ ] **M4** Import: 1Password `.1pux`, Chrome/Safari CSV, Bitwarden JSON
- [ ] **M5** Sync server + multi-device
- [ ] **M6** Watchtower: breached (HIBP k-anonymity), weak, reused, missing 2FA
- [ ] **M7** SSH agent, `.env` secret references, share links, passkeys
