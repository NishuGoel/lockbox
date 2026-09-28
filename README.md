# lockbox

A personal, end-to-end encrypted password manager in the spirit of 1Password. macOS desktop app + CLI + a self-hosted sync server that only ever sees ciphertext.

> ⚠️ Pre-alpha, unaudited. Don't trust it with real secrets yet.

Security design: [SPEC.md](./SPEC.md)

## Layout (planned)

```
crates/core     Rust: crypto, vault model, local store, generator, TOTP
crates/cli      `lockbox` command-line client
crates/server   sync server (axum + SQLite, single binary)
apps/desktop    Tauri 2 macOS app
```

## Roadmap

- [x] **M0** Security spec (this repo's SPEC.md)
- [x] **M1** Core: create/unlock account, vault + item CRUD, password generator, TOTP, known-answer tests
- [ ] **M2** CLI: `init`, `unlock`, `add`, `get`, `ls`, `gen`, `totp`, `copy`
- [ ] **M3** Desktop: unlock, ⌘K search, item detail, copy + clipboard clear, auto-lock, Touch ID, Quick Access
- [ ] **M4** Import: 1Password `.1pux`, Chrome/Safari CSV, Bitwarden JSON
- [ ] **M5** Sync server + multi-device
- [ ] **M6** Watchtower: breached (HIBP k-anonymity), weak, reused, missing 2FA
- [ ] **M7** SSH agent, `.env` secret references, share links, passkeys
