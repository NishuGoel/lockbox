# lockbox — Security Spec v0.1

Status: draft. Nothing here is audited. Changes to this file need the same care as code.

## 1. Threat model

**Protected against**

| Attacker | Gets | Must not get |
|---|---|---|
| Sync server breach (DB dump, malicious operator) | ciphertext, item counts/sizes/timestamps | any plaintext, any key, a password-crackable hash |
| Network attacker | TLS traffic | anything (TLS + everything is already E2E-encrypted) |
| Stolen laptop, app locked | local SQLite + Keychain | plaintext without master password + Secret Key |
| Leaked master password alone | password | vault (Secret Key still required) |

**Out of scope:** malware on an unlocked machine, compromised OS/kernel, keyloggers, physical coercion (Travel Mode later), side channels.

**Accepted metadata leak:** server sees number of vaults/items, blob sizes, update times, IP addresses.

## 2. Secrets the user holds

- **Master password (MP)** — chosen by user, never leaves the device.
- **Secret Key (SK)** — 128 random bits generated at signup, stored on each device (Keychain), shown once in the Emergency Kit. Format: `LB1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X` (Crockford base32 + checksum char).
- Losing both MP and SK (or the Emergency Kit) = data is unrecoverable. By design; no backdoor.

## 3. Key hierarchy

```
MP ──Argon2id(salt, params)──► k_mp ─┐
                                     ├─ XOR ──► AUK  (Account Unlock Key, 256-bit)
SK ──HKDF-SHA256(salt, "lb-auk")─► k_sk ┘

AUK ──HKDF("lb-enc")──► KEK        encrypts vault keys
AUK ──HKDF("lb-auth")─► auth_key   proves identity to the server

vault_key (random 256-bit per vault) ── encrypted with KEK
item      ── encrypted with its vault_key
```

- **Argon2id:** m = 256 MiB, t = 3, p = 4 by default; params + 16-byte random salt stored in the account header so they can be raised later.
- MP is NFKD-normalised and trimmed before hashing.
- XOR-combining means neither MP nor SK alone reduces the search space.

## 4. Encryption

- **AEAD:** XChaCha20-Poly1305, random 24-byte nonce per encryption (no counter state to get wrong).
- **AAD** binds ciphertext to its place: `"lb1" || vault_id || item_id || version`. The server can't swap, replay, or move blobs between items or vaults without detection.
- **Everything is inside the blob** — title, URL, username, password, notes, TOTP secret, tags. Plaintext search happens in memory after unlock. There are no plaintext columns except IDs and version numbers.
- Blob format: `version(1) || nonce(24) || ciphertext+tag`.

## 5. Server authentication

- Signup: client sends `email`, account header (salt, Argon2 params — not secret), and `verifier = auth_key`. Server stores `Argon2id(verifier)` only.
- Login: client re-derives `auth_key` and sends it over TLS. Server compares hashes and issues a short-lived session token.
- Because AUK includes SK, a server DB dump cannot be brute-forced offline against the master password.
- `ponytail:` direct-verifier auth, like Bitwarden's. The ceiling: a live server compromise sees auth_key at login (but it still can't decrypt anything, since KEK is a separate HKDF branch). Upgrade path: OPAQUE (RFC 9807) or SRP-6a like 1Password.

## 6. Local device

- SK is kept in the macOS Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
- **Touch ID unlock:** AUK is wrapped by a Secure Enclave key with `biometryCurrentSet` access control. Enrolling a new fingerprint invalidates it, so the user has to enter MP again.
- **Auto-lock** on idle (default 10 min), sleep, screen lock, and quit. Keys live in `zeroize`-on-drop buffers.
- **Clipboard:** copied secrets are marked `org.nspasteboard.ConcealedType` (clipboard managers skip them) and cleared after 90 s if the value is unchanged.
- The CLI unlock session is held by the desktop app over a Unix socket (`0600`, peer UID checked). The CLI never writes keys to disk.

## 7. Sync

- The server stores rows of `(item_id, vault_id, version, blob, updated_at)` and `(vault_id, encrypted_vault_key)`.
- Pushes include `expected_version`; a mismatch returns `409`, and the client pulls, merges (last-write-wins by field, loser kept in item history), and retries.
- Deletes are tombstones (version bump + empty blob) so they propagate.

## 8. Crypto rules

- Use audited crates only: `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `rand_core::OsRng`, `zeroize`. No hand-rolled primitives.
- Every primitive gets a known-answer test against published vectors.
- Constant-time comparison for verifiers (`subtle`).
- Log no secrets, ever. `Debug` on key types prints `[redacted]`.

## 9. Deferred (with reason)

- Sharing / family vaults → needs X25519 keypairs per account; add with the sharing feature.
- Passkeys → needs the macOS credential provider extension.
- Travel Mode, share links, SSH agent → after the daily loop is solid.
