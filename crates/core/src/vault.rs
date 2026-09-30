//! Local encrypted store. Only ids and version numbers are plaintext; see SPEC.md §4.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Key, SecretKey};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Login,
    SecureNote,
    Card,
    Identity,
    ApiCredential,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub concealed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Item {
    pub kind: Kind,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    /// `otpauth://` URI or bare base32 secret
    pub totp: Option<String>,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
    pub favorite: bool,
    pub created_at: u64,
    pub updated_at: u64,
    /// Older passwords, newest first. Filled in by `update_item`.
    pub password_history: Vec<PasswordChange>,
    pub passkey: Option<Passkey>,
}

/// A WebAuthn credential (ES256). Created and used only inside lockbox; the key never reaches a web page.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Passkey {
    pub rp_id: String,
    /// base64url
    pub credential_id: String,
    /// base64url, the site's user id
    pub user_handle: String,
    pub user_name: String,
    pub user_display_name: String,
    /// P-256 private scalar, base64url
    pub private_key: String,
    pub created_at: u64,
}

impl std::fmt::Debug for Passkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkey").field("rp_id", &self.rp_id).field("user_name", &self.user_name).field("private_key", &"[redacted]").finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PasswordChange {
    pub password: String,
    /// when it stopped being the current password
    pub replaced_at: u64,
}

const HISTORY_MAX: usize = 20;

fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?.trim_end_matches('.').to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    (!host.is_empty()).then_some(host)
}

fn scheme_of(url: &str) -> &str {
    url.trim().split_once("://").map_or("https", |(s, _)| s)
}

/// Anti-phishing rule for autofill: the page's host must equal the saved host or be a subdomain
/// of it (saved `github.com` fills on `gist.github.com`, never on `github.com.evil.io`), and an
/// https login is never filled into an http page.
// ponytail: host/subdomain rule, no public-suffix list. Ceiling: a login saved for a bare public
// suffix (e.g. "github.io") would match every site under it; add the PSL if that ever matters.
pub fn site_matches(saved_url: &str, page_url: &str) -> bool {
    let (Some(saved), Some(page)) = (host_of(saved_url), host_of(page_url)) else { return false };
    if !saved.contains('.') && saved != "localhost" {
        return false;
    }
    let downgrade = scheme_of(page_url).eq_ignore_ascii_case("http") && !scheme_of(saved_url).eq_ignore_ascii_case("http");
    !downgrade && (page == saved || page.ends_with(&format!(".{saved}")))
}

/// The host shown to people and used as a new item's title.
pub fn display_host(url: &str) -> Option<String> {
    host_of(url)
}

impl Item {
    /// password, username, url (first), notes, title, or a custom field by name.
    pub fn field(&self, name: &str) -> Option<String> {
        match name.to_lowercase().as_str() {
            "password" => self.password.clone(),
            "username" => self.username.clone(),
            "url" => self.urls.first().cloned(),
            "notes" => self.notes.clone(),
            "title" => Some(self.title.clone()),
            n => self.fields.iter().find(|f| f.name.eq_ignore_ascii_case(n)).map(|f| f.value.clone()),
        }
    }

    /// Case-insensitive substring match on title, username, urls and tags.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        let hit = |s: &str| s.to_lowercase().contains(&q);
        hit(&self.title)
            || self.username.as_deref().is_some_and(hit)
            || self.urls.iter().any(|u| hit(u))
            || self.tags.iter().any(|t| hit(t))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ItemRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub version: u64,
    pub item: Item,
    /// set while the item sits in Recently deleted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
}

/// Items stay in Recently deleted this long before their data is wiped.
pub const TRASH_DAYS: u64 = 30;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub added: usize,
    pub duplicates: usize,
    pub vaults_created: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    format: u8,
    salt: [u8; 16],
    kdf: KdfParams,
    canary: Vec<u8>,
}

const CANARY_AAD: &[u8] = b"lb1-canary";

fn vault_key_aad(vault: &Uuid) -> Vec<u8> {
    [b"lb1-vk".as_slice(), vault.as_bytes()].concat()
}

fn vault_meta_aad(vault: &Uuid) -> Vec<u8> {
    [b"lb1-vm".as_slice(), vault.as_bytes()].concat()
}

fn item_aad(vault: &Uuid, item: &Uuid, version: u64) -> Vec<u8> {
    [b"lb1".as_slice(), vault.as_bytes(), item.as_bytes(), &version.to_le_bytes()].concat()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn uuid(s: String) -> Uuid {
    Uuid::parse_str(&s).expect("ids are written by us")
}

/// An unlocked lockbox. Dropping it zeroizes the key.
pub struct Lockbox {
    db: Connection,
    kek: Key,
}

impl std::fmt::Debug for Lockbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Lockbox([unlocked])")
    }
}

fn open_db(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS vaults (id TEXT PRIMARY KEY, key_blob BLOB NOT NULL, meta_blob BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS items (
           id TEXT PRIMARY KEY, vault_id TEXT NOT NULL REFERENCES vaults(id),
           version INTEGER NOT NULL, blob BLOB -- NULL = tombstone (kept for sync)
         );",
    )?;
    // v2: Recently deleted
    let has_deleted: i64 = db.query_row("SELECT COUNT(*) FROM pragma_table_info('items') WHERE name='deleted_at'", [], |r| r.get(0))?;
    if has_deleted == 0 {
        db.execute_batch("ALTER TABLE items ADD COLUMN deleted_at INTEGER")?;
    }
    Ok(db)
}

fn read_header(db: &Connection) -> Result<Option<Header>> {
    let raw: Option<Vec<u8>> = db.query_row("SELECT v FROM meta WHERE k='header'", [], |r| r.get(0)).optional()?;
    Ok(raw.map(|r| serde_json::from_slice(&r)).transpose()?)
}

/// Consistent snapshot of a lockbox file (`VACUUM INTO`). Needs no keys: the copy is exactly as
/// encrypted as the original and opens with the same master password + Secret Key.
pub fn backup_file(db: &Path, dest: &Path) -> Result<()> {
    if !db.exists() {
        return Err(Error::NotInitialized);
    }
    if dest.exists() {
        return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "backup file already exists")));
    }
    let conn = Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.execute("VACUUM INTO ?1", [dest.to_string_lossy()])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn otpauth(title: &str, totp: &str) -> String {
    if totp.starts_with("otpauth://") {
        return totp.to_string();
    }
    let label: String = title.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    format!("otpauth://totp/{label}?secret={}", totp.replace(' ', "").to_uppercase())
}

impl Lockbox {
    /// Plaintext CSV in the Safari/Passwords layout (Title,URL,Username,Password,Notes,OTPAuth), which
    /// Apple Passwords, Chrome, Bitwarden, 1Password and lockbox itself can import. Custom fields are
    /// appended to the notes so nothing is dropped.
    pub fn export_csv(&self) -> Result<Zeroizing<String>> {
        let mut w = csv::Writer::from_writer(Vec::new());
        let io = |e: csv::Error| Error::Io(std::io::Error::other(e));
        w.write_record(["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]).map_err(io)?;
        let mut items = self.items(None)?;
        items.sort_by_key(|r| r.item.title.to_lowercase());
        for r in items {
            let i = &r.item;
            let mut notes = i.notes.clone().unwrap_or_default();
            for f in &i.fields {
                notes.push_str(&format!("{}{}: {}", if notes.is_empty() { "" } else { "\n" }, f.name, f.value));
            }
            let otp = i.totp.as_deref().map(|t| otpauth(&i.title, t)).unwrap_or_default();
            w.write_record([&i.title, i.urls.first().unwrap_or(&String::new()), i.username.as_deref().unwrap_or(""), i.password.as_deref().unwrap_or(""), &notes, &otp])
                .map_err(io)?;
        }
        let bytes = Zeroizing::new(w.into_inner().map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?);
        Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Creates a new lockbox with a "Personal" vault. Show the returned Secret Key to the user once.
    pub fn create(path: &Path, password: &str, kdf: KdfParams) -> Result<(Self, SecretKey)> {
        let db = open_db(path)?;
        if read_header(&db)?.is_some() {
            return Err(Error::AlreadyInitialized);
        }
        let sk = SecretKey::generate();
        let salt = crypto::random_bytes();
        let kek = crypto::kek(&crypto::derive_auk(password, &sk, &salt, kdf)?);
        let header = Header { format: 1, salt, kdf, canary: crypto::seal(&kek, b"lockbox", CANARY_AAD) };
        db.execute("INSERT INTO meta (k, v) VALUES ('header', ?1)", [serde_json::to_vec(&header)?])?;
        let lb = Self { db, kek };
        lb.create_vault("Personal")?;
        Ok((lb, sk))
    }

    pub fn unlock(path: &Path, password: &str, sk: &SecretKey) -> Result<Self> {
        if !path.exists() {
            return Err(Error::NotInitialized);
        }
        let db = open_db(path)?;
        let h = read_header(&db)?.ok_or(Error::NotInitialized)?;
        let kek = crypto::kek(&crypto::derive_auk(password, sk, &h.salt, h.kdf)?);
        crypto::open(&kek, &h.canary, CANARY_AAD).map_err(|_| Error::WrongCredentials)?;
        let lb = Self { db, kek };
        let _ = lb.purge_expired();
        Ok(lb)
    }

    fn vault_key(&self, vault: &Uuid) -> Result<Key> {
        let blob: Vec<u8> = self
            .db
            .query_row("SELECT key_blob FROM vaults WHERE id=?1", [vault.to_string()], |r| r.get(0))
            .optional()?
            .ok_or(Error::NotFound)?;
        let raw = crypto::open(&self.kek, &blob, &vault_key_aad(vault))?;
        Ok(Zeroizing::new(raw[..].try_into().map_err(|_| Error::Decrypt)?))
    }

    pub fn create_vault(&self, name: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let vk = crypto::random_key();
        self.db.execute(
            "INSERT INTO vaults (id, key_blob, meta_blob) VALUES (?1, ?2, ?3)",
            params![
                id.to_string(),
                crypto::seal(&self.kek, &vk[..], &vault_key_aad(&id)),
                crypto::seal(&vk, name.as_bytes(), &vault_meta_aad(&id)),
            ],
        )?;
        Ok(id)
    }

    pub fn vaults(&self) -> Result<Vec<Vault>> {
        let mut stmt = self.db.prepare("SELECT id, meta_blob FROM vaults")?;
        let rows = stmt.query_map([], |r| Ok((uuid(r.get(0)?), r.get::<_, Vec<u8>>(1)?)))?;
        rows.map(|row| {
            let (id, blob) = row?;
            let name = crypto::open(&self.vault_key(&id)?, &blob, &vault_meta_aad(&id))?;
            Ok(Vault { id, name: String::from_utf8_lossy(&name).into_owned() })
        })
        .collect()
    }

    fn write_item(&self, id: &Uuid, vault: &Uuid, version: u64, item: &Item) -> Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(item)?);
        let blob = crypto::seal(&self.vault_key(vault)?, &json, &item_aad(vault, id, version));
        self.db.execute(
            "INSERT INTO items (id, vault_id, version, blob) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET vault_id=?2, version=?3, blob=?4",
            params![id.to_string(), vault.to_string(), version as i64, blob],
        )?;
        Ok(())
    }

    pub fn add_item(&self, vault: &Uuid, mut item: Item) -> Result<Uuid> {
        self.vault_key(vault)?; // fail fast on unknown vault
        let id = Uuid::new_v4();
        item.created_at = now();
        item.updated_at = item.created_at;
        self.write_item(&id, vault, 1, &item)?;
        Ok(id)
    }

    // ponytail: no per-item history yet; add with sync (M5), where it's needed for conflict losers.
    pub fn update_item(&self, id: &Uuid, mut item: Item) -> Result<()> {
        let cur = self.get_item(id)?;
        item.created_at = cur.item.created_at;
        item.updated_at = now();
        // history is owned by the store: callers can't rewrite or drop it
        item.password_history = cur.item.password_history;
        if let Some(old) = cur.item.password.filter(|old| item.password.as_ref() != Some(old)) {
            item.password_history.insert(0, PasswordChange { password: old, replaced_at: item.updated_at });
            item.password_history.truncate(HISTORY_MAX);
        }
        self.write_item(id, &cur.vault_id, cur.version + 1, &item)
    }

    /// Moves an item to Recently deleted. It stays restorable for `TRASH_DAYS`.
    pub fn delete_item(&self, id: &Uuid) -> Result<()> {
        let n = self.db.execute(
            "UPDATE items SET deleted_at=?2 WHERE id=?1 AND blob IS NOT NULL AND deleted_at IS NULL",
            params![id.to_string(), now() as i64],
        )?;
        if n == 0 { Err(Error::NotFound) } else { Ok(()) }
    }

    pub fn restore_item(&self, id: &Uuid) -> Result<()> {
        let n = self.db.execute("UPDATE items SET deleted_at=NULL WHERE id=?1 AND blob IS NOT NULL AND deleted_at IS NOT NULL", [id.to_string()])?;
        if n == 0 { Err(Error::NotFound) } else { Ok(()) }
    }

    /// Wipes an item's data for good, leaving a tombstone so the deletion can sync later.
    pub fn purge_item(&self, id: &Uuid) -> Result<()> {
        let n = self.db.execute("UPDATE items SET blob=NULL, version=version+1 WHERE id=?1 AND blob IS NOT NULL AND deleted_at IS NOT NULL", [id.to_string()])?;
        if n == 0 { Err(Error::NotFound) } else { Ok(()) }
    }

    /// Wipes items that have been in Recently deleted longer than `TRASH_DAYS`. Returns how many.
    pub fn purge_expired(&self) -> Result<usize> {
        let cutoff = now().saturating_sub(TRASH_DAYS * 86_400) as i64;
        Ok(self.db.execute("UPDATE items SET blob=NULL, version=version+1 WHERE blob IS NOT NULL AND deleted_at IS NOT NULL AND deleted_at < ?1", [cutoff])?)
    }

    /// What's in Recently deleted, newest first.
    pub fn trash(&self) -> Result<Vec<ItemRecord>> {
        let mut stmt = self.db.prepare("SELECT id, vault_id, version, blob, deleted_at FROM items WHERE blob IS NOT NULL AND deleted_at IS NOT NULL ORDER BY deleted_at DESC")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)?)))?;
        rows.map(|row| {
            let (a, b, c, d, del) = row?;
            let mut rec = self.decode(a, b, c, d)?;
            rec.deleted_at = Some(del as u64);
            Ok(rec)
        })
        .collect()
    }

    /// Makes an older password current again; the replaced one goes into history.
    pub fn restore_old_password(&self, id: &Uuid, index: usize) -> Result<()> {
        let cur = self.get_item(id)?;
        let mut item = cur.item;
        if index >= item.password_history.len() {
            return Err(Error::NotFound);
        }
        let old = item.password_history.remove(index);
        if let Some(p) = item.password.replace(old.password) {
            item.password_history.insert(0, PasswordChange { password: p, replaced_at: now() });
        }
        item.updated_at = now();
        self.write_item(id, &cur.vault_id, cur.version + 1, &item)
    }

    pub fn rename_vault(&self, id: &Uuid, name: &str) -> Result<()> {
        let vk = self.vault_key(id)?;
        self.db.execute("UPDATE vaults SET meta_blob=?2 WHERE id=?1", params![id.to_string(), crypto::seal(&vk, name.as_bytes(), &vault_meta_aad(id))])?;
        Ok(())
    }

    /// Only empty vaults can go (nothing live or in Recently deleted), and never the last one.
    pub fn delete_vault(&self, id: &Uuid) -> Result<()> {
        self.vault_key(id)?;
        let used: i64 = self.db.query_row("SELECT COUNT(*) FROM items WHERE vault_id=?1 AND blob IS NOT NULL", [id.to_string()], |r| r.get(0))?;
        let vaults: i64 = self.db.query_row("SELECT COUNT(*) FROM vaults", [], |r| r.get(0))?;
        if used > 0 || vaults <= 1 {
            return Err(Error::VaultNotEmpty);
        }
        self.db.execute("DELETE FROM items WHERE vault_id=?1", [id.to_string()])?;
        self.db.execute("DELETE FROM vaults WHERE id=?1", [id.to_string()])?;
        Ok(())
    }

    /// Re-encrypts an item under another vault's key.
    pub fn move_item(&self, id: &Uuid, to: &Uuid) -> Result<()> {
        let cur = self.get_item(id)?;
        if &cur.vault_id == to {
            return Ok(());
        }
        self.vault_key(to)?;
        self.write_item(id, to, cur.version + 1, &cur.item)
    }

    /// New master password (and key-derivation strength). Only the vault keys and the header are
    /// re-wrapped, in one transaction; item data is untouched. The Secret Key stays the same.
    pub fn change_password(&mut self, current: &str, sk: &SecretKey, new_password: &str, kdf: KdfParams) -> Result<()> {
        let h = read_header(&self.db)?.ok_or(Error::NotInitialized)?;
        let old_kek = crypto::kek(&crypto::derive_auk(current, sk, &h.salt, h.kdf)?);
        crypto::open(&old_kek, &h.canary, CANARY_AAD).map_err(|_| Error::WrongCredentials)?;
        let salt = crypto::random_bytes();
        let new_kek = crypto::kek(&crypto::derive_auk(new_password, sk, &salt, kdf)?);
        let wrapped: Vec<(String, Vec<u8>)> = {
            let mut stmt = self.db.prepare("SELECT id, key_blob FROM vaults")?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let tx = self.db.unchecked_transaction()?;
        for (id, blob) in wrapped {
            let aad = vault_key_aad(&uuid(id.clone()));
            let raw = crypto::open(&old_kek, &blob, &aad)?;
            tx.execute("UPDATE vaults SET key_blob=?2 WHERE id=?1", params![id, crypto::seal(&new_kek, &raw, &aad)])?;
        }
        let header = Header { format: 1, salt, kdf, canary: crypto::seal(&new_kek, b"lockbox", CANARY_AAD) };
        tx.execute("UPDATE meta SET v=?1 WHERE k='header'", [serde_json::to_vec(&header)?])?;
        tx.commit()?;
        self.kek = new_kek;
        Ok(())
    }

    pub fn kdf_params(&self) -> Result<KdfParams> {
        Ok(read_header(&self.db)?.ok_or(Error::NotInitialized)?.kdf)
    }

    fn decode(&self, id: String, vault: String, version: i64, blob: Vec<u8>) -> Result<ItemRecord> {
        let (id, vault_id, version) = (uuid(id), uuid(vault), version as u64);
        let json = crypto::open(&self.vault_key(&vault_id)?, &blob, &item_aad(&vault_id, &id, version))?;
        Ok(ItemRecord { id, vault_id, version, item: serde_json::from_slice(&json)?, deleted_at: None })
    }

    pub fn get_item(&self, id: &Uuid) -> Result<ItemRecord> {
        let row = self
            .db
            .query_row(
                "SELECT id, vault_id, version, blob FROM items WHERE id=?1 AND blob IS NOT NULL AND deleted_at IS NULL",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        self.decode(row.0, row.1, row.2, row.3)
    }

    /// All live items, optionally limited to one vault.
    pub fn items(&self, vault: Option<&Uuid>) -> Result<Vec<ItemRecord>> {
        let mut stmt = self.db.prepare(
            "SELECT id, vault_id, version, blob FROM items WHERE blob IS NOT NULL AND deleted_at IS NULL AND (?1 IS NULL OR vault_id=?1)",
        )?;
        let rows = stmt.query_map([vault.map(|v| v.to_string())], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.map(|row| {
            let (a, b, c, d) = row?;
            self.decode(a, b, c, d)
        })
        .collect()
    }

    /// Adds imported items. `target` puts everything in one vault; otherwise each item goes to the
    /// vault named like its source vault (created if missing), falling back to the first vault.
    /// Exact duplicates (title, username, first url, password) of existing or earlier items are skipped,
    /// so importing the same file twice is harmless.
    pub fn import(&self, items: Vec<crate::import::Imported>, target: Option<&Uuid>) -> Result<ImportSummary> {
        type Key = (String, Option<String>, Option<String>, Option<String>);
        let key = |i: &Item| -> Key { (i.title.to_lowercase(), i.username.clone(), i.urls.first().cloned(), i.password.clone()) };
        let mut seen: std::collections::HashSet<Key> = self.items(None)?.iter().map(|r| key(&r.item)).collect();
        let mut vaults = self.vaults()?;
        let fallback = vaults.first().ok_or(Error::NotFound)?.id;
        let mut sum = ImportSummary::default();
        for imp in items {
            if !seen.insert(key(&imp.item)) {
                sum.duplicates += 1;
                continue;
            }
            let vault = match (target, &imp.vault) {
                (Some(t), _) => *t,
                (None, None) => fallback,
                (None, Some(name)) => match vaults.iter().find(|v| v.name.eq_ignore_ascii_case(name)) {
                    Some(v) => v.id,
                    None => {
                        let id = self.create_vault(name)?;
                        vaults.push(Vault { id, name: name.clone() });
                        sum.vaults_created.push(name.clone());
                        id
                    }
                },
            };
            let (created, updated) = (imp.item.created_at, imp.item.updated_at);
            let id = self.add_item(&vault, imp.item)?;
            if created > 0 {
                // keep the source's timestamps when it has them
                let mut rec = self.get_item(&id)?;
                (rec.item.created_at, rec.item.updated_at) = (created, updated.max(created));
                self.write_item(&id, &vault, rec.version, &rec.item)?;
            }
            sum.added += 1;
        }
        Ok(sum)
    }

    // ponytail: linear scan over decrypted items; fine to ~10k items, add an in-memory index if search lags.
    pub fn search(&self, query: &str) -> Result<Vec<ItemRecord>> {
        Ok(self.items(None)?.into_iter().filter(|r| r.item.matches(query)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("lockbox-test-{}.db", Uuid::new_v4()))
    }

    fn login(title: &str) -> Item {
        Item { title: title.into(), username: Some("me@example.com".into()), password: Some("hunter2".into()), urls: vec!["https://github.com".into()], ..Default::default() }
    }

    #[test]
    fn create_unlock_and_wrong_credentials() {
        let p = tmp();
        let (lb, sk) = Lockbox::create(&p, "correct horse", FAST).unwrap();
        let vault = lb.vaults().unwrap()[0].clone();
        assert_eq!(vault.name, "Personal");
        let id = lb.add_item(&vault.id, login("GitHub")).unwrap();
        drop(lb);

        assert!(matches!(Lockbox::unlock(&p, "wrong", &sk), Err(Error::WrongCredentials)));
        assert!(matches!(Lockbox::unlock(&p, "correct horse", &SecretKey::generate()), Err(Error::WrongCredentials)));
        assert!(matches!(Lockbox::create(&p, "x", FAST), Err(Error::AlreadyInitialized)));

        let sk = SecretKey::parse(&sk.to_display()).unwrap();
        let lb = Lockbox::unlock(&p, "correct horse", &sk).unwrap();
        assert_eq!(lb.get_item(&id).unwrap().item.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn crud_and_search() {
        let (lb, _) = Lockbox::create(&tmp(), "pw", FAST).unwrap();
        let personal = lb.vaults().unwrap()[0].id;
        let work = lb.create_vault("Work").unwrap();
        let gh = lb.add_item(&personal, login("GitHub")).unwrap();
        lb.add_item(&work, Item { title: "AWS".into(), tags: vec!["infra".into()], ..Default::default() }).unwrap();

        assert_eq!(lb.items(None).unwrap().len(), 2);
        assert_eq!(lb.items(Some(&work)).unwrap()[0].item.title, "AWS");
        assert_eq!(lb.search("github").unwrap()[0].id, gh);
        assert_eq!(lb.search("INFRA").unwrap()[0].item.title, "AWS");

        let before = lb.get_item(&gh).unwrap();
        lb.update_item(&gh, Item { password: Some("n3w".into()), ..before.item.clone() }).unwrap();
        let after = lb.get_item(&gh).unwrap();
        assert_eq!((after.version, after.item.password.as_deref()), (2, Some("n3w")));
        assert_eq!(after.item.created_at, before.item.created_at);

        lb.delete_item(&gh).unwrap();
        assert!(matches!(lb.get_item(&gh), Err(Error::NotFound)));
        assert!(matches!(lb.delete_item(&gh), Err(Error::NotFound)));
        assert_eq!(lb.items(None).unwrap().len(), 1);
        assert_eq!(lb.trash().unwrap()[0].item.title, "GitHub");
        lb.restore_item(&gh).unwrap();
        assert_eq!(lb.items(None).unwrap().len(), 2);
        lb.delete_item(&gh).unwrap();
        lb.purge_item(&gh).unwrap();
        assert!(lb.trash().unwrap().is_empty() && matches!(lb.restore_item(&gh), Err(Error::NotFound)));
    }

    #[test]
    fn import_routes_vaults_and_skips_duplicates() {
        use crate::import::Imported;
        let (lb, _) = Lockbox::create(&tmp(), "pw", FAST).unwrap();
        let personal = lb.vaults().unwrap()[0].id;
        let batch = || vec![
            Imported { vault: Some("Employee".into()), item: login("Jira") },
            Imported { vault: None, item: login("GitHub") },
            Imported { vault: Some("personal".into()), item: Item { title: "Bank".into(), ..Default::default() } },
        ];
        let s = lb.import(batch(), None).unwrap();
        assert_eq!((s.added, s.duplicates, s.vaults_created.clone()), (3, 0, vec!["Employee".to_string()]));
        let employee = lb.vaults().unwrap().into_iter().find(|v| v.name == "Employee").unwrap().id;
        assert_eq!(lb.items(Some(&employee)).unwrap()[0].item.title, "Jira");
        assert_eq!(lb.items(Some(&personal)).unwrap().len(), 2, "unnamed + case-insensitive match go to Personal");

        let again = lb.import(batch(), None).unwrap();
        assert_eq!((again.added, again.duplicates), (0, 3));
        assert_eq!(lb.items(None).unwrap().len(), 3);

        let into = lb.import(vec![Imported { vault: Some("Employee".into()), item: login("Figma") }], Some(&personal)).unwrap();
        assert_eq!(into.added, 1);
        assert_eq!(lb.search("figma").unwrap()[0].vault_id, personal, "explicit target wins");
    }

    #[test]
    fn backup_opens_with_same_credentials_and_export_round_trips() {
        let p = tmp();
        let (lb, sk) = Lockbox::create(&p, "pw", FAST).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        let mut gh = login("GitHub");
        gh.totp = Some("gezd gnbv gy3t qojq".into());
        gh.notes = Some("line one, with \"quotes\"".into());
        gh.fields.push(Field { name: "Recovery".into(), value: "abc-123".into(), concealed: true });
        lb.add_item(&v, gh).unwrap();
        lb.add_item(&v, Item { title: "Wi-Fi".into(), password: Some("maple-orbit".into()), ..Default::default() }).unwrap();

        let dest = p.with_extension("backup");
        backup_file(&p, &dest).unwrap();
        assert!(backup_file(&p, &dest).is_err(), "never overwrites an existing backup");
        let restored = Lockbox::unlock(&dest, "pw", &sk).unwrap();
        assert_eq!(restored.items(None).unwrap().len(), 2);
        assert!(matches!(Lockbox::unlock(&dest, "wrong", &sk), Err(Error::WrongCredentials)));

        let csv = lb.export_csv().unwrap();
        assert!(csv.starts_with("Title,URL,Username,Password,Notes,OTPAuth"));
        let back = crate::import::parse_csv(csv.as_bytes()).unwrap().items;
        let g = &back.iter().find(|i| i.item.title == "GitHub").unwrap().item;
        assert_eq!((g.username.as_deref(), g.password.as_deref()), (Some("me@example.com"), Some("hunter2")));
        assert_eq!(g.notes.as_deref(), Some("line one, with \"quotes\"\nRecovery: abc-123"));
        assert_eq!(g.totp.as_deref(), Some("otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQ"));
        crate::totp::parse(g.totp.as_deref().unwrap()).unwrap();
        assert!(back.iter().any(|i| i.item.title == "Wi-Fi" && i.item.password.as_deref() == Some("maple-orbit")));
    }

    #[test]
    fn site_matching_blocks_lookalikes() {
        let ok = [
            ("https://github.com/login", "https://github.com/session"),
            ("github.com", "https://gist.github.com/"),
            ("https://www.github.com", "https://github.com"),
            ("https://accounts.google.com/signin", "https://ACCOUNTS.google.com./x"),
            ("http://router.local", "http://router.local:8080/"),
            ("http://localhost:3000", "http://localhost:5173"),
        ];
        for (saved, page) in ok {
            assert!(site_matches(saved, page), "{saved} should fill on {page}");
        }
        let bad = [
            ("https://github.com", "https://github.com.evil.io/login"),
            ("https://github.com", "https://evilgithub.com"),
            ("https://github.com", "http://github.com"),
            ("https://gist.github.com", "https://github.com"),
            ("https://github.com", "https://user@evil.io/github.com"),
            ("https://bank.example", "https://bank.example@evil.io/"),
            ("com", "https://anything.com"),
            ("", "https://github.com"),
        ];
        for (saved, page) in bad {
            assert!(!site_matches(saved, page), "{saved} must NOT fill on {page}");
        }
    }

    #[test]
    fn password_history_records_changes_only() {
        let (lb, _) = Lockbox::create(&tmp(), "pw", FAST).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        let id = lb.add_item(&v, login("GitHub")).unwrap();
        let mut it = lb.get_item(&id).unwrap().item;
        it.notes = Some("same password".into());
        lb.update_item(&id, it).unwrap();
        assert!(lb.get_item(&id).unwrap().item.password_history.is_empty());
        let mut it = lb.get_item(&id).unwrap().item;
        it.password = Some("second".into());
        lb.update_item(&id, it).unwrap();
        lb.update_item(&id, Item { title: "GitHub".into(), password: Some("second".into()), ..Default::default() }).unwrap();
        assert_eq!(lb.get_item(&id).unwrap().item.password_history.len(), 1, "a caller omitting history can't erase it");
        for n in 0..25 {
            let mut it = lb.get_item(&id).unwrap().item;
            it.password = Some(format!("pw{n}"));
            lb.update_item(&id, it).unwrap();
        }
        let h = lb.get_item(&id).unwrap().item.password_history;
        assert_eq!(h.len(), 20);
        assert_eq!((h[0].password.as_str(), h[19].password.as_str()), ("pw23", "pw4"));
    }

    #[test]
    fn upgrades_a_vault_made_before_recently_deleted() {
        let p = tmp();
        let (lb, sk) = Lockbox::create(&p, "pw", FAST).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        lb.add_item(&v, login("GitHub")).unwrap();
        lb.db.execute_batch("ALTER TABLE items DROP COLUMN deleted_at").unwrap();
        drop(lb);
        let lb = Lockbox::unlock(&p, "pw", &sk).unwrap();
        assert_eq!(lb.items(None).unwrap().len(), 1);
        let id = lb.items(None).unwrap()[0].id;
        lb.delete_item(&id).unwrap();
        assert_eq!(lb.trash().unwrap().len(), 1);
    }

    #[test]
    fn trash_expires_after_30_days() {
        let (lb, _) = Lockbox::create(&tmp(), "pw", FAST).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        let old = lb.add_item(&v, login("Old")).unwrap();
        let recent = lb.add_item(&v, login("Recent")).unwrap();
        lb.delete_item(&old).unwrap();
        lb.delete_item(&recent).unwrap();
        lb.db.execute("UPDATE items SET deleted_at=?2 WHERE id=?1", params![old.to_string(), (now() - 31 * 86_400) as i64]).unwrap();
        assert_eq!(lb.purge_expired().unwrap(), 1);
        let left: Vec<String> = lb.trash().unwrap().into_iter().map(|r| r.item.title).collect();
        assert_eq!(left, vec!["Recent"]);
        let blob: Option<Vec<u8>> = lb.db.query_row("SELECT blob FROM items WHERE id=?1", [old.to_string()], |r| r.get(0)).unwrap();
        assert!(blob.is_none(), "expired data is really gone");
    }

    #[test]
    fn change_password_rewraps_keys_only() {
        let p = tmp();
        let (mut lb, sk) = Lockbox::create(&p, "old password", FAST).unwrap();
        let work = lb.create_vault("Work").unwrap();
        lb.add_item(&work, login("GitHub")).unwrap();
        assert!(matches!(lb.change_password("wrong", &sk, "new password", FAST), Err(Error::WrongCredentials)));
        let stronger = KdfParams { m_kib: 128, t: 2, p: 1 };
        lb.change_password("old password", &sk, "new password", stronger).unwrap();
        assert_eq!(lb.items(None).unwrap()[0].item.title, "GitHub", "same session keeps working");
        assert_eq!(lb.kdf_params().unwrap(), stronger);
        drop(lb);
        assert!(matches!(Lockbox::unlock(&p, "old password", &sk), Err(Error::WrongCredentials)));
        let lb = Lockbox::unlock(&p, "new password", &sk).unwrap();
        assert_eq!(lb.items(Some(&work)).unwrap()[0].item.password.as_deref(), Some("hunter2"));
        assert_eq!(lb.vaults().unwrap().len(), 2);
    }

    #[test]
    fn vaults_rename_move_delete() {
        let (lb, _) = Lockbox::create(&tmp(), "pw", FAST).unwrap();
        let personal = lb.vaults().unwrap()[0].id;
        let work = lb.create_vault("Wrok").unwrap();
        lb.rename_vault(&work, "Work").unwrap();
        assert!(lb.vaults().unwrap().iter().any(|v| v.name == "Work"));
        let id = lb.add_item(&work, login("Jira")).unwrap();
        assert!(matches!(lb.delete_vault(&work), Err(Error::VaultNotEmpty)));
        lb.move_item(&id, &personal).unwrap();
        let moved = lb.get_item(&id).unwrap();
        assert_eq!((moved.vault_id, moved.item.password.as_deref()), (personal, Some("hunter2")));
        lb.delete_vault(&work).unwrap();
        assert_eq!(lb.vaults().unwrap().len(), 1);
        assert!(matches!(lb.delete_vault(&personal), Err(Error::VaultNotEmpty)), "never the last vault");
    }

    #[test]
    fn restore_an_old_password() {
        let (lb, _) = Lockbox::create(&tmp(), "pw", FAST).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        let id = lb.add_item(&v, login("GitHub")).unwrap();
        let mut it = lb.get_item(&id).unwrap().item;
        it.password = Some("new-one".into());
        lb.update_item(&id, it).unwrap();
        lb.restore_old_password(&id, 0).unwrap();
        let it = lb.get_item(&id).unwrap().item;
        assert_eq!(it.password.as_deref(), Some("hunter2"));
        assert_eq!(it.password_history.iter().map(|c| c.password.as_str()).collect::<Vec<_>>(), vec!["new-one"]);
    }

    #[test]
    fn nothing_readable_on_disk_and_blobs_cant_be_swapped() {
        let p = tmp();
        let (lb, _) = Lockbox::create(&p, "pw", FAST).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        let a = lb.add_item(&v, login("GitHub")).unwrap();
        let b = lb.add_item(&v, Item { title: "Bank".into(), password: Some("s3cret".into()), ..Default::default() }).unwrap();
        lb.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();

        let raw = std::fs::read(&p).unwrap();
        for needle in ["GitHub", "hunter2", "Bank", "s3cret", "Personal", "github.com"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle.as_bytes()), "{needle} leaked to disk");
        }

        // a malicious store copies Bank's blob onto GitHub's row
        lb.db.execute("UPDATE items SET blob=(SELECT blob FROM items WHERE id=?2) WHERE id=?1", [a.to_string(), b.to_string()]).unwrap();
        assert!(matches!(lb.get_item(&a), Err(Error::Decrypt)));
        // rolling a version number back is caught too
        lb.db.execute("UPDATE items SET version=version+1 WHERE id=?1", [b.to_string()]).unwrap();
        assert!(matches!(lb.get_item(&b), Err(Error::Decrypt)));
    }
}
