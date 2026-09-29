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
}

impl Item {
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    pub name: String,
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
    Ok(db)
}

fn read_header(db: &Connection) -> Result<Option<Header>> {
    let raw: Option<Vec<u8>> = db.query_row("SELECT v FROM meta WHERE k='header'", [], |r| r.get(0)).optional()?;
    Ok(raw.map(|r| serde_json::from_slice(&r)).transpose()?)
}

impl Lockbox {
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
        Ok(Self { db, kek })
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
        self.write_item(id, &cur.vault_id, cur.version + 1, &item)
    }

    /// Soft delete: leaves a tombstone so the deletion can sync.
    pub fn delete_item(&self, id: &Uuid) -> Result<()> {
        let n = self.db.execute(
            "UPDATE items SET blob=NULL, version=version+1 WHERE id=?1 AND blob IS NOT NULL",
            [id.to_string()],
        )?;
        if n == 0 { Err(Error::NotFound) } else { Ok(()) }
    }

    fn decode(&self, id: String, vault: String, version: i64, blob: Vec<u8>) -> Result<ItemRecord> {
        let (id, vault_id, version) = (uuid(id), uuid(vault), version as u64);
        let json = crypto::open(&self.vault_key(&vault_id)?, &blob, &item_aad(&vault_id, &id, version))?;
        Ok(ItemRecord { id, vault_id, version, item: serde_json::from_slice(&json)? })
    }

    pub fn get_item(&self, id: &Uuid) -> Result<ItemRecord> {
        let row = self
            .db
            .query_row(
                "SELECT id, vault_id, version, blob FROM items WHERE id=?1 AND blob IS NOT NULL",
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
            "SELECT id, vault_id, version, blob FROM items WHERE blob IS NOT NULL AND (?1 IS NULL OR vault_id=?1)",
        )?;
        let rows = stmt.query_map([vault.map(|v| v.to_string())], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        rows.map(|row| {
            let (a, b, c, d) = row?;
            self.decode(a, b, c, d)
        })
        .collect()
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
