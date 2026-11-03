//! Share links: encrypt one item here, upload only ciphertext to the share server (server/share),
//! and put the key in the link's #fragment. The key schedule must match server/share/public/viewer.js:
//!   K = 32 random bytes (the fragment)
//!   P = PBKDF2-SHA256(NFKC(passphrase), salt = K, 600k, 32 bytes)     (only with a passphrase)
//!   64 bytes = HKDF-SHA256(ikm = K || P, salt = "lockbox-share", info = "lockbox-share-v1")
//!   aes key = [0..32]; verifier = b64url(SHA-256([32..64] || id))
//!   blob = 0x01 | flags | nonce(12) | AES-256-GCM(json, aad = "lockbox-share-v1:" + id)

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use lockbox_core::Item;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::backup::Settings;
use crate::webauthn::{b64, unb64};

pub const PBKDF2_ROUNDS: u32 = 600_000;
const TOKEN_SERVICE: &str = "lockbox.share-token";
const FLAG_PASSPHRASE: u8 = 1;

/// What goes into a share. The 2FA secret is opt-in: sharing it grants lasting access.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Include {
    pub username: bool,
    pub password: bool,
    pub urls: bool,
    pub notes: bool,
    pub totp: bool,
    pub fields: bool,
}

impl Default for Include {
    fn default() -> Self {
        Self { username: true, password: true, urls: true, notes: true, totp: false, fields: true }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SharedField {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SharedItem {
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
    pub fields: Vec<SharedField>,
}

pub fn payload(item: &Item, inc: &Include) -> SharedItem {
    let pick = |on: bool, v: &Option<String>| if on { v.clone() } else { None };
    SharedItem {
        title: item.title.clone(),
        username: pick(inc.username, &item.username),
        password: pick(inc.password, &item.password),
        urls: if inc.urls { item.urls.clone() } else { vec![] },
        notes: pick(inc.notes, &item.notes),
        totp: pick(inc.totp, &item.totp),
        fields: if inc.fields { item.fields.iter().map(|f| SharedField { name: f.name.clone(), value: f.value.clone() }).collect() } else { vec![] },
    }
}

pub struct Sealed {
    pub id: String,
    pub ciphertext: String,
    pub verifier: String,
    /// goes in the #fragment only; never sent to the server
    pub key: Zeroizing<String>,
}

fn schedule(k: &[u8], passphrase: Option<&str>, id: &str) -> (Zeroizing<[u8; 64]>, String) {
    let mut ikm = Zeroizing::new(k.to_vec());
    if let Some(p) = passphrase {
        let mut pk = Zeroizing::new([0u8; 32]);
        let norm = Zeroizing::new(p.nfkc().collect::<String>());
        pbkdf2::pbkdf2_hmac::<Sha256>(norm.as_bytes(), k, PBKDF2_ROUNDS, pk.as_mut());
        ikm.extend_from_slice(&pk[..]);
    }
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(b"lockbox-share"), &ikm).expand(b"lockbox-share-v1", okm.as_mut()).expect("64 bytes is a valid length");
    let verifier = b64(&Sha256::digest([&okm[32..], id.as_bytes()].concat()));
    (okm, verifier)
}

fn aad(id: &str) -> Vec<u8> {
    format!("lockbox-share-v1:{id}").into_bytes()
}

pub fn seal(plaintext: &[u8], passphrase: Option<&str>) -> Sealed {
    let id = b64(&lockbox_core::crypto::random_bytes::<16>());
    let k = Zeroizing::new(lockbox_core::crypto::random_bytes::<32>());
    let (okm, verifier) = schedule(&k[..], passphrase, &id);
    let nonce: [u8; 12] = lockbox_core::crypto::random_bytes();
    let ct = Aes256Gcm::new_from_slice(&okm[..32])
        .expect("32-byte key")
        .encrypt(&Nonce::from(nonce), Payload { msg: plaintext, aad: &aad(&id) })
        .expect("in-memory encryption");
    let flags = if passphrase.is_some() { FLAG_PASSPHRASE } else { 0 };
    let blob = [&[1u8, flags][..], &nonce, &ct].concat();
    Sealed { ciphertext: b64(&blob), verifier, key: Zeroizing::new(b64(&k[..])), id }
}

/// The recipient side, for tests and `lockbox share open`.
pub fn open(id: &str, key: &str, ciphertext: &str, passphrase: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
    let k = Zeroizing::new(unb64(key)?);
    let blob = unb64(ciphertext)?;
    if k.len() != 32 || blob.len() < 14 || blob[0] != 1 {
        return Err("not a lockbox share".into());
    }
    let (okm, _) = schedule(&k, passphrase, id);
    let nonce: [u8; 12] = blob[2..14].try_into().unwrap();
    Aes256Gcm::new_from_slice(&okm[..32])
        .expect("32-byte key")
        .decrypt(&Nonce::from(nonce), Payload { msg: &blob[14..], aad: &aad(id) })
        .map(Zeroizing::new)
        .map_err(|_| "wrong passphrase or damaged link".into())
}

// ---------- server ----------

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedLink {
    pub id: String,
    pub title: String,
    pub created_at: u64,
    /// milliseconds since the epoch, as the server reports it
    pub expires_at: u64,
    pub views: Option<u32>,
}

pub struct Server {
    pub url: String,
    token: Zeroizing<String>,
}

fn http_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(401) => "The sharing server rejected lockbox's token. Run the sharing setup again.".into(),
        ureq::Error::StatusCode(413) => "That item is too large to share.".into(),
        ureq::Error::StatusCode(c) => format!("The sharing server answered {c}."),
        e => format!("Couldn't reach the sharing server: {e}"),
    }
}

impl Server {
    /// The server lockbox was set up with, if any. The URL lives in settings, the token in the Keychain.
    pub fn configured(dir: &Path) -> Option<Self> {
        let url = Settings::load(dir).share_url?;
        let token = crate::mac::load_secret(TOKEN_SERVICE, &url).ok().flatten()?;
        Some(Self { url, token: Zeroizing::new(token) })
    }

    /// Checks the URL + token against the server, then saves them.
    pub fn setup(dir: &Path, url: &str, token: &str) -> Result<(), String> {
        let url = url.trim().trim_end_matches('/').to_string();
        if !(url.starts_with("https://") || url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1")) {
            return Err("The sharing server must use https.".into());
        }
        let s = Self { url: url.clone(), token: Zeroizing::new(token.trim().to_string()) };
        let health: serde_json::Value = s.get("/api/health")?;
        if health["authorized"] != true {
            return Err("The server is up, but it doesn't accept that token.".into());
        }
        crate::mac::save_secret(TOKEN_SERVICE, &url, &s.token)?;
        let mut st = Settings::load(dir);
        st.share_url = Some(url);
        st.save(dir).map_err(|e| e.to_string())
    }

    fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        ureq::get(format!("{}{path}", self.url))
            .header("authorization", format!("Bearer {}", *self.token))
            .call()
            .map_err(http_err)?
            .body_mut()
            .read_json()
            .map_err(|e| e.to_string())
    }

    /// Encrypts, uploads, records the link (without its key) and returns the full link.
    pub fn share(&self, dir: &Path, item: &Item, inc: &Include, views: Option<u32>, ttl_secs: u64, passphrase: Option<&str>) -> Result<(String, SharedLink), String> {
        let json = Zeroizing::new(serde_json::to_vec(&payload(item, inc)).map_err(|e| e.to_string())?);
        let sealed = seal(&json, passphrase.filter(|p| !p.is_empty()));
        let body = serde_json::json!({
            "id": sealed.id, "ciphertext": sealed.ciphertext, "verifier": sealed.verifier,
            "views": views, "ttl": ttl_secs, "passphrase": passphrase.is_some_and(|p| !p.is_empty()),
        });
        let res: serde_json::Value = ureq::post(format!("{}/api/shares", self.url))
            .header("authorization", format!("Bearer {}", *self.token))
            .send_json(&body)
            .map_err(http_err)?
            .body_mut()
            .read_json()
            .map_err(|e| e.to_string())?;
        let link = SharedLink {
            id: sealed.id.clone(),
            title: item.title.clone(),
            created_at: crate::backup::now(),
            expires_at: res["expiresAt"].as_u64().unwrap_or(0),
            views,
        };
        let mut st = Settings::load(dir);
        st.shares.retain(|s| s.expires_at > crate::backup::now() * 1000);
        st.shares.insert(0, link.clone());
        st.save(dir).map_err(|e| e.to_string())?;
        Ok((format!("{}/s/{}#{}", self.url, sealed.id, *sealed.key), link))
    }

    pub fn revoke(&self, dir: &Path, id: &str) -> Result<(), String> {
        ureq::delete(format!("{}/api/shares/{id}", self.url))
            .header("authorization", format!("Bearer {}", *self.token))
            .call()
            .map_err(http_err)?;
        let mut st = Settings::load(dir);
        st.shares.retain(|s| s.id != id);
        st.save(dir).map_err(|e| e.to_string())
    }
}

/// "1h", "2d", "30m", "7 days" → seconds.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let n: u64 = s[..split].parse().ok()?;
    let unit = s[split..].trim();
    let mult = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86_400,
        _ => return None,
    };
    Some(n * mult)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockbox_core::Field;

    fn item() -> Item {
        Item {
            title: "Wi-Fi".into(), username: Some("guest".into()), password: Some("maple-orbit".into()),
            urls: vec!["http://router.local".into()], notes: Some("2nd floor".into()), totp: Some("GEZDGNBVGY3TQOJQ".into()),
            fields: vec![Field { name: "PIN".into(), value: "1234".into(), concealed: true }], ..Default::default()
        }
    }

    #[test]
    fn seal_open_round_trip_and_binding() {
        let json = serde_json::to_vec(&payload(&item(), &Include::default())).unwrap();
        let s = seal(&json, None);
        assert_eq!((s.id.len(), s.key.len()), (22, 43));
        let back: SharedItem = serde_json::from_slice(&open(&s.id, &s.key, &s.ciphertext, None).unwrap()).unwrap();
        assert_eq!(back.password.as_deref(), Some("maple-orbit"));
        assert_eq!(back.totp, None, "2FA secret is opt-in");
        assert!(open("AAAAAAAAAAAAAAAAAAAAAA", &s.key, &s.ciphertext, None).is_err(), "bound to its id");
        let other = seal(&json, None);
        assert!(open(&s.id, &other.key, &s.ciphertext, None).is_err());
    }

    #[test]
    fn passphrase_and_verifier() {
        let s = seal(b"{}", Some("correct ho\u{0301}rse"));
        assert!(open(&s.id, &s.key, &s.ciphertext, None).is_err());
        assert!(open(&s.id, &s.key, &s.ciphertext, Some("wrong")).is_err());
        // NFKC: precomposed and combining forms are the same passphrase
        assert!(open(&s.id, &s.key, &s.ciphertext, Some("correct hórse")).is_ok());
        let k = unb64(&s.key).unwrap();
        assert_eq!(schedule(&k, Some("correct hórse"), &s.id).1, s.verifier);
        assert_ne!(schedule(&k, Some("wrong"), &s.id).1, s.verifier);
    }

    #[test]
    fn include_choices() {
        let none = Include { username: false, password: false, urls: false, notes: false, totp: false, fields: false };
        let p = payload(&item(), &none);
        assert_eq!((p.title.as_str(), p.username, p.password, p.urls.len(), p.fields.len()), ("Wi-Fi", None, None, 0, 0));
        assert_eq!(payload(&item(), &Include { totp: true, ..Default::default() }).totp.as_deref(), Some("GEZDGNBVGY3TQOJQ"));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("7 days"), Some(604_800));
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration("soon"), None);
    }
}
