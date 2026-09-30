//! A software WebAuthn authenticator (ES256 / P-256, "none" attestation, discoverable, synced).
//! The browser extension hands over the page's request; the *page URL comes from the browser*,
//! so a page can't claim to be another site. Private keys never leave this module.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lockbox_core::Passkey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Identifies lockbox as the authenticator model (random, fixed).
pub const AAGUID: [u8; 16] = [0x6c, 0x0b, 0x6f, 0x78, 0x3a, 0x4e, 0x4f, 0x6a, 0x9d, 0x2e, 0x5b, 0x21, 0xc4, 0x17, 0x8a, 0x93];
pub const ES256: i64 = -7;

// user present | user verified (vault unlocked + explicit click) | backup eligible | backed up
const FLAGS_GET: u8 = 0x01 | 0x04 | 0x08 | 0x10;
const FLAG_ATTESTED: u8 = 0x40;

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| "bad base64url".into())
}

fn parts(url: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let host = authority.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(authority, |(h, _)| h);
    Some((scheme.to_lowercase(), host.to_lowercase(), authority.to_lowercase()))
}

/// `scheme://host[:port]`, as the browser would put it in clientDataJSON.
pub fn origin_of(page_url: &str) -> Option<String> {
    parts(page_url).map(|(s, _, a)| format!("{s}://{a}"))
}

/// The page may use `rp_id` if it's the page's own host or a parent domain of it, over https
/// (http only for localhost), the same rule browsers apply.
// ponytail: no public-suffix list. Ceiling: a page on evil.github.io could claim rpId "github.io"; it
// can only ever reach passkeys made for "github.io" itself, never another site's.
pub fn rp_id_ok(rp_id: &str, page_url: &str) -> bool {
    let Some((scheme, host, _)) = parts(page_url) else { return false };
    let rp = rp_id.to_lowercase();
    let local = host == "localhost";
    let secure = scheme == "https" || (scheme == "http" && local);
    secure && (rp.contains('.') || (local && rp == "localhost")) && (host == rp || host.ends_with(&format!(".{rp}")))
}

// ---- minimal CBOR (only the shapes WebAuthn needs) ----
fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => [&[m | 25][..], &(n as u16).to_be_bytes()].concat(),
        _ => [&[m | 26][..], &(n as u32).to_be_bytes()].concat(),
    }
}
fn int(v: i64) -> Vec<u8> {
    if v >= 0 { head(0, v as u64) } else { head(1, (-1 - v) as u64) }
}
fn bytes(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}
fn text(s: &str) -> Vec<u8> {
    [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}

fn signing_key(pk: &Passkey) -> Result<SigningKey, String> {
    let raw = Zeroizing::new(unb64(&pk.private_key)?);
    SigningKey::from_slice(&raw).map_err(|_| "corrupt passkey".into())
}

fn sec1(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

/// COSE_Key for ES256, canonical key order 1, 3, -1, -2, -3.
fn cose_key(sk: &SigningKey) -> Vec<u8> {
    let p = sec1(sk);
    [head(5, 5), int(1), int(2), int(3), int(ES256), int(-1), int(1), int(-2), bytes(&p[1..33]), int(-3), bytes(&p[33..65])].concat()
}

/// SubjectPublicKeyInfo DER for a P-256 key (what `response.getPublicKey()` returns).
fn spki(sk: &SigningKey) -> Vec<u8> {
    const PREFIX: [u8; 26] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
    [&PREFIX[..], &sec1(sk)].concat()
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })).unwrap()
}

fn auth_data(rp_id: &str, flags: u8, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut d = Sha256::digest(rp_id.as_bytes()).to_vec();
    d.push(flags);
    d.extend_from_slice(&0u32.to_be_bytes()); // synced credentials keep signCount at 0
    if let Some((cred_id, cose)) = attested {
        d.extend_from_slice(&AAGUID);
        d.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        d.extend_from_slice(cred_id);
        d.extend_from_slice(cose);
    }
    d
}

pub struct Request<'a> {
    pub page_url: &'a str,
    pub rp_id: &'a str,
    pub challenge: &'a str,
}

/// navigator.credentials.create(): a new passkey and the attestation response for the page.
pub fn create(req: &Request, user_handle: &str, user_name: &str, display_name: &str) -> Result<(Passkey, serde_json::Value), String> {
    if !rp_id_ok(req.rp_id, req.page_url) {
        return Err("This site can't create a passkey for that domain.".into());
    }
    unb64(req.challenge)?;
    unb64(user_handle)?;
    let origin = origin_of(req.page_url).ok_or("bad page url")?;
    let sk = loop {
        let raw = Zeroizing::new(lockbox_core::crypto::random_bytes::<32>());
        if let Ok(k) = SigningKey::from_slice(&raw[..]) {
            break k;
        }
    };
    let cred_id = lockbox_core::crypto::random_bytes::<16>();
    let cdj = client_data("webauthn.create", req.challenge, &origin);
    let ad = auth_data(req.rp_id, FLAGS_GET | FLAG_ATTESTED, Some((&cred_id, &cose_key(&sk))));
    let att = [head(5, 3), text("fmt"), text("none"), text("attStmt"), head(5, 0), text("authData"), bytes(&ad)].concat();
    let pk = Passkey {
        rp_id: req.rp_id.to_lowercase(),
        credential_id: b64(&cred_id),
        user_handle: user_handle.to_string(),
        user_name: user_name.to_string(),
        user_display_name: display_name.to_string(),
        private_key: b64(&sk.to_bytes()),
        created_at: crate::backup::now(),
    };
    let resp = serde_json::json!({
        "id": pk.credential_id, "clientDataJSON": b64(&cdj), "attestationObject": b64(&att),
        "authenticatorData": b64(&ad), "publicKey": b64(&spki(&sk)), "publicKeyAlgorithm": ES256,
        "transports": ["hybrid", "internal"],
    });
    Ok((pk, resp))
}

/// navigator.credentials.get(): sign the page's challenge with a stored passkey.
pub fn assert(req: &Request, pk: &Passkey) -> Result<serde_json::Value, String> {
    if !rp_id_ok(req.rp_id, req.page_url) || !pk.rp_id.eq_ignore_ascii_case(req.rp_id) {
        return Err("This passkey isn't for this site.".into());
    }
    unb64(req.challenge)?;
    let origin = origin_of(req.page_url).ok_or("bad page url")?;
    let cdj = client_data("webauthn.get", req.challenge, &origin);
    let ad = auth_data(&pk.rp_id, FLAGS_GET, None);
    let sig: Signature = signing_key(pk)?.sign(&[&ad[..], &Sha256::digest(&cdj)].concat());
    Ok(serde_json::json!({
        "id": pk.credential_id, "clientDataJSON": b64(&cdj), "authenticatorData": b64(&ad),
        "signature": b64(&sig.to_der().to_bytes()), "userHandle": pk.user_handle,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value as C;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    fn get_map(m: &C, key: C) -> &C {
        m.as_map().unwrap().iter().find(|(k, _)| *k == key).map(|(_, v)| v).unwrap()
    }

    #[test]
    fn rp_id_rules() {
        assert!(rp_id_ok("github.com", "https://github.com/login"));
        assert!(rp_id_ok("example.com", "https://login.example.com/"));
        assert!(rp_id_ok("localhost", "http://localhost:8766/x"));
        assert!(!rp_id_ok("github.com", "https://github.com.evil.io/"), "not a parent domain");
        assert!(!rp_id_ok("login.example.com", "https://example.com/"), "can't claim a child domain");
        assert!(!rp_id_ok("example.com", "http://example.com/"), "https only");
        assert!(!rp_id_ok("com", "https://example.com/"), "no bare TLDs");
        assert!(!rp_id_ok("evil.io", "https://github.com@evil.io/"), "no userinfo tricks");
        assert_eq!(origin_of("https://Login.Example.com:8443/a?b").as_deref(), Some("https://login.example.com:8443"));
    }

    #[test]
    fn create_then_assert_verifies() {
        let challenge = b64(b"random-challenge-from-server-1234");
        let req = Request { page_url: "https://webauthn.io/register", rp_id: "webauthn.io", challenge: &challenge };
        let (pk, resp) = create(&req, &b64(b"user-42"), "nishu", "Nishu").unwrap();
        assert!(format!("{pk:?}").contains("[redacted]") && !format!("{pk:?}").contains(&pk.private_key));

        // attestation object decodes as CBOR with the fields servers read
        let att: C = ciborium::from_reader(&unb64(resp["attestationObject"].as_str().unwrap()).unwrap()[..]).unwrap();
        assert_eq!(get_map(&att, C::Text("fmt".into())), &C::Text("none".into()));
        let ad = get_map(&att, C::Text("authData".into())).as_bytes().unwrap().clone();
        assert_eq!(&ad[..32], &Sha256::digest(b"webauthn.io")[..]);
        assert_eq!(ad[32], 0x5d, "UP UV BE BS AT");
        assert_eq!(&ad[37..53], &AAGUID);
        let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        assert_eq!(b64(&ad[55..55 + id_len]), pk.credential_id);
        let cose: C = ciborium::from_reader(&ad[55 + id_len..]).unwrap();
        assert_eq!(get_map(&cose, C::Integer(3.into())), &C::Integer((-7).into()));
        let x = get_map(&cose, C::Integer((-2).into())).as_bytes().unwrap().clone();

        // SPKI and COSE describe the same key
        let spki_bytes = unb64(resp["publicKey"].as_str().unwrap()).unwrap();
        assert_eq!(&spki_bytes[27..59], &x[..]);
        let vk = VerifyingKey::from_sec1_bytes(&spki_bytes[26..]).unwrap();

        let cdj: serde_json::Value = serde_json::from_slice(&unb64(resp["clientDataJSON"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!((cdj["type"].as_str(), cdj["origin"].as_str(), cdj["challenge"].as_str()), (Some("webauthn.create"), Some("https://webauthn.io"), Some(challenge.as_str())));

        // sign in: signature verifies over authData || sha256(clientDataJSON)
        let c2 = b64(b"second-challenge");
        let a = assert(&Request { page_url: "https://webauthn.io/", rp_id: "webauthn.io", challenge: &c2 }, &pk).unwrap();
        let ad2 = unb64(a["authenticatorData"].as_str().unwrap()).unwrap();
        let cdj2 = unb64(a["clientDataJSON"].as_str().unwrap()).unwrap();
        let sig = Signature::from_der(&unb64(a["signature"].as_str().unwrap()).unwrap()).unwrap();
        vk.verify(&[&ad2[..], &Sha256::digest(&cdj2)].concat(), &sig).unwrap();
        assert_eq!((ad2.len(), ad2[32]), (37, 0x1d));
        assert_eq!(a["userHandle"], b64(b"user-42"));

        // a lookalike can't use it, nor claim its rpId
        assert!(assert(&Request { page_url: "https://webauthn.io.evil.com/", rp_id: "webauthn.io", challenge: &c2 }, &pk).is_err());
        assert!(assert(&Request { page_url: "https://evil.com/", rp_id: "evil.com", challenge: &c2 }, &pk).is_err());
        assert!(create(&Request { page_url: "https://evil.com/", rp_id: "webauthn.io", challenge: &c2 }, "dQ", "x", "x").is_err());
    }

    #[test]
    fn cbor_lengths() {
        assert_eq!(bytes(&[0; 23])[0], 0x57);
        assert_eq!(&bytes(&[0; 24])[..2], &[0x58, 24]);
        assert_eq!(&bytes(&[0; 300])[..3], &[0x59, 0x01, 0x2c]);
        assert_eq!(int(-7), vec![0x26]);
        assert_eq!(int(-3), vec![0x22]);
    }
}
