//! Key derivation and AEAD. See SPEC.md §2–4. Changing anything here breaks existing vaults.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::Error;

pub type Key = Zeroizing<[u8; 32]>;

const BLOB_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_kib: 256 * 1024, t: 3, p: 4 }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SysRng.try_fill_bytes(&mut b).expect("OS RNG unavailable");
    b
}

pub fn random_key() -> Key {
    Zeroizing::new(random_bytes())
}

fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Key {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(salt, ikm).expand(info, out.as_mut()).expect("32 bytes is a valid HKDF length");
    out
}

/// AUK = Argon2id(MP) XOR HKDF(SK). Both halves are needed.
pub fn derive_auk(password: &str, secret_key: &SecretKey, salt: &[u8; 16], p: KdfParams) -> Result<Key, Error> {
    let pw = Zeroizing::new(password.trim().nfkd().collect::<String>());
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| Error::BadKdfParams)?;
    let mut k_mp = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt, k_mp.as_mut())
        .map_err(|_| Error::BadKdfParams)?;
    let k_sk = hkdf(&secret_key.0[..], Some(salt), b"lb-auk");
    let mut auk = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        auk[i] = k_mp[i] ^ k_sk[i];
    }
    Ok(auk)
}

pub fn kek(auk: &Key) -> Key {
    hkdf(&auk[..], None, b"lb-enc")
}

/// Sent to the sync server (M5); never used for encryption.
pub fn auth_key(auk: &Key) -> Key {
    hkdf(&auk[..], None, b"lb-auth")
}

/// `version(1) || nonce(24) || ciphertext+tag`
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = XNonce::generate();
    let ct = XChaCha20Poly1305::new(&(**key).into())
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("encryption of in-memory buffer cannot fail");
    [&[BLOB_VERSION][..], &nonce[..], &ct].concat()
}

pub fn open(key: &Key, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if blob.len() < 1 + NONCE_LEN || blob[0] != BLOB_VERSION {
        return Err(Error::Decrypt);
    }
    let nonce = XNonce::try_from(&blob[1..1 + NONCE_LEN]).map_err(|_| Error::Decrypt)?;
    XChaCha20Poly1305::new(&(**key).into())
        .decrypt(&nonce, Payload { msg: &blob[1 + NONCE_LEN..], aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// 128-bit Secret Key. Display format: `LB1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-C`
/// (26 Crockford base32 chars: first carries 3 bits, rest 5 each; plus 1 checksum char).
pub struct SecretKey(pub Zeroizing<[u8; 16]>);

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

impl SecretKey {
    pub fn generate() -> Self {
        Self(Zeroizing::new(random_bytes()))
    }

    fn checksum(bytes: &[u8; 16]) -> u8 {
        CROCKFORD[(Sha256::digest(bytes)[0] & 31) as usize]
    }

    pub fn to_display(&self) -> String {
        let n = u128::from_be_bytes(*self.0);
        let chars: Vec<u8> = (0..26).rev().map(|i| CROCKFORD[((n >> (i * 5)) & 31) as usize]).collect();
        let s = std::str::from_utf8(&chars).unwrap();
        format!(
            "LB1-{}-{}-{}-{}-{}-{}",
            &s[0..6], &s[6..11], &s[11..16], &s[16..21], &s[21..26],
            Self::checksum(&self.0) as char
        )
    }

    /// Case-insensitive; ignores dashes/spaces; accepts Crockford aliases (O→0, I/L→1).
    pub fn parse(input: &str) -> Result<Self, Error> {
        let upper: String = input.to_ascii_uppercase().chars().filter(|c| !matches!(c, '-' | ' ')).collect();
        let body: Vec<u8> = upper
            .strip_prefix("LB1")
            .ok_or(Error::BadSecretKey)?
            .bytes()
            .map(|c| match c {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                c => c,
            })
            .collect();
        if body.len() != 27 {
            return Err(Error::BadSecretKey);
        }
        let mut n: u128 = 0;
        for (i, &c) in body[..26].iter().enumerate() {
            let v = CROCKFORD.iter().position(|&x| x == c).ok_or(Error::BadSecretKey)? as u128;
            if i == 0 && v >= 8 {
                return Err(Error::BadSecretKey);
            }
            n = (n << 5) | v;
        }
        let bytes = n.to_be_bytes();
        if Self::checksum(&bytes) != body[26] {
            return Err(Error::BadSecretKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // RFC 5869 A.1
    #[test]
    fn hkdf_rfc5869() {
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&h("000102030405060708090a0b0c")), &[0x0b; 22])
            .expand(&h("f0f1f2f3f4f5f6f7f8f9"), &mut okm)
            .unwrap();
        assert_eq!(hex::encode(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    // RFC 9106 §5.3
    #[test]
    fn argon2id_rfc9106() {
        let mut out = [0u8; 32];
        let p = argon2::ParamsBuilder::new().m_cost(32).t_cost(3).p_cost(4).output_len(32).data(argon2::AssociatedData::new(&[4; 12]).unwrap()).build().unwrap();
        let a = Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, p).unwrap();
        a.hash_password_into(&[1; 32], &[2; 16], &mut out).unwrap();
        assert_eq!(hex::encode(out), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    // draft-irtf-cfrg-xchacha-03 A.3.1
    #[test]
    fn xchacha_draft_vector() {
        let key: [u8; 32] = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").try_into().unwrap();
        let nonce = XNonce::try_from(&h("404142434445464748494a4b4c4d4e4f5051525354555657")[..]).unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = XChaCha20Poly1305::new(&key.into())
            .encrypt(&nonce, Payload { msg: pt, aad: &h("50515253c0c1c2c3c4c5c6c7") })
            .unwrap();
        assert_eq!(
            hex::encode(ct),
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        );
    }

    /// Pins lockbox's own derivation. If this changes, existing vaults stop opening.
    #[test]
    fn auk_golden() {
        let sk = SecretKey(Zeroizing::new([7; 16]));
        let auk = derive_auk("  correct horse  ", &sk, &[9; 16], KdfParams { m_kib: 64, t: 1, p: 1 }).unwrap();
        assert_eq!(hex::encode(*auk), "f937115d9c21188f400d07b7ac7474b3c499b61003031ab4c49248b5b3ce3aac");
    }

    #[test]
    fn seal_open_and_aad_binding() {
        let k = random_key();
        let blob = seal(&k, b"hunter2", b"item-a");
        assert_eq!(&open(&k, &blob, b"item-a").unwrap()[..], b"hunter2");
        assert!(open(&k, &blob, b"item-b").is_err(), "moved blob must not open");
        assert!(open(&random_key(), &blob, b"item-a").is_err());
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&k, &tampered, b"item-a").is_err());
    }

    #[test]
    fn secret_key_roundtrip_and_typos() {
        for _ in 0..200 {
            let sk = SecretKey::generate();
            let s = sk.to_display();
            assert_eq!(s.len(), 4 + 6 + 4 * 6 + 2);
            assert_eq!(*SecretKey::parse(&s).unwrap().0, *sk.0);
            assert_eq!(*SecretKey::parse(&s.to_lowercase().replace('-', " ")).unwrap().0, *sk.0);
        }
        let s = SecretKey(Zeroizing::new([0xAB; 16])).to_display();
        let mut typo = s.clone().into_bytes();
        typo[8] = if typo[8] == b'Z' { b'Y' } else { b'Z' };
        assert!(SecretKey::parse(std::str::from_utf8(&typo).unwrap()).is_err());
    }
}
