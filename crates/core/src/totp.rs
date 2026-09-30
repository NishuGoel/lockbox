use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Builder, Secret, Totp};

use crate::{Error, Result};

/// Accepts an `otpauth://totp/...` URI or a bare base32 secret (spaces, lowercase, `=` padding ok).
/// Unchecked parsing on purpose: plenty of real sites issue 80-bit secrets that RFC-strict mode rejects.
pub fn parse(input: &str) -> Result<Totp> {
    let s = input.trim();
    if s.starts_with("otpauth://") {
        return Totp::from_url_unchecked(s).map_err(|_| Error::BadTotp);
    }
    let b32: String = s.chars().filter(|c| !c.is_whitespace() && *c != '=').collect::<String>().to_uppercase();
    let secret = Secret::try_from_base32(&b32).map_err(|_| Error::BadTotp)?;
    if secret.as_bytes().is_empty() {
        return Err(Error::BadTotp);
    }
    Ok(Builder::new().with_secret(secret).build_noncompliant())
}

pub struct Code {
    pub code: String,
    /// seconds until this code rotates
    pub remaining: u64,
}

pub fn current(input: &str) -> Result<Code> {
    let t = parse(input)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    Ok(Code { code: t.generate(now).to_string(), remaining: t.next_step(now) - now })
}

#[cfg(test)]
mod tests {
    use super::*;
    use totp_rs::Algorithm;

    // RFC 6238 Appendix B
    #[test]
    fn rfc6238_vectors() {
        let sha1 = Builder::new().with_digits(8).with_secret(b"12345678901234567890".to_vec()).build_noncompliant();
        let sha256 = Builder::new()
            .with_digits(8)
            .with_algorithm(Algorithm::SHA256)
            .with_secret(b"12345678901234567890123456789012".to_vec())
            .build_noncompliant();
        for (t, c1, c256) in [(59, "94287082", "46119246"), (1111111109, "07081804", "68084774"), (1234567890, "89005924", "91819424"), (20000000000, "65353130", "77737706")] {
            assert_eq!(sha1.generate(t).to_string(), c1, "sha1 t={t}");
            assert_eq!(sha256.generate(t).to_string(), c256, "sha256 t={t}");
        }
    }

    #[test]
    fn parses_real_world_inputs() {
        // base32("12345678901234567890") in the messy ways users paste it
        for s in ["GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ===="] {
            assert_eq!(parse(s).unwrap().generate(59).to_string(), "287082");
        }
        let uri = "otpauth://totp/GitHub:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8";
        assert_eq!(parse(uri).unwrap().generate(59).to_string(), "94287082");
        assert!(parse("not base32 !!").is_err());
        let c = current("GEZDGNBVGY3TQOJQ").unwrap();
        assert!(c.code.len() == 6 && (1..=30).contains(&c.remaining));
    }
}
