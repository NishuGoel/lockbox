use rand::RngExt;
use rand::seq::{IndexedRandom, SliceRandom};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug)]
pub struct PasswordOpts {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    /// drop 0/O, 1/l/I — for passwords you'll type by hand
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOpts {
    fn default() -> Self {
        Self { length: 24, lower: true, upper: true, digits: true, symbols: true, avoid_ambiguous: false }
    }
}

const AMBIGUOUS: &str = "0O1lI";

/// Uniform over the pool, guaranteeing one char from each enabled class. ThreadRng is a CSPRNG seeded from the OS.
pub fn password(o: PasswordOpts) -> Result<String> {
    let classes: Vec<Vec<char>> = [
        (o.lower, "abcdefghijklmnopqrstuvwxyz"),
        (o.upper, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (o.digits, "0123456789"),
        (o.symbols, "!@#$%^&*()-_=+[]{};:,.?/~"),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, cs)| cs.chars().filter(|c| !(o.avoid_ambiguous && AMBIGUOUS.contains(*c))).collect())
    .collect();
    if classes.is_empty() {
        return Err(Error::BadGeneratorOptions("enable at least one character class"));
    }
    if o.length < classes.len().max(8) || o.length > 256 {
        return Err(Error::BadGeneratorOptions("length must be 8–256 and ≥ number of classes"));
    }
    let pool: Vec<char> = classes.concat();
    let rng = &mut rand::rng();
    let mut out: Vec<char> = classes.iter().map(|c| *c.choose(rng).unwrap()).collect();
    out.extend((out.len()..o.length).map(|_| *pool.choose(rng).unwrap()));
    out.shuffle(rng);
    Ok(out.into_iter().collect())
}

/// EFF large wordlist: 7776 words, ~12.9 bits per word.
const WORDS: &str = include_str!("../data/eff_large_wordlist.txt");

pub fn memorable(words: usize, separator: &str) -> Result<String> {
    if !(3..=12).contains(&words) {
        return Err(Error::BadGeneratorOptions("use 3–12 words"));
    }
    let list: Vec<&str> = WORDS.lines().collect();
    let rng = &mut rand::rng();
    Ok((0..words).map(|_| *list.choose(rng).unwrap()).collect::<Vec<_>>().join(separator))
}

pub fn pin(length: usize) -> Result<String> {
    if !(4..=32).contains(&length) {
        return Err(Error::BadGeneratorOptions("PIN length must be 4–32"));
    }
    let rng = &mut rand::rng();
    Ok((0..length).map(|_| char::from(b'0' + rng.random_range(0..10u8))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_options() {
        for _ in 0..500 {
            let p = password(PasswordOpts::default()).unwrap();
            assert_eq!(p.chars().count(), 24);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| !c.is_ascii_alphanumeric()));

            let p = password(PasswordOpts { symbols: false, avoid_ambiguous: true, length: 12, ..Default::default() }).unwrap();
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric() && !AMBIGUOUS.contains(c)));
        }
        assert!(password(PasswordOpts { lower: false, upper: false, digits: false, symbols: false, ..Default::default() }).is_err());
        assert!(password(PasswordOpts { length: 4, ..Default::default() }).is_err());
        let m = memorable(4, "-").unwrap();
        assert_eq!(m.split('-').count(), 4);
        assert!(m.split('-').all(|w| WORDS.lines().any(|l| l == w)));
        assert_eq!(WORDS.lines().count(), 7776);
        assert!(memorable(2, "-").is_err());
        let p = pin(6).unwrap();
        assert!(p.len() == 6 && p.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn roughly_uniform() {
        let o = PasswordOpts { upper: false, digits: false, symbols: false, length: 256, ..Default::default() };
        let mut counts = [0u32; 26];
        for _ in 0..200 {
            for c in password(o).unwrap().bytes() {
                counts[(c - b'a') as usize] += 1;
            }
        }
        // expected ≈ 1969 per letter; a biased picker (e.g. modulo on a byte) drifts well past ±15%
        assert!(counts.iter().all(|&n| (1670..2270).contains(&n)), "{counts:?}");
    }
}
