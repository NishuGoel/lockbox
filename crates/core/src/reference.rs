//! Secret references for agents and scripts: `lockbox://<vault>/<item>/<field>`.
//! The reference is safe to write into `.env` files, commands and prompts; only lockbox turns it
//! into the value, after you approve. `<item>` is the item's title (or its id), `<field>` is
//! password, username, url, notes, totp (the current code) or a custom field's name.
//! Characters that would confuse the format can be percent-encoded (`%2F` for `/`).

use crate::vault::{ItemRecord, Vault};

pub const SCHEME: &str = "lockbox://";

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reference {
    pub vault: String,
    pub item: String,
    pub field: String,
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn encode(s: &str) -> String {
    s.replace('%', "%25").replace('/', "%2F")
}

impl Reference {
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.trim().strip_prefix(SCHEME)?;
        let (vault, rest) = rest.split_once('/')?;
        let (item, field) = rest.rsplit_once('/')?;
        let r = Self { vault: decode(vault), item: decode(item), field: decode(field) };
        (!r.vault.is_empty() && !r.item.is_empty() && !r.field.is_empty()).then_some(r)
    }

    pub fn new(vault: &str, item: &str, field: &str) -> Self {
        Self { vault: vault.into(), item: item.into(), field: field.into() }
    }

    /// Finds the item this reference points at (no secret is read yet).
    pub fn find<'a>(&self, items: &'a [ItemRecord], vaults: &[Vault]) -> Result<&'a ItemRecord, String> {
        let vault = vaults
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(&self.vault) || v.id.to_string() == self.vault)
            .ok_or_else(|| format!("no vault named \"{}\"", self.vault))?;
        let hits: Vec<&ItemRecord> = items
            .iter()
            .filter(|r| r.vault_id == vault.id && (r.item.title.eq_ignore_ascii_case(&self.item) || r.id.to_string() == self.item))
            .collect();
        match hits[..] {
            [one] => Ok(one),
            [] => Err(format!("no item \"{}\" in {}", self.item, vault.name)),
            _ => Err(format!("{} items are called \"{}\" in {}; use the item id instead", hits.len(), self.item, vault.name)),
        }
    }

    /// The secret value. `totp` gives the current one-time code.
    pub fn value(&self, item: &ItemRecord) -> Result<String, String> {
        let v = if self.field.eq_ignore_ascii_case("totp") {
            item.item.totp.as_deref().map(crate::totp::current).transpose().map_err(|e| e.to_string())?.map(|c| c.code)
        } else {
            item.item.field(&self.field)
        };
        v.ok_or_else(|| format!("{} has no {}", item.item.title, self.field))
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SCHEME}{}/{}/{}", encode(&self.vault), encode(&self.item), encode(&self.field))
    }
}

/// Every reference an item offers, for `lockbox ref` and agents (names only, never values).
pub fn references_for(item: &ItemRecord, vault_name: &str) -> Vec<Reference> {
    let i = &item.item;
    let mut fields: Vec<&str> = Vec::new();
    if i.username.is_some() {
        fields.push("username");
    }
    if i.password.is_some() {
        fields.push("password");
    }
    if i.totp.is_some() {
        fields.push("totp");
    }
    if !i.urls.is_empty() {
        fields.push("url");
    }
    if i.notes.is_some() {
        fields.push("notes");
    }
    let mut out: Vec<Reference> = fields.into_iter().map(|f| Reference::new(vault_name, &i.title, f)).collect();
    out.extend(i.fields.iter().map(|f| Reference::new(vault_name, &i.title, &f.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Field, Item};
    use uuid::Uuid;

    fn rec(vault: Uuid, title: &str) -> ItemRecord {
        ItemRecord {
            id: Uuid::new_v4(),
            vault_id: vault,
            version: 1,
            deleted_at: None,
            item: Item {
                title: title.into(),
                username: Some("deploy-bot".into()),
                password: Some("s3cr3t".into()),
                totp: Some("GEZDGNBVGY3TQOJQ".into()),
                fields: vec![Field { name: "API key".into(), value: "ak_live_123".into(), concealed: true }],
                ..Default::default()
            },
        }
    }

    #[test]
    fn parse_display_round_trip() {
        let r = Reference::parse("lockbox://Work/AWS Console/password").unwrap();
        assert_eq!(r, Reference::new("Work", "AWS Console", "password"));
        assert_eq!(r.to_string(), "lockbox://Work/AWS Console/password");
        let slash = Reference::new("Work", "CI/CD token", "API key");
        assert_eq!(slash.to_string(), "lockbox://Work/CI%2FCD token/API key");
        assert_eq!(Reference::parse(&slash.to_string()).unwrap(), slash);
        // item titles may contain '/' unencoded: the field is the last segment
        assert_eq!(Reference::parse("lockbox://Work/CI/CD token/password").unwrap().item, "CI/CD token");
        for bad in ["lockbox://", "lockbox://Work", "lockbox://Work/item", "op://Work/item/password", "lockbox:///item/password"] {
            assert!(Reference::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn find_and_value() {
        let (work, personal) = (Uuid::new_v4(), Uuid::new_v4());
        let vaults = vec![Vault { id: work, name: "Work".into() }, Vault { id: personal, name: "Personal".into() }];
        let items = vec![rec(work, "AWS Console"), rec(personal, "AWS Console"), rec(work, "Dup"), rec(work, "Dup")];
        let r = Reference::parse("lockbox://work/aws console/password").unwrap();
        let it = r.find(&items, &vaults).unwrap();
        assert_eq!(it.vault_id, work, "vault decides between same-named items");
        assert_eq!(r.value(it).unwrap(), "s3cr3t");
        assert_eq!(Reference::new("Work", "AWS Console", "api key").value(it).unwrap(), "ak_live_123");
        assert_eq!(Reference::new("Work", "AWS Console", "totp").value(it).unwrap().len(), 6);
        assert!(Reference::new("Work", "AWS Console", "notes").value(it).unwrap_err().contains("has no notes"));
        assert!(Reference::new("Work", "Dup", "password").find(&items, &vaults).unwrap_err().contains("use the item id"));
        let by_id = Reference::new("Work", &items[2].id.to_string(), "password");
        assert_eq!(by_id.find(&items, &vaults).unwrap().id, items[2].id);
        assert!(Reference::new("Nope", "x", "password").find(&items, &vaults).is_err());

        let refs: Vec<String> = references_for(&items[0], "Work").iter().map(|r| r.to_string()).collect();
        assert_eq!(refs, ["username", "password", "totp", "API key"].map(|f| format!("lockbox://Work/AWS Console/{f}")));
    }
}
