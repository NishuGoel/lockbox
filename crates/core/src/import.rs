//! Importers: 1Password `.1pux`, and CSV from Chrome, Safari/Passwords, Firefox, Bitwarden, 1Password CSV
//! (columns are matched by header name, so one parser covers them all). Parsing never touches the vault.

use std::io::{Read, Seek};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::vault::{Field, Item, Kind};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Imported {
    /// Source vault name (1Password); `None` = the vault the user picked.
    pub vault: Option<String>,
    pub item: Item,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Parsed {
    pub items: Vec<Imported>,
    /// Human-readable reasons, e.g. "archived: Old router".
    pub skipped: Vec<String>,
}

impl Parsed {
    /// Source vaults with item counts, in export order (1Password only; CSV has none).
    pub fn vaults(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for name in self.items.iter().filter_map(|i| i.vault.as_ref()) {
            match out.iter_mut().find(|(n, _)| n == name) {
                Some((_, c)) => *c += 1,
                None => out.push((name.clone(), 1)),
            }
        }
        out
    }

    /// Keep only items from these source vaults (case-insensitive), e.g. just "Employee".
    pub fn only_vaults(mut self, names: &[String]) -> Self {
        let before = self.items.len();
        self.items.retain(|i| i.vault.as_ref().is_some_and(|v| names.iter().any(|n| n.eq_ignore_ascii_case(v))));
        let dropped = before - self.items.len();
        if dropped > 0 {
            self.skipped.push(format!("{dropped} item{} from other vaults", if dropped == 1 { "" } else { "s" }));
        }
        self
    }
}

pub fn parse_file(path: &Path) -> Result<Parsed> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    match ext.as_str() {
        "1pux" => parse_1pux(std::fs::File::open(path)?),
        "csv" => parse_csv(&std::fs::read(path)?),
        _ => Err(Error::Import("choose a .1pux (1Password) or .csv (Chrome, Safari, Firefox, Bitwarden) export".into())),
    }
}

fn opt(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    opt(rest.split(['/', '?', '#']).next().unwrap_or("").trim_start_matches("www."))
}

// ---------- CSV ----------

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Title,
    Url,
    Username,
    Password,
    Notes,
    Totp,
    Folder,
    Type,
}

fn col(header: &str) -> Option<Col> {
    Some(match header.trim().trim_start_matches('\u{feff}').to_lowercase().as_str() {
        "title" | "name" => Col::Title,
        "url" | "login_uri" | "website" | "uri" | "web site" => Col::Url,
        "username" | "login_username" | "login" | "user name" => Col::Username,
        "password" | "login_password" => Col::Password,
        "notes" | "note" | "comments" | "extra" => Col::Notes,
        "otpauth" | "totp" | "login_totp" | "otp" | "one-time password" => Col::Totp,
        "folder" | "grouping" => Col::Folder,
        "type" => Col::Type,
        _ => return None,
    })
}

pub fn parse_csv(data: &[u8]) -> Result<Parsed> {
    let bad = |e: csv::Error| Error::Import(format!("couldn't read the CSV: {e}"));
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(data);
    let cols: Vec<Option<Col>> = rdr.headers().map_err(bad)?.iter().map(col).collect();
    if !cols.contains(&Some(Col::Password)) {
        return Err(Error::Import("this CSV has no password column; is it a password export?".into()));
    }
    let mut out = Parsed::default();
    for (n, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(bad)?;
        let get = |c: Col| cols.iter().position(|x| *x == Some(c)).and_then(|i| rec.get(i)).and_then(opt);
        let (url, username, password) = (get(Col::Url), get(Col::Username), get(Col::Password));
        let notes = get(Col::Notes);
        if url.is_none() && username.is_none() && password.is_none() && notes.is_none() {
            out.skipped.push(format!("line {}: empty", rec.position().map_or(n as u64 + 2, |p| p.line())));
            continue;
        }
        let is_note = get(Col::Type).is_some_and(|t| t.eq_ignore_ascii_case("note"));
        let title = get(Col::Title).or_else(|| url.as_deref().and_then(host)).unwrap_or_else(|| "Untitled".into());
        out.items.push(Imported {
            vault: None,
            item: Item {
                kind: if is_note { Kind::SecureNote } else { Kind::Login },
                title,
                username,
                password,
                urls: url.into_iter().collect(),
                notes,
                totp: get(Col::Totp),
                tags: get(Col::Folder).into_iter().collect(),
                ..Default::default()
            },
        });
    }
    Ok(out)
}

// ---------- 1Password 1PUX ----------

pub fn parse_1pux(reader: impl Read + Seek) -> Result<Parsed> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|_| Error::Import("not a valid .1pux file".into()))?;
    let mut json = String::new();
    zip.by_name("export.data")
        .map_err(|_| Error::Import("no export.data inside this .1pux".into()))?
        .read_to_string(&mut json)?;
    parse_1pux_json(&json)
}

fn kind_for(category: &str) -> Kind {
    match category {
        "002" => Kind::Card,
        "003" => Kind::SecureNote,
        "004" => Kind::Identity,
        "112" => Kind::ApiCredential,
        _ => Kind::Login,
    }
}

/// A section field's `value` is a one-key object: {"string": ..}, {"concealed": ..}, {"totp": ..},
/// {"email": {"email_address": ..}}, {"date": 1614298956}, {"address": {...}}, … Returns (text, concealed, is_totp).
fn field_value(v: &Value) -> Option<(String, bool, bool)> {
    let (kind, inner) = v.as_object()?.iter().next()?;
    let text = match inner {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Object(o) => {
            if let Some(Value::String(e)) = o.get("email_address") {
                e.clone()
            } else if let Some(Value::String(k)) = o.get("privateKey") {
                k.clone()
            } else {
                o.values().filter_map(|x| x.as_str()).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", ")
            }
        }
        _ => return None,
    };
    if text.is_empty() || kind == "file" {
        return None;
    }
    let concealed = matches!(kind.as_str(), "concealed" | "creditCardNumber" | "sshKey" | "totp");
    Some((text, concealed, kind == "totp"))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn parse_1pux_json(json: &str) -> Result<Parsed> {
    let root: Value = serde_json::from_str(json).map_err(|e| Error::Import(format!("export.data isn't valid JSON: {e}")))?;
    let mut out = Parsed::default();
    let arr = |v: &Value, k: &str| v.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    for account in arr(&root, "accounts") {
        for vault in arr(&account, "vaults") {
            let vault_name = opt(s(vault.get("attrs").unwrap_or(&vault), "name"));
            for it in arr(&vault, "items") {
                let (ov, det) = (it.get("overview").cloned().unwrap_or_default(), it.get("details").cloned().unwrap_or_default());
                let title = opt(s(&ov, "title")).unwrap_or_else(|| "Untitled".into());
                if s(&it, "state") == "archived" {
                    out.skipped.push(format!("archived: {title}"));
                    continue;
                }
                if det.get("documentAttributes").is_some() {
                    out.skipped.push(format!("document (files aren't supported yet): {title}"));
                    continue;
                }
                let mut item = Item {
                    kind: kind_for(s(&it, "categoryUuid")),
                    title,
                    notes: opt(s(&det, "notesPlain")),
                    favorite: it.get("favIndex").and_then(Value::as_i64).unwrap_or(0) > 0,
                    tags: arr(&ov, "tags").iter().filter_map(|t| t.as_str().and_then(opt)).collect(),
                    ..Default::default()
                };
                item.urls = arr(&ov, "urls").iter().filter_map(|u| opt(s(u, "url"))).collect();
                if let Some(u) = opt(s(&ov, "url")).filter(|u| !item.urls.contains(u)) {
                    item.urls.insert(0, u);
                }
                for f in arr(&det, "loginFields") {
                    let v = opt(s(&f, "value"));
                    match s(&f, "designation") {
                        "username" => item.username = item.username.take().or(v),
                        "password" => item.password = item.password.take().or(v),
                        _ => {}
                    }
                }
                if item.password.is_none() {
                    item.password = opt(s(&det, "password")); // "Password" category keeps it here
                }
                for sec in arr(&det, "sections") {
                    for f in arr(&sec, "fields") {
                        let Some((text, concealed, is_totp)) = f.get("value").and_then(field_value) else { continue };
                        if is_totp && item.totp.is_none() {
                            item.totp = Some(text);
                            continue;
                        }
                        let name = opt(s(&f, "title")).or_else(|| opt(s(&sec, "title"))).unwrap_or_else(|| "field".into());
                        item.fields.push(Field { name, value: text, concealed });
                    }
                }
                out.items.push(Imported { vault: vault_name.clone(), item });
            }
        }
    }
    if out.items.is_empty() && out.skipped.is_empty() {
        return Err(Error::Import("no items found in this export".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\ngithub.com,https://github.com/login,me@example.com,hunter2,\n,https://accounts.example.org/,,s3cret,\"multi\nline, with comma\"\n,,,,\n";
        let p = parse_csv(csv.as_bytes()).unwrap();
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.items[0].item.title, "github.com");
        assert_eq!(p.items[0].item.password.as_deref(), Some("hunter2"));
        assert_eq!(p.items[0].item.notes, None);
        assert_eq!(p.items[1].item.title, "accounts.example.org", "title falls back to host");
        assert_eq!(p.items[1].item.notes.as_deref(), Some("multi\nline, with comma"));
        assert_eq!(p.skipped, vec!["line 5: empty"], "multi-line notes shift line numbers");
    }

    #[test]
    fn safari_csv_with_otp_and_bom() {
        let csv = "\u{feff}Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com/,me,pw1,,otpauth://totp/GitHub:me?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub\n";
        let i = &parse_csv(csv.as_bytes()).unwrap().items[0].item;
        assert_eq!((i.title.as_str(), i.username.as_deref()), ("GitHub", Some("me")));
        assert!(i.totp.as_deref().unwrap().starts_with("otpauth://"));
        crate::totp::parse(i.totp.as_deref().unwrap()).unwrap();
    }

    #[test]
    fn firefox_and_bitwarden_csv() {
        let ff = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\"https://www.mozilla.org\",\"fox\",\"pw\",,\"https://www.mozilla.org\",\"{x}\"\n";
        let i = &parse_csv(ff.as_bytes()).unwrap().items[0].item;
        assert_eq!((i.title.as_str(), i.username.as_deref()), ("mozilla.org", Some("fox")));

        let bw = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Jira,,,,https://jira.example,me,pw,JBSWY3DPEHPK3PXP\n,,note,Recovery codes,abc def,,,,,,\n";
        let p = parse_csv(bw.as_bytes()).unwrap();
        assert_eq!(p.items[0].item.tags, vec!["Work"]);
        assert_eq!(p.items[0].item.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!((p.items[1].item.kind, p.items[1].item.notes.as_deref()), (Kind::SecureNote, Some("abc def")));
    }

    #[test]
    fn rejects_non_password_csv() {
        assert!(parse_csv(b"date,amount\n2026-01-01,5\n").is_err());
    }

    // Based on the example in 1Password's 1PUX format docs, plus the other shapes we map.
    const EXPORT: &str = r#"{"accounts":[{"attrs":{"name":"Me"},"vaults":[
      {"attrs":{"uuid":"v1","name":"Private"},"items":[
        {"uuid":"a","favIndex":1,"state":"active","categoryUuid":"001",
         "overview":{"title":"Dropbox","url":"https://www.dropbox.com/","urls":[{"label":"","url":"https://www.dropbox.com/"}],"tags":["cloud"]},
         "details":{"loginFields":[
             {"value":"me@example.com","name":"email","fieldType":"E","designation":"username"},
             {"value":"most-secure-password-ever!","name":"password","fieldType":"P","designation":"password"}],
           "notesPlain":"This is a note. *bold*!",
           "sections":[{"title":"Security","fields":[
             {"title":"PIN","value":{"concealed":"12345"}},
             {"title":"one-time password","value":{"totp":"otpauth://totp/Dropbox?secret=GEZDGNBVGY3TQOJQ"}},
             {"title":"recovery email","value":{"email":{"email_address":"backup@example.com","provider":null}}},
             {"title":"since","value":{"date":1614298956}},
             {"title":"attachment","value":{"file":{"fileName":"x.pdf"}}}]}]}},
        {"uuid":"b","favIndex":0,"state":"archived","categoryUuid":"001","overview":{"title":"Old router"},"details":{}},
        {"uuid":"c","state":"active","categoryUuid":"006","overview":{"title":"Passport scan"},"details":{"documentAttributes":{"fileName":"p.pdf"}}}]},
      {"attrs":{"uuid":"v2","name":"Work"},"items":[
        {"uuid":"d","state":"active","categoryUuid":"003","overview":{"title":"Wi-Fi guest"},"details":{"notesPlain":"guest / letmein"}},
        {"uuid":"e","state":"active","categoryUuid":"005","overview":{"title":"Router admin"},"details":{"password":"r0uter!"}}]}]}]}"#;

    #[test]
    fn onepux_json() {
        let p = parse_1pux_json(EXPORT).unwrap();
        assert_eq!(p.items.len(), 3);
        assert_eq!(p.skipped, vec!["archived: Old router", "document (files aren't supported yet): Passport scan"]);
        let d = &p.items[0];
        assert_eq!(d.vault.as_deref(), Some("Private"));
        assert_eq!((d.item.username.as_deref(), d.item.password.as_deref()), (Some("me@example.com"), Some("most-secure-password-ever!")));
        assert_eq!(d.item.urls, vec!["https://www.dropbox.com/"]);
        assert!(d.item.favorite && d.item.tags == vec!["cloud"]);
        assert!(d.item.totp.as_deref().unwrap().contains("GEZDGNBVGY3TQOJQ"));
        let f: Vec<_> = d.item.fields.iter().map(|f| (f.name.as_str(), f.value.as_str(), f.concealed)).collect();
        assert_eq!(f, vec![("PIN", "12345", true), ("recovery email", "backup@example.com", false), ("since", "1614298956", false)]);
        assert_eq!((p.items[1].item.kind, p.items[1].vault.as_deref()), (Kind::SecureNote, Some("Work")));
        assert_eq!(p.items[2].item.password.as_deref(), Some("r0uter!"));

        assert_eq!(p.vaults(), vec![("Private".to_string(), 1), ("Work".to_string(), 2)]);
        let only = parse_1pux_json(EXPORT).unwrap().only_vaults(&["work".into()]);
        assert_eq!(only.items.len(), 2);
        assert!(only.items.iter().all(|i| i.vault.as_deref() == Some("Work")));
        assert_eq!(only.skipped.last().unwrap(), "1 item from other vaults");
    }

    #[test]
    fn onepux_zip() {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut z = zip::ZipWriter::new(&mut buf);
        z.start_file("export.attributes", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(b"{\"version\":3}").unwrap();
        z.start_file("export.data", zip::write::SimpleFileOptions::default()).unwrap();
        z.write_all(EXPORT.as_bytes()).unwrap();
        z.finish().unwrap();
        buf.set_position(0);
        assert_eq!(parse_1pux(buf).unwrap().items.len(), 3);
        assert!(parse_1pux(std::io::Cursor::new(b"not a zip".to_vec())).is_err());
    }
}
