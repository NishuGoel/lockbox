//! Browser connector (Chrome native messaging) for Dia and Chrome. The browser starts the lockbox
//! app binary with the extension's origin as argv[1] and exchanges length-prefixed JSON on stdio.
//! Every request goes through the unlock agent, so the browser only works while lockbox is unlocked.
//! Secrets never leave for a page whose host doesn't match the item (`site_matches`).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use lockbox_core::generator::{self, PasswordOpts};
use lockbox_core::{Item, ItemRecord, Vault, display_host, site_matches, totp};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::agent::{self, Request, Response};

pub const HOST_NAME: &str = "dev.lockbox.connector";
/// Fixed by the public `key` in apps/extension/manifest.json.
pub const EXTENSION_ID: &str = "ndlmdmhhecdngfpeehboklmiehkgbnpe";

pub fn is_extension_origin(arg: &str) -> bool {
    arg.starts_with("chrome-extension://")
}

/// Writes the connector manifest for Dia and Chrome (whichever are installed). Idempotent.
pub fn install_manifests(exe: &Path) -> Vec<PathBuf> {
    let support = std::env::home_dir().unwrap_or_default().join("Library/Application Support");
    let manifest = json!({
        "name": HOST_NAME,
        "description": "lockbox password manager",
        "path": exe,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    let mut written = Vec::new();
    for profile in ["Google/Chrome", "Dia/User Data"] {
        let base = support.join(profile);
        if !base.is_dir() {
            continue;
        }
        let dir = base.join("NativeMessagingHosts");
        let file = dir.join(format!("{HOST_NAME}.json"));
        if std::fs::create_dir_all(&dir).is_ok() && std::fs::write(&file, serde_json::to_vec_pretty(&manifest).unwrap()).is_ok() {
            written.push(file);
        }
    }
    written
}

fn read_msg(r: &mut impl Read) -> Option<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).ok()?;
    let n = u32::from_ne_bytes(len) as usize;
    if n > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

fn write_msg(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(v)?;
    w.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

/// The connector loop. Chrome checks `allowed_origins` too; this is the second lock on the door.
pub fn run(origin: &str, db: &Path, sock: &Path) {
    let (mut stdin, mut stdout) = (std::io::stdin().lock(), std::io::stdout().lock());
    if origin != format!("chrome-extension://{EXTENSION_ID}/") {
        let _ = write_msg(&mut stdout, &json!({ "error": "unknown extension" }));
        return;
    }
    let call = |req: Request| -> Response {
        if !agent::is_running(sock) {
            return Err(if db.exists() { "locked" } else { "no_vault" }.into());
        }
        agent::call(sock, &req)
    };
    while let Some(msg) = read_msg(&mut stdin) {
        let reply = handle(&msg, &call).unwrap_or_else(|e| json!({ "error": e }));
        if write_msg(&mut stdout, &reply).is_err() {
            break;
        }
    }
}

type Call<'a> = &'a dyn Fn(Request) -> Response;

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn items(call: Call) -> Result<Vec<ItemRecord>, String> {
    serde_json::from_value(call(Request::Items)?).map_err(|e| e.to_string())
}

fn for_site(r: &ItemRecord, url: &str) -> bool {
    r.item.urls.iter().any(|u| site_matches(u, url))
}

/// What the popup may show: never a secret.
fn summary(r: &ItemRecord, url: &str) -> Value {
    json!({
        "id": r.id, "title": r.item.title, "username": r.item.username,
        "host": r.item.urls.first().and_then(|u| display_host(u)),
        "hasTotp": r.item.totp.is_some(), "hasPassword": r.item.password.is_some(), "hasPasskey": r.item.passkey.is_some(),
        "matches": for_site(r, url),
    })
}

fn find(call: Call, id: &str) -> Result<ItemRecord, String> {
    let id = Uuid::parse_str(id).map_err(|_| "bad id")?;
    items(call)?.into_iter().find(|r| r.id == id).ok_or_else(|| "item not found".into())
}

fn opt_str(v: &str) -> Option<String> {
    (!v.trim().is_empty()).then(|| v.trim().to_string())
}

fn same_user(a: Option<&str>, b: &str) -> bool {
    a.unwrap_or("").trim().eq_ignore_ascii_case(b.trim())
}

pub fn handle(msg: &Value, call: Call) -> Result<Value, String> {
    let url = s(msg, "url");
    match s(msg, "cmd") {
        "status" => Ok(match call(Request::Vaults) {
            Ok(_) => json!({ "state": "unlocked" }),
            Err(e) => json!({ "state": e }),
        }),
        "match" => {
            let mut hits: Vec<ItemRecord> = items(call)?.into_iter().filter(|r| for_site(r, url)).collect();
            hits.sort_by_key(|r| r.item.title.to_lowercase());
            Ok(json!({ "items": hits.iter().map(|r| summary(r, url)).collect::<Vec<_>>() }))
        }
        "search" => {
            let q = s(msg, "q");
            let mut hits: Vec<ItemRecord> = items(call)?.into_iter().filter(|r| r.item.matches(q)).collect();
            hits.sort_by_key(|r| (!for_site(r, url), r.item.title.to_lowercase()));
            hits.truncate(20);
            Ok(json!({ "items": hits.iter().map(|r| summary(r, url)).collect::<Vec<_>>() }))
        }
        "fill" => {
            let r = find(call, s(msg, "id"))?;
            if !for_site(&r, url) {
                return Err(format!("{} isn't saved for this site", r.item.title));
            }
            let code = r.item.totp.as_deref().and_then(|t| totp::current(t).ok()).map(|c| c.code);
            Ok(json!({ "username": r.item.username, "password": r.item.password, "totp": code }))
        }
        "copy" => {
            let r = find(call, s(msg, "id"))?;
            let field = s(msg, "field");
            let v = if field == "totp" { r.item.totp.as_deref().and_then(|t| totp::current(t).ok()).map(|c| c.code) } else { r.item.field(field) };
            let n = crate::mac::copy_concealed(&v.ok_or_else(|| format!("{} has no {field}", r.item.title))?);
            // the connector exits right away, so a detached copy of this binary clears the clipboard later
            if let Ok(exe) = std::env::current_exe() {
                let _ = std::process::Command::new(exe).args(["--clear-clipboard", &n.to_string()])
                    .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
            }
            Ok(json!({ "ok": true }))
        }
        "check" => {
            let (user, pw) = (s(msg, "username"), s(msg, "password"));
            if pw.is_empty() || display_host(url).is_none() {
                return Ok(json!({ "status": "ignore" }));
            }
            let all = match items(call) {
                Ok(v) => v,
                Err(e) => return Ok(json!({ "status": e, "host": display_host(url) })),
            };
            let site: Vec<&ItemRecord> = all.iter().filter(|r| for_site(r, url)).collect();
            if site.iter().any(|r| r.item.password.as_deref() == Some(pw) && (user.is_empty() || same_user(r.item.username.as_deref(), user))) {
                return Ok(json!({ "status": "same" }));
            }
            Ok(match site.iter().find(|r| same_user(r.item.username.as_deref(), user)) {
                Some(r) => json!({ "status": "changed", "id": r.id, "title": r.item.title, "host": display_host(url) }),
                None => json!({ "status": "new", "title": display_host(url), "host": display_host(url) }),
            })
        }
        "save" => {
            let (user, pw) = (s(msg, "username"), s(msg, "password"));
            if pw.is_empty() {
                return Err("nothing to save".into());
            }
            let host = display_host(url).ok_or("this page has no website address")?;
            if let Some(id) = msg.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()) {
                let mut r = find(call, id)?;
                if !for_site(&r, url) {
                    return Err(format!("{} isn't saved for this site", r.item.title));
                }
                r.item.password = Some(pw.to_string());
                if r.item.username.is_none() && !user.is_empty() {
                    r.item.username = Some(user.to_string());
                }
                call(Request::Update { id: r.id, item: r.item.clone() })?;
                return Ok(json!({ "action": "updated", "id": r.id, "title": r.item.title }));
            }
            let vaults: Vec<Vault> = serde_json::from_value(call(Request::Vaults)?).map_err(|e| e.to_string())?;
            let vault = vaults.iter().find(|v| v.name.eq_ignore_ascii_case("Personal")).or(vaults.first()).ok_or("no vault")?;
            let scheme = url.split_once("://").map_or("https", |(sch, _)| sch);
            let item = Item {
                title: host.clone(),
                username: (!user.is_empty()).then(|| user.to_string()),
                password: Some(pw.to_string()),
                urls: vec![format!("{scheme}://{host}")],
                ..Default::default()
            };
            let id: Uuid = serde_json::from_value(call(Request::Add { vault: vault.id, item })?).map_err(|e| e.to_string())?;
            Ok(json!({ "action": "added", "id": id, "title": host, "vault": vault.name }))
        }
        "generate" => {
            let length = msg.get("length").and_then(Value::as_u64).unwrap_or(20) as usize;
            generator::password(PasswordOpts { length, ..Default::default() }).map(|p| json!({ "password": p })).map_err(|e| e.to_string())
        }
        "pk_list" => {
            let rp = s(msg, "rpId");
            if !crate::webauthn::rp_id_ok(rp, url) {
                return Ok(json!({ "items": [] }));
            }
            let allow: Vec<&str> = msg.get("allow").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            let hits: Vec<Value> = items(call)?
                .iter()
                .filter_map(|r| r.item.passkey.as_ref().map(|p| (r, p)))
                .filter(|(_, p)| p.rp_id.eq_ignore_ascii_case(rp) && (allow.is_empty() || allow.contains(&p.credential_id.as_str())))
                .map(|(r, p)| json!({ "id": r.id, "title": r.item.title, "userName": p.user_name, "displayName": p.user_display_name }))
                .collect();
            Ok(json!({ "items": hits }))
        }
        "pk_create" => {
            let rp = s(msg, "rpId");
            let algs: Vec<i64> = msg.get("algs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
            if !algs.is_empty() && !algs.contains(&crate::webauthn::ES256) {
                return Ok(json!({ "fallback": true }));
            }
            let all = items(call)?;
            let exclude: Vec<&str> = msg.get("exclude").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            if all.iter().filter_map(|r| r.item.passkey.as_ref()).any(|p| p.rp_id.eq_ignore_ascii_case(rp) && exclude.contains(&p.credential_id.as_str())) {
                return Err("InvalidStateError: you already have a passkey for this account in lockbox".into());
            }
            let req = crate::webauthn::Request { page_url: url, rp_id: rp, challenge: s(msg, "challenge") };
            let (user, display) = (s(msg, "userName"), s(msg, "displayName"));
            let (pk, resp) = crate::webauthn::create(&req, s(msg, "userId"), user, display)?;
            let site_url = format!("https://{}", pk.rp_id);
            // same account re-registering → replace its passkey; else attach to the matching login (like 1Password)
            let same_account = |r: &&ItemRecord| r.item.passkey.as_ref().is_some_and(|p| p.rp_id == pk.rp_id && p.user_handle == pk.user_handle);
            let existing = all.iter().find(same_account).or_else(|| all.iter().find(|r| r.item.passkey.is_none() && for_site(r, &site_url) && same_user(r.item.username.as_deref(), user)));
            let title = match existing {
                Some(r) => {
                    let mut item = r.item.clone();
                    item.passkey = Some(pk);
                    call(Request::Update { id: r.id, item })?;
                    r.item.title.clone()
                }
                None => {
                    let vaults: Vec<Vault> = serde_json::from_value(call(Request::Vaults)?).map_err(|e| e.to_string())?;
                    let vault = vaults.iter().find(|v| v.name.eq_ignore_ascii_case("Personal")).or(vaults.first()).ok_or("no vault")?;
                    let title = opt_str(s(msg, "rpName")).unwrap_or_else(|| pk.rp_id.clone());
                    let item = Item { title: title.clone(), username: opt_str(user), urls: vec![site_url], passkey: Some(pk), ..Default::default() };
                    call(Request::Add { vault: vault.id, item })?;
                    title
                }
            };
            Ok(json!({ "response": resp, "title": title }))
        }
        "pk_get" => {
            let r = find(call, s(msg, "id"))?;
            let pk = r.item.passkey.as_ref().ok_or("no passkey on this item")?;
            let req = crate::webauthn::Request { page_url: url, rp_id: s(msg, "rpId"), challenge: s(msg, "challenge") };
            Ok(json!({ "response": crate::webauthn::assert(&req, pk)? }))
        }
        "open_app" => {
            let _ = std::process::Command::new("open").args(["-b", "dev.lockbox.desktop"]).spawn();
            Ok(json!({ "ok": true }))
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockbox_core::{KdfParams, Lockbox};

    fn vault() -> Lockbox {
        let p = std::env::temp_dir().join(format!("lb-native-{}.db", Uuid::new_v4()));
        let (lb, _) = Lockbox::create(&p, "pw", KdfParams { m_kib: 64, t: 1, p: 1 }).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        lb.add_item(&v, Item { title: "GitHub".into(), username: Some("me@example.com".into()), password: Some("old-pw".into()), urls: vec!["https://github.com/login".into()], totp: Some("GEZDGNBVGY3TQOJQ".into()), ..Default::default() }).unwrap();
        lb.add_item(&v, Item { title: "Bank".into(), username: Some("me".into()), password: Some("bank-pw".into()), urls: vec!["https://bank.example".into()], ..Default::default() }).unwrap();
        lb
    }

    fn ask(lb: &Lockbox, msg: Value) -> Result<Value, String> {
        handle(&msg, &|r| agent::handle(lb, r))
    }

    #[test]
    fn match_and_fill_respect_the_site() {
        let lb = vault();
        let m = ask(&lb, json!({ "cmd": "match", "url": "https://github.com/session" })).unwrap();
        let items = m["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0].get("password").is_none(), "match never includes secrets");
        let id = items[0]["id"].as_str().unwrap().to_string();

        let f = ask(&lb, json!({ "cmd": "fill", "id": id, "url": "https://github.com/session" })).unwrap();
        assert_eq!((f["username"].as_str(), f["password"].as_str()), (Some("me@example.com"), Some("old-pw")));
        assert_eq!(f["totp"].as_str().unwrap().len(), 6);

        let phish = ask(&lb, json!({ "cmd": "fill", "id": id, "url": "https://github.com.evil.io/login" }));
        assert!(phish.unwrap_err().contains("isn't saved for this site"));

        let search = ask(&lb, json!({ "cmd": "search", "q": "", "url": "https://bank.example/" })).unwrap();
        assert_eq!(search["items"][0]["title"], "Bank", "site matches sort first");
    }

    #[test]
    fn check_and_save_cover_new_changed_same() {
        let lb = vault();
        let gh = |pw: &str, user: &str| json!({ "cmd": "check", "url": "https://github.com/login", "username": user, "password": pw });
        assert_eq!(ask(&lb, gh("old-pw", "me@example.com")).unwrap()["status"], "same");
        assert_eq!(ask(&lb, gh("old-pw", "")).unwrap()["status"], "same", "password-only step of a 2-step login");
        let changed = ask(&lb, gh("new-pw", "ME@example.com ")).unwrap();
        assert_eq!(changed["status"], "changed");
        assert_eq!(ask(&lb, gh("x", "someone-else")).unwrap()["status"], "new");
        assert_eq!(ask(&lb, json!({ "cmd": "check", "url": "https://github.com", "password": "" })).unwrap()["status"], "ignore");

        let up = ask(&lb, json!({ "cmd": "save", "url": "https://github.com/login", "username": "me@example.com", "password": "new-pw", "id": changed["id"] })).unwrap();
        assert_eq!(up["action"], "updated");
        let rec = lb.search("github").unwrap().remove(0);
        assert_eq!(rec.item.password.as_deref(), Some("new-pw"));
        assert_eq!(rec.item.password_history[0].password, "old-pw");

        let bad = ask(&lb, json!({ "cmd": "save", "url": "https://evil.io", "password": "p", "id": changed["id"] }));
        assert!(bad.is_err(), "can't overwrite an item from a different site");

        let add = ask(&lb, json!({ "cmd": "save", "url": "https://www.figma.com/login?next=/", "username": "me", "password": "fig" })).unwrap();
        assert_eq!((add["action"].as_str(), add["title"].as_str(), add["vault"].as_str()), (Some("added"), Some("figma.com"), Some("Personal")));
        assert_eq!(lb.search("figma").unwrap()[0].item.urls, vec!["https://figma.com"]);
        assert_eq!(ask(&lb, json!({ "cmd": "check", "url": "https://figma.com/x", "username": "me", "password": "fig" })).unwrap()["status"], "same");
    }

    #[test]
    fn passkeys_attach_list_and_sign() {
        let lb = vault();
        let ch = crate::webauthn::b64(b"challenge-1");
        let make = |user: &str, uid: &str| ask(&lb, json!({ "cmd": "pk_create", "url": "https://github.com/settings", "rpId": "github.com", "rpName": "GitHub",
            "userId": crate::webauthn::b64(uid.as_bytes()), "userName": user, "displayName": user, "challenge": ch, "algs": [-7, -257] }));
        let c = make("me@example.com", "u1").unwrap();
        assert_eq!(c["title"], "GitHub", "attached to the existing GitHub login");
        assert_eq!(lb.items(None).unwrap().len(), 2);
        let other = make("work@example.com", "u2").unwrap();
        assert_eq!(other["title"], "GitHub");
        assert_eq!(lb.items(None).unwrap().len(), 3, "a second account gets its own item");
        let c = make("me@example.com", "u1").unwrap();
        assert_eq!(lb.items(None).unwrap().len(), 3, "re-registering the same account replaces its passkey");

        let listed = ask(&lb, json!({ "cmd": "pk_list", "url": "https://github.com/login", "rpId": "github.com" })).unwrap();
        assert_eq!(listed["items"].as_array().unwrap().len(), 2);
        assert!(listed.to_string().find("private").is_none(), "listing never includes keys");
        let only = ask(&lb, json!({ "cmd": "pk_list", "url": "https://github.com/login", "rpId": "github.com", "allow": [c["response"]["id"]] })).unwrap();
        assert_eq!(only["items"].as_array().unwrap().len(), 1);
        assert_eq!(ask(&lb, json!({ "cmd": "pk_list", "url": "https://evil.io/", "rpId": "github.com" })).unwrap()["items"].as_array().unwrap().len(), 0);

        let id = only["items"][0]["id"].as_str().unwrap();
        let got = ask(&lb, json!({ "cmd": "pk_get", "id": id, "url": "https://github.com/login", "rpId": "github.com", "challenge": ch })).unwrap();
        assert!(got["response"]["signature"].as_str().unwrap().len() > 60);
        assert!(ask(&lb, json!({ "cmd": "pk_get", "id": id, "url": "https://evil.io/", "rpId": "github.com", "challenge": ch })).is_err());

        let dup = ask(&lb, json!({ "cmd": "pk_create", "url": "https://github.com/", "rpId": "github.com", "userId": "dTE", "userName": "x", "challenge": ch, "exclude": [c["response"]["id"]] }));
        assert!(dup.unwrap_err().starts_with("InvalidStateError"));
        let rsa_only = ask(&lb, json!({ "cmd": "pk_create", "url": "https://github.com/", "rpId": "github.com", "userId": "dTE", "userName": "x", "challenge": ch, "algs": [-257] })).unwrap();
        assert_eq!(rsa_only["fallback"], true);
    }

    #[test]
    fn locked_and_framing() {
        let locked = |_: Request| -> Response { Err("locked".into()) };
        assert_eq!(handle(&json!({ "cmd": "status" }), &locked).unwrap()["state"], "locked");
        assert_eq!(handle(&json!({ "cmd": "check", "url": "https://a.com", "password": "p" }), &locked).unwrap()["status"], "locked");

        let mut buf = Vec::new();
        write_msg(&mut buf, &json!({ "cmd": "status" })).unwrap();
        assert_eq!(read_msg(&mut buf.as_slice()).unwrap()["cmd"], "status");
        assert!(read_msg(&mut [0xff, 0xff, 0xff, 0x7f].as_slice()).is_none(), "oversized frames are rejected");
    }
}
