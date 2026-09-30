mod agent;
mod mac;

use std::io::{BufRead, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use agent::Request;
use clap::{Parser, Subcommand};
use lockbox_core::generator::{self, PasswordOpts};
use lockbox_core::{Item, ItemRecord, KdfParams, Kind, Lockbox, SecretKey, Vault, totp};
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

type R<T> = Result<T, Box<dyn std::error::Error>>;

const CLEAR_SECS: u64 = 90;

#[derive(Parser)]
#[command(name = "lockbox", version, about = "End-to-end encrypted password manager")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new lockbox and Secret Key
    Init,
    /// Unlock and keep unlocked in the background until idle
    Unlock {
        /// idle minutes before auto-lock
        #[arg(long, default_value_t = 10)]
        minutes: u64,
    },
    /// Lock now
    Lock,
    /// Show lock state and paths
    Status,
    /// List vaults, or `vaults add <name>`
    Vaults {
        #[command(subcommand)]
        cmd: Option<VaultCmd>,
    },
    /// List items, optionally filtered by a search query
    Ls {
        query: Option<String>,
        #[arg(long)]
        vault: Option<String>,
    },
    /// Show an item, or print one field (password, username, url, notes, totp, json, or a custom field)
    Get {
        query: String,
        #[arg(short, long)]
        field: Option<String>,
    },
    /// Copy a field to the clipboard (hidden from clipboard managers, cleared after 90s)
    Copy {
        query: String,
        #[arg(short, long, default_value = "password")]
        field: String,
    },
    /// Show the current 2FA code
    Totp {
        query: String,
        #[arg(short, long)]
        copy: bool,
    },
    /// Add an item (prompts for the password; leave empty to generate one)
    Add {
        title: String,
        #[command(flatten)]
        fields: ItemArgs,
        #[arg(long)]
        vault: Option<String>,
        /// secure note instead of login
        #[arg(long)]
        note: bool,
    },
    /// Edit an item
    Edit {
        query: String,
        #[arg(long)]
        title: Option<String>,
        #[command(flatten)]
        fields: ItemArgs,
        /// prompt for a new password
        #[arg(long)]
        password: bool,
    },
    /// Delete an item
    Rm {
        query: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Generate a password or PIN
    Gen {
        #[arg(short, long, default_value_t = 24)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
        /// skip 0/O, 1/l/I
        #[arg(long)]
        easy_type: bool,
        /// generate a PIN of this many digits
        #[arg(long)]
        pin: Option<usize>,
        #[arg(short, long)]
        copy: bool,
    },
    #[command(name = "__agent", hide = true)]
    Agent { minutes: u64 },
    #[command(name = "__clear-clipboard", hide = true)]
    ClearClipboard { change_count: isize },
}

#[derive(Subcommand)]
enum VaultCmd {
    Add { name: String },
}

#[derive(clap::Args)]
struct ItemArgs {
    #[arg(short, long)]
    username: Option<String>,
    #[arg(long)]
    url: Vec<String>,
    /// otpauth:// URI or base32 secret
    #[arg(long)]
    totp: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long)]
    tag: Vec<String>,
    /// generate a new password
    #[arg(short, long)]
    generate: bool,
}

struct Paths {
    db: PathBuf,
    sock: PathBuf,
}

impl Paths {
    fn new() -> R<Self> {
        let dir = match std::env::var_os("LOCKBOX_DIR") {
            Some(d) => PathBuf::from(d),
            None => std::env::home_dir().ok_or("no home directory")?.join("Library/Application Support/lockbox"),
        };
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        Ok(Self { db: dir.join("lockbox.db"), sock: dir.join("agent.sock") })
    }

    /// Keychain account: one Secret Key per lockbox file.
    fn account(&self) -> String {
        self.db.to_string_lossy().into_owned()
    }
}

enum Session {
    Agent(PathBuf),
    Direct(Lockbox),
}

impl Session {
    fn open(p: &Paths) -> R<Self> {
        if agent::is_running(&p.sock) {
            return Ok(Self::Agent(p.sock.clone()));
        }
        Ok(Self::Direct(unlock_interactive(p)?.0))
    }

    fn call<T: DeserializeOwned>(&self, req: Request) -> R<T> {
        let v = match self {
            Self::Agent(sock) => agent::call(sock, &req),
            Self::Direct(lb) => agent::handle(lb, req),
        }?;
        Ok(serde_json::from_value(v)?)
    }

    fn items(&self) -> R<Vec<ItemRecord>> {
        self.call(Request::Items)
    }

    fn find(&self, query: &str) -> R<ItemRecord> {
        Ok(resolve(&self.items()?, query)?.clone())
    }

    fn vault(&self, name: Option<&str>) -> R<Vault> {
        let vaults: Vec<Vault> = self.call(Request::Vaults)?;
        let want = name.unwrap_or("Personal");
        vaults
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(want))
            .or(if name.is_none() { vaults.first() } else { None })
            .cloned()
            .ok_or_else(|| format!("no vault named '{want}'").into())
    }
}

fn prompt_hidden(label: &str) -> R<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(label)?))
}

fn unlock_interactive(p: &Paths) -> R<(Lockbox, Zeroizing<String>, SecretKey)> {
    if !p.db.exists() {
        return Err("no lockbox yet, run `lockbox init`".into());
    }
    let stored = mac::load_secret_key(&p.account())?;
    let sk = match &stored {
        Some(s) => SecretKey::parse(s)?,
        None => SecretKey::parse(&prompt_hidden("Secret Key (from your Emergency Kit): ")?)?,
    };
    let pw = prompt_hidden("Master password: ")?;
    let lb = Lockbox::unlock(&p.db, &pw, &sk)?;
    if stored.is_none() {
        mac::save_secret_key(&p.account(), &sk.to_display())?;
    }
    Ok((lb, pw, sk))
}

fn resolve<'a>(items: &'a [ItemRecord], q: &str) -> Result<&'a ItemRecord, String> {
    if let Ok(id) = Uuid::parse_str(q) {
        return items.iter().find(|r| r.id == id).ok_or_else(|| "no item with that id".into());
    }
    let exact: Vec<_> = items.iter().filter(|r| r.item.title.eq_ignore_ascii_case(q)).collect();
    let hits = if exact.is_empty() { items.iter().filter(|r| r.item.matches(q)).collect() } else { exact };
    match hits[..] {
        [one] => Ok(one),
        [] => Err(format!("nothing matches '{q}'")),
        ref many => Err(format!(
            "'{q}' matches {} items, be more specific or use an id:\n{}",
            many.len(),
            many.iter().map(|r| format!("  {}  {}", r.id, r.item.title)).collect::<Vec<_>>().join("\n")
        )),
    }
}

fn field(item: &Item, name: &str) -> R<String> {
    let v = match name.to_lowercase().as_str() {
        "password" => item.password.clone(),
        "username" => item.username.clone(),
        "url" => item.urls.first().cloned(),
        "notes" => item.notes.clone(),
        "title" => Some(item.title.clone()),
        "totp" | "otp" => item.totp.as_deref().map(totp::current).transpose()?.map(|c| c.code),
        "json" => Some(serde_json::to_string_pretty(item)?),
        n => item.fields.iter().find(|f| f.name.eq_ignore_ascii_case(n)).map(|f| f.value.clone()),
    };
    v.ok_or_else(|| format!("'{}' has no {name}", item.title).into())
}

fn detached(args: &[&str]) -> R<Command> {
    let mut c = Command::new(std::env::current_exe()?);
    c.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0);
    Ok(c)
}

fn copy(value: &str, what: &str) -> R<()> {
    let n = mac::copy_concealed(value);
    detached(&["__clear-clipboard", &n.to_string()])?.spawn()?;
    println!("Copied {what}. Clipboard clears in {CLEAR_SECS}s.");
    Ok(())
}

fn generate() -> String {
    generator::password(PasswordOpts::default()).expect("default options are valid")
}

fn apply(item: &mut Item, a: ItemArgs) -> R<()> {
    if let Some(t) = &a.totp {
        totp::parse(t)?;
        item.totp = a.totp;
    }
    if a.username.is_some() {
        item.username = a.username;
    }
    if !a.url.is_empty() {
        item.urls = a.url;
    }
    if a.notes.is_some() {
        item.notes = a.notes;
    }
    if !a.tag.is_empty() {
        item.tags = a.tag;
    }
    if a.generate {
        item.password = Some(generate());
    }
    Ok(())
}

fn show(item: &ItemRecord, vault: &str) -> R<()> {
    let i = &item.item;
    println!("{}  ({vault})", i.title);
    let row = |k: &str, v: &str| println!("  {k:<9} {v}");
    if let Some(u) = &i.username {
        row("username", u);
    }
    if i.password.is_some() {
        row("password", &format!("••••••••  (lockbox copy \"{}\")", i.title));
    }
    for u in &i.urls {
        row("url", u);
    }
    if let Some(t) = &i.totp {
        let c = totp::current(t)?;
        row("totp", &format!("{} {}  ({}s)", &c.code[..c.code.len() / 2], &c.code[c.code.len() / 2..], c.remaining));
    }
    for f in &i.fields {
        row(&f.name, if f.concealed { "••••••••" } else { &f.value });
    }
    if !i.tags.is_empty() {
        row("tags", &i.tags.join(", "));
    }
    if let Some(n) = &i.notes {
        row("notes", n);
    }
    row("id", &item.id.to_string());
    Ok(())
}

fn confirm(q: &str) -> R<bool> {
    print!("{q} [y/N] ");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().eq_ignore_ascii_case("y"))
}

fn run(cmd: Cmd) -> R<()> {
    let p = Paths::new()?;
    match cmd {
        Cmd::Init => {
            if p.db.exists() {
                return Err(format!("a lockbox already exists at {}", p.db.display()).into());
            }
            let pw = prompt_hidden("Choose a master password: ")?;
            if pw.chars().count() < 10 {
                return Err("use at least 10 characters; a long phrase is easiest to remember".into());
            }
            if *prompt_hidden("Repeat it: ")? != *pw {
                return Err("passwords didn't match".into());
            }
            let (_, sk) = Lockbox::create(&p.db, &pw, KdfParams::default())?;
            let saved = mac::save_secret_key(&p.account(), &sk.to_display());
            println!("\nlockbox created at {}\n", p.db.display());
            println!("  Your Secret Key:  {}\n", sk.to_display());
            println!("Write it down or store it somewhere safe offline. On a new device you need it AND");
            println!("your master password. Nobody, including lockbox, can recover either one.");
            if let Err(e) = saved {
                eprintln!("\nwarning: couldn't save the Secret Key to the Keychain ({e}); you'll be asked for it on unlock");
            }
        }
        Cmd::Unlock { minutes } => {
            if agent::is_running(&p.sock) {
                println!("Already unlocked.");
                return Ok(());
            }
            let (lb, pw, sk) = unlock_interactive(&p)?;
            drop(lb);
            let mut child = detached(&["__agent", &minutes.to_string()])?.stdin(Stdio::piped()).spawn()?;
            let payload = Zeroizing::new(format!("{}\n{}\n", *pw, sk.to_display()));
            child.stdin.take().ok_or("agent stdin")?.write_all(payload.as_bytes())?;
            for _ in 0..100 {
                if agent::is_running(&p.sock) {
                    println!("Unlocked. Auto-locks after {minutes} idle minutes (`lockbox lock` to lock now).");
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            return Err("agent didn't start".into());
        }
        Cmd::Agent { minutes } => {
            let mut lines = std::io::stdin().lock().lines();
            let pw = Zeroizing::new(lines.next().ok_or("no password")??);
            let sk = SecretKey::parse(&Zeroizing::new(lines.next().ok_or("no secret key")??))?;
            let lb = Lockbox::unlock(&p.db, &pw, &sk)?;
            drop((pw, sk));
            agent::serve(lb, &p.sock, Duration::from_secs(minutes * 60))?;
        }
        Cmd::ClearClipboard { change_count } => {
            std::thread::sleep(Duration::from_secs(CLEAR_SECS));
            mac::clear_if_unchanged(change_count);
        }
        Cmd::Lock => {
            if agent::is_running(&p.sock) {
                agent::call(&p.sock, &Request::Lock)?;
            }
            println!("Locked.");
        }
        Cmd::Status => {
            println!("lockbox   {}", p.db.display());
            println!("state     {}", if !p.db.exists() { "not set up" } else if agent::is_running(&p.sock) { "unlocked" } else { "locked" });
        }
        Cmd::Gen { length, no_symbols, easy_type, pin, copy: c } => {
            let pw = match pin {
                Some(n) => generator::pin(n)?,
                None => generator::password(PasswordOpts { length, symbols: !no_symbols, avoid_ambiguous: easy_type, ..Default::default() })?,
            };
            if c { copy(&pw, "generated password")? } else { println!("{pw}") }
        }
        cmd => {
            let s = Session::open(&p)?;
            match cmd {
                Cmd::Vaults { cmd: None } => {
                    for v in s.call::<Vec<Vault>>(Request::Vaults)? {
                        println!("{}", v.name);
                    }
                }
                Cmd::Vaults { cmd: Some(VaultCmd::Add { name }) } => {
                    s.call::<Uuid>(Request::CreateVault { name: name.clone() })?;
                    println!("Created vault {name}.");
                }
                Cmd::Ls { query, vault } => {
                    let vaults: Vec<Vault> = s.call(Request::Vaults)?;
                    let vname = |id| vaults.iter().find(|v| v.id == id).map_or("?", |v| v.name.as_str());
                    let only = vault.map(|n| s.vault(Some(&n))).transpose()?;
                    let mut items: Vec<_> = s
                        .items()?
                        .into_iter()
                        .filter(|r| only.as_ref().is_none_or(|v| v.id == r.vault_id))
                        .filter(|r| query.as_deref().is_none_or(|q| r.item.matches(q)))
                        .collect();
                    items.sort_by_key(|r| r.item.title.to_lowercase());
                    for r in &items {
                        println!("{:<32} {:<32} {}", r.item.title, r.item.username.as_deref().unwrap_or(""), vname(r.vault_id));
                    }
                    if items.is_empty() {
                        println!("No items.");
                    }
                }
                Cmd::Get { query, field: None } => {
                    let r = s.find(&query)?;
                    let vaults: Vec<Vault> = s.call(Request::Vaults)?;
                    show(&r, vaults.iter().find(|v| v.id == r.vault_id).map_or("?", |v| &v.name))?;
                }
                Cmd::Get { query, field: Some(f) } => println!("{}", field(&s.find(&query)?.item, &f)?),
                Cmd::Copy { query, field: f } => {
                    let r = s.find(&query)?;
                    copy(&field(&r.item, &f)?, &format!("{f} for {}", r.item.title))?;
                }
                Cmd::Totp { query, copy: c } => {
                    let r = s.find(&query)?;
                    let code = totp::current(r.item.totp.as_deref().ok_or(format!("'{}' has no 2FA secret", r.item.title))?)?;
                    if c { copy(&code.code, &format!("2FA code for {} ({}s left)", r.item.title, code.remaining))? } else { println!("{}", code.code) }
                }
                Cmd::Add { title, fields, vault, note } => {
                    let v = s.vault(vault.as_deref())?;
                    let mut item = Item { title, kind: if note { Kind::SecureNote } else { Kind::Login }, ..Default::default() };
                    let generated = fields.generate;
                    apply(&mut item, fields)?;
                    if !note && !generated {
                        let pw = prompt_hidden("Password (leave empty to generate): ")?;
                        item.password = Some(if pw.is_empty() { generate() } else { pw.to_string() });
                    }
                    let title = item.title.clone();
                    s.call::<Uuid>(Request::Add { vault: v.id, item })?;
                    println!("Added {title} to {}.", v.name);
                }
                Cmd::Edit { query, title, fields, password } => {
                    let mut r = s.find(&query)?;
                    if let Some(t) = title {
                        r.item.title = t;
                    }
                    apply(&mut r.item, fields)?;
                    if password {
                        r.item.password = Some(prompt_hidden("New password: ")?.to_string());
                    }
                    let t = r.item.title.clone();
                    s.call::<()>(Request::Update { id: r.id, item: r.item })?;
                    println!("Updated {t}.");
                }
                Cmd::Rm { query, yes } => {
                    let r = s.find(&query)?;
                    if yes || confirm(&format!("Delete {}?", r.item.title))? {
                        s.call::<()>(Request::Delete { id: r.id })?;
                        println!("Deleted {}.", r.item.title);
                    }
                }
                _ => unreachable!("handled above"),
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse().cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(title: &str, user: &str) -> ItemRecord {
        ItemRecord {
            id: Uuid::new_v4(),
            vault_id: Uuid::nil(),
            version: 1,
            item: Item { title: title.into(), username: Some(user.into()), ..Default::default() },
        }
    }

    #[test]
    fn resolve_prefers_id_then_exact_title_then_search() {
        let items = vec![rec("GitHub", "me"), rec("GitHub Enterprise", "work"), rec("Gmail", "me@gmail.com")];
        assert_eq!(resolve(&items, &items[1].id.to_string()).unwrap().item.title, "GitHub Enterprise");
        assert_eq!(resolve(&items, "github").unwrap().item.title, "GitHub"); // exact beats substring
        assert_eq!(resolve(&items, "enterprise").unwrap().item.title, "GitHub Enterprise");
        assert!(resolve(&items, "g").unwrap_err().contains("matches 3 items"));
        assert!(resolve(&items, "nope").is_err());
    }

    #[test]
    fn fields() {
        let mut i = rec("GitHub", "me").item;
        i.password = Some("pw".into());
        i.fields.push(lockbox_core::Field { name: "Recovery".into(), value: "abc".into(), concealed: true });
        assert_eq!(field(&i, "password").unwrap(), "pw");
        assert_eq!(field(&i, "recovery").unwrap(), "abc");
        assert!(field(&i, "notes").is_err());
    }

    #[test]
    fn agent_round_trip() {
        let dir = std::env::temp_dir().join(format!("lb-{}", &Uuid::new_v4().to_string()[..8]));
        std::fs::create_dir_all(&dir).unwrap();
        let (lb, _) = Lockbox::create(&dir.join("t.db"), "pw", KdfParams { m_kib: 64, t: 1, p: 1 }).unwrap();
        let sock = dir.join("s");
        let s2 = sock.clone();
        let t = std::thread::spawn(move || agent::serve(lb, &s2, Duration::from_secs(60)).unwrap());
        while !agent::is_running(&sock) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let s = Session::Agent(sock.clone());
        let v = s.vault(None).unwrap();
        s.call::<Uuid>(Request::Add { vault: v.id, item: rec("GitHub", "me").item }).unwrap();
        assert_eq!(s.find("git").unwrap().item.username.as_deref(), Some("me"));
        agent::call(&sock, &Request::Lock).unwrap();
        t.join().unwrap();
        assert!(!agent::is_running(&sock) && !sock.exists());
    }
}
