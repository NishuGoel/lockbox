use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lockbox_core::generator::{self, PasswordOpts};
use lockbox_core::import::{self, Parsed};
use lockbox_core::{ImportSummary, Item, KdfParams, Kind, Lockbox, SecretKey, Vault, totp};
use lockbox_platform::agent::{self, Request};
use lockbox_platform::mac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};
use uuid::Uuid;
use zeroize::Zeroizing;

const IDLE_SECS: u64 = 10 * 60;
const CLEAR_SECS: u64 = 90;

type Res<T> = Result<T, String>;

fn err(e: impl ToString) -> String {
    e.to_string()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

struct Shared {
    lb: Mutex<Option<Lockbox>>,
    db: PathBuf,
    sock: PathBuf,
    last: AtomicU64,
    hosting: AtomicBool,
    /// The export being imported. Its path is the only file `delete_import_file` may remove.
    pending: Mutex<Option<(PathBuf, Option<Parsed>)>>,
}

type S<'a> = State<'a, Arc<Shared>>;

impl Shared {
    fn account(&self) -> String {
        self.db.to_string_lossy().into_owned()
    }

    fn touch(&self) {
        self.last.store(now(), Ordering::Relaxed);
    }

    fn with<T>(&self, f: impl FnOnce(&Lockbox) -> lockbox_core::Result<T>) -> Res<T> {
        self.touch();
        let g = self.lb.lock().unwrap();
        f(g.as_ref().ok_or("locked")?).map_err(err)
    }

    fn unlocked(&self) -> bool {
        self.lb.lock().unwrap().is_some()
    }

    /// Drops the keys (zeroized on drop) and tells every window.
    fn drop_keys(&self, app: &AppHandle) {
        if let Some((_, parsed)) = self.pending.lock().unwrap().as_mut() {
            parsed.take();
        }
        if self.lb.lock().unwrap().take().is_some() {
            let _ = app.emit("locked", ());
            if let Some(q) = app.get_webview_window("quick") {
                let _ = q.hide();
            }
        }
    }

    fn lock(&self, app: &AppHandle) {
        self.drop_keys(app);
        if self.hosting.swap(false, Ordering::SeqCst) {
            let _ = agent::call(&self.sock, &Request::Lock);
        }
    }
}

/// Serve the CLI's agent socket while unlocked, unless `lockbox unlock` already does.
fn start_hosting(app: &AppHandle, sh: &Arc<Shared>) {
    if agent::is_running(&sh.sock) || sh.hosting.swap(true, Ordering::SeqCst) {
        return;
    }
    let (sh, app) = (sh.clone(), app.clone());
    std::thread::spawn(move || {
        let sock = sh.sock.clone();
        let _ = agent::serve(&sock, None, |req| {
            if matches!(req, Request::Lock) {
                sh.hosting.store(false, Ordering::SeqCst);
                sh.drop_keys(&app);
                return Ok(Value::Null);
            }
            sh.touch();
            match sh.lb.lock().unwrap().as_ref() {
                Some(lb) => agent::handle(lb, req),
                None => Err("locked".into()),
            }
        });
        sh.hosting.store(false, Ordering::SeqCst);
    });
}

fn screen_locked() -> bool {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }
    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        return false;
    }
    let d: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    d.find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .and_then(|v| v.downcast::<CFBoolean>())
        .is_some_and(bool::from)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    exists: bool,
    unlocked: bool,
    has_secret_key: bool,
}

#[tauri::command]
fn status(s: S) -> Status {
    Status {
        exists: s.db.exists(),
        unlocked: s.unlocked(),
        has_secret_key: mac::load_secret_key(&s.account()).ok().flatten().is_some(),
    }
}

#[tauri::command]
async fn create(app: AppHandle, s: S<'_>, password: String) -> Res<String> {
    let pw = Zeroizing::new(password);
    if s.db.exists() {
        return Err("a lockbox already exists".into());
    }
    if pw.chars().count() < 10 {
        return Err("Use at least 10 characters. A long phrase is easiest to remember.".into());
    }
    let (lb, sk) = Lockbox::create(&s.db, &pw, KdfParams::default()).map_err(err)?;
    mac::save_secret_key(&s.account(), &sk.to_display())?;
    *s.lb.lock().unwrap() = Some(lb);
    s.touch();
    start_hosting(&app, s.inner());
    Ok(sk.to_display())
}

#[tauri::command]
async fn unlock(app: AppHandle, s: S<'_>, password: String, secret_key: Option<String>) -> Res<()> {
    let pw = Zeroizing::new(password);
    let stored = mac::load_secret_key(&s.account())?;
    let sk = match (&stored, secret_key.as_deref()) {
        (Some(k), _) => SecretKey::parse(k),
        (None, Some(k)) => SecretKey::parse(k),
        (None, None) => return Err("need_secret_key".into()),
    }
    .map_err(err)?;
    let lb = Lockbox::unlock(&s.db, &pw, &sk).map_err(err)?;
    if stored.is_none() {
        mac::save_secret_key(&s.account(), &sk.to_display())?;
    }
    *s.lb.lock().unwrap() = Some(lb);
    s.touch();
    start_hosting(&app, s.inner());
    Ok(())
}

#[tauri::command]
fn lock(app: AppHandle, s: S) {
    s.lock(&app);
}

#[tauri::command]
fn activity(s: S) {
    s.touch();
}

#[tauri::command]
fn vaults(s: S) -> Res<Vec<Vault>> {
    s.with(|lb| lb.vaults())
}

/// What the list and detail views see: no password or TOTP secret, concealed fields blanked.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemView {
    id: Uuid,
    vault_id: Uuid,
    kind: Kind,
    title: String,
    username: Option<String>,
    urls: Vec<String>,
    notes: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    has_password: bool,
    has_totp: bool,
    fields: Vec<(String, Option<String>)>,
    updated_at: u64,
}

#[tauri::command]
fn items(s: S) -> Res<Vec<ItemView>> {
    let recs = s.with(|lb| lb.items(None))?;
    Ok(recs
        .into_iter()
        .map(|r| {
            let i = r.item;
            ItemView {
                id: r.id,
                vault_id: r.vault_id,
                kind: i.kind,
                has_password: i.password.is_some(),
                has_totp: i.totp.is_some(),
                fields: i.fields.into_iter().map(|f| (f.name, (!f.concealed).then_some(f.value))).collect(),
                title: i.title,
                username: i.username,
                urls: i.urls,
                notes: i.notes,
                tags: i.tags,
                favorite: i.favorite,
                updated_at: i.updated_at,
            }
        })
        .collect())
}

/// Full item, for the editor.
#[tauri::command]
fn get_item(s: S, id: Uuid) -> Res<Item> {
    s.with(|lb| lb.get_item(&id)).map(|r| r.item)
}

fn value_of(s: &Shared, id: Uuid, field: &str) -> Res<String> {
    let item = s.with(|lb| lb.get_item(&id))?.item;
    let v = if field == "totp" {
        item.totp.as_deref().map(totp::current).transpose().map_err(err)?.map(|c| c.code)
    } else {
        item.field(field)
    };
    v.ok_or_else(|| format!("{} has no {field}", item.title))
}

#[tauri::command]
fn reveal(s: S, id: Uuid, field: Option<String>) -> Res<String> {
    value_of(&s, id, field.as_deref().unwrap_or("password"))
}

#[derive(Serialize)]
struct TotpCode {
    code: String,
    remaining: u64,
}

#[tauri::command]
fn totp_code(s: S, id: Uuid) -> Res<TotpCode> {
    let item = s.with(|lb| lb.get_item(&id))?.item;
    let c = totp::current(item.totp.as_deref().ok_or("no 2FA secret")?).map_err(err)?;
    Ok(TotpCode { code: c.code, remaining: c.remaining })
}

// ponytail: the clear thread dies with the app; quitting within 90s leaves the value on the clipboard.
fn copy_concealed(value: &str) {
    let n = mac::copy_concealed(value);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(CLEAR_SECS));
        mac::clear_if_unchanged(n);
    });
}

#[tauri::command]
fn copy(s: S, id: Uuid, field: String) -> Res<()> {
    copy_concealed(&value_of(&s, id, &field)?);
    Ok(())
}

#[tauri::command]
fn copy_text(s: S, text: String) {
    s.touch();
    copy_concealed(&Zeroizing::new(text));
}

#[derive(Deserialize)]
struct GenOpts {
    mode: String,
    length: usize,
    digits: bool,
    symbols: bool,
    easy: bool,
}

#[tauri::command]
fn generate(o: GenOpts) -> Res<String> {
    match o.mode.as_str() {
        "pin" => generator::pin(o.length),
        "memorable" => generator::memorable(o.length, "-"),
        _ => generator::password(PasswordOpts { length: o.length, digits: o.digits, symbols: o.symbols, avoid_ambiguous: o.easy, ..Default::default() }),
    }
    .map_err(err)
}

#[tauri::command]
fn save_item(s: S, id: Option<Uuid>, vault_id: Option<Uuid>, item: Item) -> Res<Uuid> {
    if item.title.trim().is_empty() {
        return Err("Give the item a title.".into());
    }
    if let Some(t) = item.totp.as_deref().filter(|t| !t.is_empty()) {
        totp::parse(t).map_err(|_| "That 2FA secret isn't valid. Paste the setup key or otpauth:// link.")?;
    }
    s.with(|lb| match id {
        Some(id) => lb.update_item(&id, item).map(|_| id),
        None => {
            let vault = match vault_id {
                Some(v) => v,
                None => lb.vaults()?.first().ok_or(lockbox_core::Error::NotFound)?.id,
            };
            lb.add_item(&vault, item)
        }
    })
}

#[tauri::command]
fn delete_item(s: S, id: Uuid) -> Res<()> {
    s.with(|lb| lb.delete_item(&id))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportPreview {
    file_name: String,
    count: usize,
    vaults: Vec<(String, usize)>,
    skipped: Vec<String>,
}

/// Native file picker (from Rust, so the page needs no file-system access), then parse.
#[tauri::command]
async fn import_pick(app: AppHandle, s: S<'_>) -> Res<Option<ImportPreview>> {
    if !s.unlocked() {
        return Err("locked".into());
    }
    let Some(picked) = app
        .dialog()
        .file()
        .set_title("Choose a password export")
        .add_filter("Password export", &["1pux", "csv"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(err)?;
    let parsed = import::parse_file(&path).map_err(err)?;
    let preview = ImportPreview {
        file_name: path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        count: parsed.items.len(),
        vaults: parsed.vaults(),
        skipped: parsed.skipped.clone(),
    };
    *s.pending.lock().unwrap() = Some((path, Some(parsed)));
    Ok(Some(preview))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    summary: ImportSummary,
    skipped: Vec<String>,
}

#[tauri::command]
fn import_run(s: S, only_vaults: Vec<String>, vault_id: Option<Uuid>) -> Res<ImportResult> {
    let mut parsed = s.pending.lock().unwrap().as_mut().and_then(|(_, p)| p.take()).ok_or("choose a file first")?;
    if !parsed.vaults().is_empty() {
        parsed = parsed.only_vaults(&only_vaults);
    }
    let summary = s.with(|lb| lb.import(parsed.items, vault_id.as_ref()))?;
    Ok(ImportResult { summary, skipped: parsed.skipped })
}

#[tauri::command]
fn delete_import_file(s: S) -> Res<()> {
    let (path, _) = s.pending.lock().unwrap().take().ok_or("nothing to delete")?;
    std::fs::remove_file(&path).map_err(err)
}

#[tauri::command]
fn hide_quick(app: AppHandle) {
    if let Some(w) = app.get_webview_window("quick") {
        let _ = w.hide();
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[tauri::command]
fn open_main(app: AppHandle) {
    hide_quick(app.clone());
    show_main(&app);
}

fn toggle_quick(app: &AppHandle) {
    let Some(w) = app.get_webview_window("quick") else { return };
    if w.is_visible().unwrap_or(false) {
        let _ = w.hide();
    } else {
        let _ = w.center();
        let _ = w.show();
        let _ = w.set_focus();
        let _ = app.emit_to("quick", "quick-shown", ());
    }
}

fn main() {
    let dir = lockbox_platform::data_dir().expect("data dir");
    let shared = Arc::new(Shared {
        lb: Mutex::new(None),
        db: dir.join("lockbox.db"),
        sock: dir.join("agent.sock"),
        last: AtomicU64::new(now()),
        hosting: AtomicBool::new(false),
        pending: Mutex::new(None),
    });
    let quick = Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::Space);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_shortcut(quick)
                .expect("valid shortcut")
                .with_handler(move |app, sc, ev| {
                    if sc == &quick && ev.state() == ShortcutState::Pressed {
                        toggle_quick(app);
                    }
                })
                .build(),
        )
        .manage(shared.clone())
        .setup(move |app| {
            let (app, sh) = (app.handle().clone(), shared);
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(2));
                if sh.unlocked() && (now() - sh.last.load(Ordering::Relaxed) > IDLE_SECS || screen_locked()) {
                    sh.lock(&app);
                }
            });
            Ok(())
        })
        .on_window_event(|w, e| match e {
            WindowEvent::CloseRequested { api, .. } if w.label() == "main" => {
                api.prevent_close();
                let _ = w.hide();
            }
            WindowEvent::Focused(false) if w.label() == "quick" => {
                let _ = w.hide();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            status, create, unlock, lock, activity, vaults, items, get_item, reveal, totp_code, copy, copy_text, generate,
            save_item, delete_item, import_pick, import_run, delete_import_file, hide_quick, open_main
        ])
        .build(tauri::generate_context!())
        .expect("tauri app");

    app.run(|app, e| match e {
        RunEvent::Reopen { .. } => show_main(app),
        RunEvent::Exit => {
            if let Some(s) = app.try_state::<Arc<Shared>>() {
                s.lock(app);
            }
        }
        _ => {}
    });
}
