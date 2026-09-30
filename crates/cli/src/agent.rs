//! Unlock agent: holds an unlocked Lockbox in memory, serves one JSON request per connection
//! over a 0600 Unix socket, checks the peer's UID, and exits after an idle timeout (SPEC §6).
//! The desktop app will host this same protocol in M3.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lockbox_core::{Item, Lockbox};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub enum Request {
    Vaults,
    CreateVault { name: String },
    Items,
    Add { vault: Uuid, item: Item },
    Update { id: Uuid, item: Item },
    Delete { id: Uuid },
    Lock,
}

pub type Response = Result<Value, String>;

pub fn handle(lb: &Lockbox, req: Request) -> Response {
    let r = match req {
        Request::Vaults => lb.vaults().map(|v| json!(v)),
        Request::CreateVault { name } => lb.create_vault(&name).map(|v| json!(v)),
        Request::Items => lb.items(None).map(|v| json!(v)),
        Request::Add { vault, item } => lb.add_item(&vault, item).map(|v| json!(v)),
        Request::Update { id, item } => lb.update_item(&id, item).map(|_| Value::Null),
        Request::Delete { id } => lb.delete_item(&id).map(|_| Value::Null),
        Request::Lock => Ok(Value::Null),
    };
    r.map_err(|e| e.to_string())
}

pub fn is_running(sock: &Path) -> bool {
    UnixStream::connect(sock).is_ok()
}

pub fn call(sock: &Path, req: &Request) -> Response {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("agent: {e}"))?;
    serde_json::to_writer(&mut s, req).map_err(|e| e.to_string())?;
    s.write_all(b"\n").map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|_| "agent closed the connection".to_string())?
}

fn peer_is_me(s: &UnixStream) -> bool {
    let (mut uid, mut gid) = (0, 0);
    unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == libc::getuid() }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn serve(lb: Lockbox, sock: &Path, idle: Duration) -> std::io::Result<()> {
    if sock.exists() && !is_running(sock) {
        std::fs::remove_file(sock)?;
    }
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;

    let last = Arc::new(AtomicU64::new(now()));
    let (l, path) = (last.clone(), sock.to_path_buf());
    // ponytail: process exit frees the key; zeroize-on-exit would need a shutdown channel, add if it matters
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        if now() - l.load(Ordering::Relaxed) > idle.as_secs() {
            let _ = std::fs::remove_file(&path);
            std::process::exit(0);
        }
    });

    for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        if !peer_is_me(&s) {
            continue;
        }
        last.store(now(), Ordering::Relaxed);
        let mut line = String::new();
        if BufReader::new(&s).read_line(&mut line).is_err() {
            continue;
        }
        let (resp, lock) = match serde_json::from_str::<Request>(&line) {
            Ok(Request::Lock) => (Ok(Value::Null), true),
            Ok(req) => (handle(&lb, req), false),
            Err(e) => (Err(format!("bad request: {e}")), false),
        };
        if serde_json::to_writer(&mut s, &resp).is_ok() {
            let _ = s.write_all(b"\n");
        }
        if lock {
            break;
        }
    }
    std::fs::remove_file(sock)
}
