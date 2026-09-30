//! Daily encrypted backups, restore, and the monthly Secret Key check. Settings live in
//! `settings.json` next to the vault; nothing in it is secret.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lockbox_core::{Lockbox, SecretKey, backup_file};
use serde::{Deserialize, Serialize};

pub const KEEP: usize = 14;
pub const DAY: u64 = 86_400;
pub const RECOVERY_CHECK_EVERY: u64 = 30 * DAY;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub auto_backup: bool,
    pub backup_dir: Option<PathBuf>,
    pub last_backup: u64,
    pub last_backup_error: Option<String>,
    /// the "turn on backups?" question has been answered
    pub backup_asked: bool,
    pub last_recovery_check: u64,
}

impl Settings {
    fn path(dir: &Path) -> PathBuf {
        dir.join("settings.json")
    }

    pub fn load(dir: &Path) -> Self {
        std::fs::read(Self::path(dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::write(Self::path(dir), serde_json::to_vec_pretty(self)?)
    }

    pub fn backup_due(&self) -> bool {
        self.auto_backup && now().saturating_sub(self.last_backup) >= DAY
    }

    pub fn recovery_due(&self) -> bool {
        now().saturating_sub(self.last_recovery_check) >= RECOVERY_CHECK_EVERY
    }
}

/// iCloud Drive if it's on (gets a copy off this Mac), else ~/Documents.
pub fn default_dir() -> PathBuf {
    let home = std::env::home_dir().unwrap_or_default();
    let icloud = home.join("Library/Mobile Documents/com~apple~CloudDocs");
    if icloud.is_dir() { icloud.join("lockbox Backups") } else { home.join("Documents/lockbox Backups") }
}

/// `lockbox-2026-09-30T0915Z.lockbox` (UTC, sorts chronologically).
pub fn file_name(secs: u64) -> String {
    // days → civil date (Howard Hinnant's algorithm)
    let z = (secs / DAY) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let t = secs % DAY;
    format!("lockbox-{y:04}-{m:02}-{d:02}T{:02}{:02}Z.lockbox", t / 3600, t % 3600 / 60)
}

/// Writes a new backup into `dir` and keeps only the newest `KEEP`.
pub fn backup_now(db: &Path, dir: &Path) -> lockbox_core::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let mut dest = dir.join(file_name(now()));
    if dest.exists() {
        dest = dir.join(file_name(now()).replace(".lockbox", &format!("-{}.lockbox", now() % 60)));
    }
    backup_file(db, &dest)?;
    let mut ours: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("lockbox-") && n.ends_with(".lockbox")))
        .collect();
    ours.sort();
    for old in ours.iter().rev().skip(KEEP) {
        let _ = std::fs::remove_file(old);
    }
    Ok(dest)
}

/// Replaces `db` with `backup` after proving the backup opens with these credentials.
/// The current vault is kept next to it as `lockbox.db.before-restore-<time>`.
pub fn restore(backup: &Path, db: &Path, password: &str, sk: &SecretKey) -> lockbox_core::Result<()> {
    let dir = db.parent().ok_or(lockbox_core::Error::NotFound)?;
    // check a scratch copy, so opening it never leaves -wal/-shm files beside the user's backup
    let check = dir.join("restore-check.db");
    let _ = std::fs::remove_file(&check);
    std::fs::copy(backup, &check)?;
    let ok = Lockbox::unlock(&check, password, sk).map(drop);
    if let Err(e) = ok {
        let _ = std::fs::remove_file(&check);
        return Err(e);
    }
    if db.exists() {
        std::fs::rename(db, dir.join(format!("lockbox.db.before-restore-{}", now())))?;
    }
    for side in ["lockbox.db-wal", "lockbox.db-shm", "restore-check.db-wal", "restore-check.db-shm"] {
        let _ = std::fs::remove_file(dir.join(side));
    }
    std::fs::rename(&check, db)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockbox_core::{Item, KdfParams};

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("lb-bk-{}", now() ^ std::process::id() as u64 ^ rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn rand_suffix() -> u64 {
        std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
    }

    #[test]
    fn file_names_are_utc_dates() {
        assert_eq!(file_name(0), "lockbox-1970-01-01T0000Z.lockbox");
        assert_eq!(file_name(1_790_712_984), "lockbox-2026-09-29T2016Z.lockbox");
        assert_eq!(file_name(951_782_400), "lockbox-2000-02-29T0000Z.lockbox"); // leap day
    }

    #[test]
    fn backup_rotation_and_restore() {
        let dir = tmpdir();
        let db = dir.join("lockbox.db");
        let fast = KdfParams { m_kib: 64, t: 1, p: 1 };
        let (lb, sk) = Lockbox::create(&db, "pw", fast).unwrap();
        let v = lb.vaults().unwrap()[0].id;
        lb.add_item(&v, Item { title: "Keep me".into(), ..Default::default() }).unwrap();

        let bdir = dir.join("backups");
        std::fs::create_dir_all(&bdir).unwrap();
        for n in 0..20 {
            std::fs::write(bdir.join(format!("lockbox-2020-01-{:02}T0000Z.lockbox", n + 1)), b"old").unwrap();
        }
        std::fs::write(bdir.join("unrelated.txt"), b"x").unwrap();
        let fresh = backup_now(&db, &bdir).unwrap();
        let left: Vec<_> = std::fs::read_dir(&bdir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(left.iter().filter(|n| n.ends_with(".lockbox")).count(), KEEP);
        assert!(left.contains(&"unrelated.txt".to_string()), "only prunes our own files");
        assert!(fresh.exists());

        // vault changes after the backup, then we restore
        lb.add_item(&v, Item { title: "After backup".into(), ..Default::default() }).unwrap();
        drop(lb);
        assert!(restore(&fresh, &db, "wrong", &sk).is_err());
        assert!(db.exists(), "a failed restore leaves the vault alone");
        restore(&fresh, &db, "pw", &sk).unwrap();
        let titles: Vec<String> = Lockbox::unlock(&db, "pw", &sk).unwrap().items(None).unwrap().into_iter().map(|r| r.item.title).collect();
        assert_eq!(titles, vec!["Keep me"]);
        assert!(std::fs::read_dir(&dir).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("lockbox.db.before-restore-")));
        assert!(!bdir.join(fresh.file_name().unwrap()).with_extension("lockbox-wal").exists());
    }

    #[test]
    fn settings_due_logic() {
        let mut s = Settings { auto_backup: true, ..Default::default() };
        assert!(s.backup_due() && s.recovery_due());
        s.last_backup = now();
        s.last_recovery_check = now() - 29 * DAY;
        assert!(!s.backup_due() && !s.recovery_due());
        s.auto_backup = false;
        s.last_backup = 0;
        assert!(!s.backup_due(), "off means off");
        let dir = tmpdir();
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
    }
}
