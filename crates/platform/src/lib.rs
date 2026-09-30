pub mod agent;
pub mod backup;
pub mod mac;
pub mod native;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// `$LOCKBOX_DIR`, else ~/Library/Application Support/lockbox. Created with 0700.
pub fn data_dir() -> std::io::Result<PathBuf> {
    let dir = match std::env::var_os("LOCKBOX_DIR") {
        Some(d) => PathBuf::from(d),
        None => std::env::home_dir()
            .ok_or_else(|| std::io::Error::other("no home directory"))?
            .join("Library/Application Support/lockbox"),
    };
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
