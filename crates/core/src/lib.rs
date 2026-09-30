pub mod crypto;
pub mod generator;
pub mod import;
pub mod totp;
pub mod vault;

pub use crypto::{KdfParams, SecretKey};
pub use vault::{Field, ImportSummary, Item, ItemRecord, Kind, Lockbox, Passkey, PasswordChange, Vault, backup_file, display_host, site_matches};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong master password or Secret Key")]
    WrongCredentials,
    #[error("Secret Key is malformed or has a typo")]
    BadSecretKey,
    #[error("invalid key derivation parameters")]
    BadKdfParams,
    #[error("decryption failed: data is corrupt or was tampered with")]
    Decrypt,
    #[error("not found")]
    NotFound,
    #[error("a lockbox already exists at this path")]
    AlreadyInitialized,
    #[error("no lockbox at this path")]
    NotInitialized,
    #[error("invalid generator options: {0}")]
    BadGeneratorOptions(&'static str),
    #[error("{0}")]
    Import(String),
    #[error("invalid TOTP secret")]
    BadTotp,
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
