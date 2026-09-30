//! Keychain + clipboard. macOS only; other platforms get a clear error.

#[cfg(target_os = "macos")]
mod imp {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
    use objc2_foundation::NSString;
    use security_framework::passwords;

    const SERVICE: &str = "lockbox.secret-key";
    const NOT_FOUND: i32 = -25300;

    // ponytail: legacy login keychain. ThisDeviceOnly/biometric ACLs need a signed app with entitlements (M3).
    pub fn save_secret_key(account: &str, sk: &str) -> Result<(), String> {
        passwords::set_generic_password(SERVICE, account, sk.as_bytes()).map_err(|e| e.to_string())
    }

    pub fn load_secret_key(account: &str) -> Result<Option<String>, String> {
        match passwords::get_generic_password(SERVICE, account) {
            Ok(b) => Ok(Some(String::from_utf8_lossy(&b).into_owned())),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Copies `s` marked as concealed so clipboard managers skip it. Returns the pasteboard change count.
    pub fn copy_concealed(s: &str) -> isize {
        let pb = NSPasteboard::generalPasteboard();
        pb.clearContents();
        pb.setString_forType(&NSString::from_str(s), unsafe { NSPasteboardTypeString });
        pb.setString_forType(&NSString::from_str(""), &NSString::from_str("org.nspasteboard.ConcealedType"));
        pb.changeCount()
    }

    /// Clears the clipboard only if nothing else was copied since `change_count`.
    pub fn clear_if_unchanged(change_count: isize) {
        let pb = NSPasteboard::generalPasteboard();
        if pb.changeCount() == change_count {
            pb.clearContents();
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    const MSG: &str = "only macOS is supported for now";
    pub fn save_secret_key(_: &str, _: &str) -> Result<(), String> { Err(MSG.into()) }
    pub fn load_secret_key(_: &str) -> Result<Option<String>, String> { Err(MSG.into()) }
    pub fn copy_concealed(_: &str) -> isize { panic!("{MSG}") }
    pub fn clear_if_unchanged(_: isize) {}
}

pub use imp::*;
