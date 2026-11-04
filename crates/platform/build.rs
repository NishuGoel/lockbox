// Stamps every build with the git commit it came from, so the app and CLI can say exactly
// which version is installed and whether main has moved on.
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    let git = |args: &[&str]| {
        Command::new("git").arg("-C").arg(&root).args(args).output().ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let commit = git(&["rev-parse", "--short=7", "HEAD"]);
    let date = git(&["log", "-1", "--format=%cs"]);
    // ponytail: dirty is refreshed when the git index changes, not on every unstaged edit
    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"]).is_empty();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let describe = if commit.is_empty() {
        version.clone()
    } else {
        format!("{version} ({commit}{}, {date})", if dirty { "+local changes" } else { "" })
    };
    println!("cargo:rustc-env=LB_COMMIT={commit}");
    println!("cargo:rustc-env=LB_COMMIT_FULL={}", git(&["rev-parse", "HEAD"]));
    println!("cargo:rustc-env=LB_COMMIT_DATE={date}");
    println!("cargo:rustc-env=LB_DIRTY={dirty}");
    println!("cargo:rustc-env=LB_REMOTE={}", git(&["config", "--get", "remote.origin.url"]));
    println!("cargo:rustc-env=LB_REPO_DIR={}", root.canonicalize().unwrap_or(root.clone()).display());
    println!("cargo:rustc-env=LB_DESCRIBE={describe}");
    for p in [".git/HEAD", ".git/index", ".git/refs/heads"] {
        println!("cargo:rerun-if-changed={}", root.join(p).display());
    }
}
