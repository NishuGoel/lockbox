//! Which build is this, and is there a newer one on main?

use serde::Serialize;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMMIT: &str = env!("LB_COMMIT");
pub const COMMIT_FULL: &str = env!("LB_COMMIT_FULL");
pub const COMMIT_DATE: &str = env!("LB_COMMIT_DATE");
/// e.g. "0.1.0 (9014ea8, 2026-11-03)"
pub const DESCRIBE: &str = env!("LB_DESCRIBE");
pub const REPO_DIR: &str = env!("LB_REPO_DIR");
const REMOTE: &str = env!("LB_REMOTE");

pub fn dirty() -> bool {
    env!("LB_DIRTY") == "true"
}

/// "owner/repo" from an https or ssh GitHub remote.
pub fn github_slug(remote: &str) -> Option<String> {
    let rest = remote.strip_prefix("https://github.com/").or_else(|| remote.strip_prefix("git@github.com:"))?;
    let slug = rest.trim_end_matches('/').trim_end_matches(".git");
    (slug.split('/').count() == 2 && !slug.contains(' ')).then(|| slug.to_string())
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Update {
    /// commits on main that this build doesn't have
    pub behind: u64,
    pub compare_url: String,
}

/// Asks GitHub how far main is ahead of this build. Only the public commit list is fetched.
pub fn check() -> Result<Update, String> {
    let slug = github_slug(REMOTE).ok_or("this build doesn't know its GitHub repo")?;
    if COMMIT_FULL.is_empty() {
        return Err("this build has no commit stamp".into());
    }
    let url = format!("https://api.github.com/repos/{slug}/compare/{COMMIT_FULL}...main");
    let body: serde_json::Value = match ureq::get(&url).header("user-agent", "lockbox-update-check").header("accept", "application/vnd.github+json").call() {
        Ok(mut r) => r.body_mut().read_json().map_err(|e| e.to_string())?,
        Err(ureq::Error::StatusCode(404)) => return Err("this build is from a commit GitHub doesn't have (not pushed yet)".into()),
        Err(ureq::Error::StatusCode(403)) => return Err("GitHub rate limit reached; try again later".into()),
        Err(e) => return Err(format!("couldn't reach GitHub: {e}")),
    };
    Ok(parse(&body, &slug))
}

fn parse(body: &serde_json::Value, slug: &str) -> Update {
    // compare/BASE...main: "ahead" = main has commits we don't
    Update { behind: body["ahead_by"].as_u64().unwrap_or(0), compare_url: format!("https://github.com/{slug}/compare/{COMMIT}...main") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(github_slug("https://github.com/NishuGoel/lockbox.git").as_deref(), Some("NishuGoel/lockbox"));
        assert_eq!(github_slug("git@github.com:NishuGoel/lockbox.git").as_deref(), Some("NishuGoel/lockbox"));
        assert_eq!(github_slug("https://gitlab.com/x/y.git"), None);
    }

    #[test]
    fn stamp_and_parse() {
        assert_eq!(COMMIT.len(), 7, "built inside the git repo");
        assert!(DESCRIBE.starts_with(VERSION) && DESCRIBE.contains(COMMIT));
        let u = parse(&serde_json::json!({ "status": "ahead", "ahead_by": 3 }), "NishuGoel/lockbox");
        assert_eq!(u.behind, 3);
        assert!(u.compare_url.ends_with(&format!("{COMMIT}...main")));
        assert_eq!(parse(&serde_json::json!({ "status": "identical", "ahead_by": 0 }), "a/b").behind, 0);
    }
}
