//! Agent access (Claude Code etc.): an agent asks for secrets by reference, you approve in the
//! app, and only then are values handed to the process that runs the approved command. Grants
//! are narrow (same agent, same folder, same references) and short; every decision is logged.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Mutex;

use lockbox_core::reference::Reference;
use lockbox_core::{Lockbox, Vault};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backup::{Settings, now};

pub const PENDING_SECS: u64 = 120;
pub const HOUR_GRANT_SECS: u64 = 3600;
const LOG_MAX: usize = 300;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Used,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Deny,
    Once,
    Hour,
}

/// What the approval sheet shows.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: String,
    pub agent: String,
    pub command: String,
    pub cwd: String,
    pub refs: Vec<String>,
    /// "AWS Console › password (Work)" for each reference
    pub labels: Vec<String>,
    pub status: Status,
    pub created: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub at: u64,
    pub agent: String,
    pub command: String,
    pub cwd: String,
    pub labels: Vec<String>,
    /// approved once | approved for 1 hour | allowed by 1-hour grant | denied | expired
    pub outcome: String,
}

struct Grant {
    agent: String,
    cwd: String,
    refs: BTreeSet<String>,
    until: u64,
}

pub struct Approvals {
    dir: PathBuf,
    state: Mutex<(Vec<Approval>, Vec<Grant>)>,
}

fn log(dir: &std::path::Path, a: &Approval, outcome: &str) {
    let mut st = Settings::load(dir);
    st.agent_log.insert(0, LogEntry { at: now(), agent: a.agent.clone(), command: a.command.clone(), cwd: a.cwd.clone(), labels: a.labels.clone(), outcome: outcome.into() });
    st.agent_log.truncate(LOG_MAX);
    let _ = st.save(dir);
}

impl Approvals {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, state: Mutex::new((Vec::new(), Vec::new())) }
    }

    /// Validates the request (every reference must point at an item in a vault agents may use)
    /// and returns its id and status: Approved straight away if a 1-hour grant covers it.
    pub fn ask(&self, lb: &Lockbox, agent: &str, command: &str, cwd: &str, refs: &[String]) -> Result<Approval, String> {
        if refs.is_empty() {
            return Err("no lockbox:// references to resolve".into());
        }
        let (items, vaults) = (lb.items(None).map_err(|e| e.to_string())?, lb.vaults().map_err(|e| e.to_string())?);
        let allowed = Settings::load(&self.dir).agent_vaults;
        let mut labels = Vec::new();
        for r in refs {
            let parsed = Reference::parse(r).ok_or_else(|| format!("not a lockbox reference: {r}"))?;
            let item = parsed.find(&items, &vaults)?;
            let vault = vaults.iter().find(|v| v.id == item.vault_id).map_or("?", |v: &Vault| v.name.as_str());
            if allowed.as_ref().is_some_and(|ids| !ids.contains(&item.vault_id)) {
                return Err(format!("agents aren't allowed to use the {vault} vault (lockbox → Settings → Agents)"));
            }
            parsed.value(item)?; // fail now, not after you approved
            labels.push(format!("{} › {} ({vault})", item.item.title, parsed.field));
        }
        let mut a = Approval {
            id: Uuid::new_v4().to_string(), agent: agent.into(), command: command.into(), cwd: cwd.into(),
            refs: refs.to_vec(), labels, status: Status::Pending, created: now(),
        };
        let mut st = self.state.lock().unwrap();
        st.1.retain(|g| g.until > now());
        let wanted: BTreeSet<String> = refs.iter().cloned().collect();
        if st.1.iter().any(|g| g.agent == a.agent && g.cwd == a.cwd && wanted.is_subset(&g.refs)) {
            a.status = Status::Approved;
            log(&self.dir, &a, "allowed by 1-hour grant");
        }
        st.0.push(a.clone());
        Ok(a)
    }

    fn expire(list: &mut [Approval], dir: &std::path::Path) {
        for a in list.iter_mut().filter(|a| a.status == Status::Pending && now().saturating_sub(a.created) > PENDING_SECS) {
            a.status = Status::Expired;
            log(dir, a, "expired");
        }
    }

    pub fn pending(&self) -> Vec<Approval> {
        let mut st = self.state.lock().unwrap();
        Self::expire(&mut st.0, &self.dir);
        st.0.iter().filter(|a| a.status == Status::Pending).cloned().collect()
    }

    pub fn status(&self, id: &str) -> Option<Status> {
        let mut st = self.state.lock().unwrap();
        Self::expire(&mut st.0, &self.dir);
        st.0.iter().find(|a| a.id == id).map(|a| a.status)
    }

    pub fn decide(&self, id: &str, d: Decision) -> Result<(), String> {
        let mut st = self.state.lock().unwrap();
        Self::expire(&mut st.0, &self.dir);
        let a = st.0.iter_mut().find(|a| a.id == id && a.status == Status::Pending).ok_or("that request is no longer waiting")?;
        a.status = if d == Decision::Deny { Status::Denied } else { Status::Approved };
        let a = a.clone();
        log(&self.dir, &a, match d { Decision::Deny => "denied", Decision::Once => "approved once", Decision::Hour => "approved for 1 hour" });
        if d == Decision::Hour {
            st.1.push(Grant { agent: a.agent, cwd: a.cwd, refs: a.refs.into_iter().collect(), until: now() + HOUR_GRANT_SECS });
        }
        Ok(())
    }

    /// The values, exactly once per approved request.
    pub fn resolve(&self, lb: &Lockbox, id: &str) -> Result<Vec<(String, String)>, String> {
        let refs = {
            let mut st = self.state.lock().unwrap();
            let a = st.0.iter_mut().find(|a| a.id == id).ok_or("unknown request")?;
            if a.status != Status::Approved {
                return Err(format!("not approved ({:?})", a.status).to_lowercase());
            }
            a.status = Status::Used;
            a.refs.clone()
        };
        let (items, vaults) = (lb.items(None).map_err(|e| e.to_string())?, lb.vaults().map_err(|e| e.to_string())?);
        refs.into_iter()
            .map(|r| {
                let p = Reference::parse(&r).ok_or("bad reference")?;
                Ok((r, p.value(p.find(&items, &vaults)?)?))
            })
            .collect()
    }

    pub fn revoke_all(&self) {
        let mut st = self.state.lock().unwrap();
        st.1.clear();
        for a in st.0.iter_mut().filter(|a| matches!(a.status, Status::Pending | Status::Approved)) {
            a.status = Status::Denied;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockbox_core::{Item, KdfParams};

    fn setup() -> (Approvals, Lockbox, Uuid) {
        let dir = std::env::temp_dir().join(format!("lb-agents-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let (lb, _) = Lockbox::create(&dir.join("lockbox.db"), "pw", KdfParams { m_kib: 64, t: 1, p: 1 }).unwrap();
        let work = lb.create_vault("Work").unwrap();
        lb.add_item(&work, Item { title: "AWS Console".into(), password: Some("aws-secret".into()), username: Some("deploy".into()), ..Default::default() }).unwrap();
        let personal = lb.vaults().unwrap().into_iter().find(|v| v.name == "Personal").unwrap().id;
        lb.add_item(&personal, Item { title: "Bank".into(), password: Some("bank-pw".into()), ..Default::default() }).unwrap();
        (Approvals::new(dir), lb, work)
    }
    const AWS: &str = "lockbox://Work/AWS Console/password";

    #[test]
    fn once_means_once_and_deny_means_deny() {
        let (ap, lb, _) = setup();
        let a = ap.ask(&lb, "Claude Code", "npm run deploy", "/p", &[AWS.into()]).unwrap();
        assert_eq!((a.status, a.labels[0].as_str()), (Status::Pending, "AWS Console › password (Work)"));
        assert!(ap.resolve(&lb, &a.id).unwrap_err().contains("not approved"));
        assert_eq!(ap.pending().len(), 1);
        ap.decide(&a.id, Decision::Once).unwrap();
        assert_eq!(ap.resolve(&lb, &a.id).unwrap(), vec![(AWS.to_string(), "aws-secret".to_string())]);
        assert!(ap.resolve(&lb, &a.id).is_err(), "a second resolve of the same approval fails");

        let b = ap.ask(&lb, "Claude Code", "npm run deploy", "/p", &[AWS.into()]).unwrap();
        assert_eq!(b.status, Status::Pending, "'once' leaves no grant behind");
        ap.decide(&b.id, Decision::Deny).unwrap();
        assert!(ap.resolve(&lb, &b.id).is_err());
        assert!(ap.decide(&b.id, Decision::Once).is_err(), "can't flip a decided request");
        let log = Settings::load(&ap.dir).agent_log;
        assert_eq!(log.iter().map(|l| l.outcome.as_str()).collect::<Vec<_>>(), vec!["denied", "approved once"]);
    }

    #[test]
    fn hour_grants_are_narrow() {
        let (ap, lb, _) = setup();
        let a = ap.ask(&lb, "Claude Code", "deploy", "/p", &[AWS.into(), "lockbox://Work/AWS Console/username".into()]).unwrap();
        ap.decide(&a.id, Decision::Hour).unwrap();
        ap.resolve(&lb, &a.id).unwrap();
        let again = ap.ask(&lb, "Claude Code", "other command", "/p", &[AWS.into()]).unwrap();
        assert_eq!(again.status, Status::Approved, "subset of granted refs, same agent + folder");
        assert_eq!(ap.ask(&lb, "Claude Code", "x", "/elsewhere", &[AWS.into()]).unwrap().status, Status::Pending, "other folder asks again");
        assert_eq!(ap.ask(&lb, "Terminal", "x", "/p", &[AWS.into()]).unwrap().status, Status::Pending, "other agent asks again");
        assert_eq!(ap.ask(&lb, "Claude Code", "x", "/p", &["lockbox://Personal/Bank/password".into()]).unwrap().status, Status::Pending, "other secret asks again");
        ap.revoke_all();
        assert_eq!(ap.ask(&lb, "Claude Code", "x", "/p", &[AWS.into()]).unwrap().status, Status::Pending, "revoke all ends grants");
    }

    #[test]
    fn validation_and_vault_policy() {
        let (ap, lb, work) = setup();
        assert!(ap.ask(&lb, "a", "c", "/", &["lockbox://Work/Nope/password".into()]).unwrap_err().contains("no item"));
        assert!(ap.ask(&lb, "a", "c", "/", &["lockbox://Work/AWS Console/notes".into()]).unwrap_err().contains("has no notes"));
        assert!(ap.ask(&lb, "a", "c", "/", &["op://x/y/z".into()]).is_err());
        let mut st = Settings::load(&ap.dir);
        st.agent_vaults = Some(vec![work]);
        st.save(&ap.dir).unwrap();
        assert!(ap.ask(&lb, "a", "c", "/", &["lockbox://Personal/Bank/password".into()]).unwrap_err().contains("aren't allowed to use the Personal vault"));
        assert!(ap.ask(&lb, "a", "c", "/", &[AWS.into()]).is_ok());
    }
}
