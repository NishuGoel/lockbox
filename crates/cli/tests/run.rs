//! End to end: the real `lockbox run` binary against an agent socket that answers with the same
//! approval logic as the app. A thread plays you, deciding in the "app".
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use lockbox_core::{Item, KdfParams, Lockbox};
use lockbox_platform::agent::{self, Request};
use lockbox_platform::agents::{Approvals, Decision};

fn server(decision: Decision) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lbr-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    let (lb, _) = Lockbox::create(&dir.join("lockbox.db"), "pw", KdfParams { m_kib: 64, t: 1, p: 1 }).unwrap();
    let work = lb.create_vault("Work").unwrap();
    lb.add_item(&work, Item { title: "AWS Console".into(), password: Some("aws-secret-123".into()), username: Some("deploy-bot".into()), ..Default::default() }).unwrap();
    let approvals = Arc::new(Approvals::new(dir.clone()));
    let (sock, ap) = (dir.join("agent.sock"), approvals.clone());
    std::thread::spawn(move || {
        agent::serve(&sock, None, |req| match &req {
            Request::AgentAsk { agent, command, cwd, refs } => ap.ask(&lb, agent, command, cwd, refs).map(|a| serde_json::json!(a)),
            Request::AgentStatus { id } => ap.status(id).map(|s| serde_json::json!(s)).ok_or_else(|| "unknown".into()),
            Request::AgentResolve { id } => ap.resolve(&lb, id).map(|v| serde_json::json!(v)),
            _ => agent::handle(&lb, req),
        })
        .unwrap();
    });
    // "you", in the app
    std::thread::spawn(move || loop {
        if let Some(a) = approvals.pending().first() {
            assert_eq!(a.agent, "Claude Code");
            approvals.decide(&a.id, decision).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    });
    while !agent::is_running(&dir.join("agent.sock")) {
        std::thread::sleep(Duration::from_millis(20));
    }
    dir
}

fn lockbox(dir: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lockbox"))
        .args(args)
        .current_dir(dir)
        .env("LOCKBOX_DIR", dir)
        .env("CLAUDECODE", "1")
        .env("AWS_KEY", "lockbox://Work/AWS Console/password")
        .output()
        .unwrap()
}

#[test]
fn approved_run_gets_the_secret_but_its_output_does_not_show_it() {
    let dir = server(Decision::Once);
    let out = lockbox(&dir, &["run", "--", "sh", "-c", "echo \"key=$AWS_KEY\"; printf %s \"$AWS_KEY\" > got.txt"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(dir.join("got.txt")).unwrap(), "aws-secret-123", "the command received the real value");
    assert_eq!(stdout.trim(), "key=‹concealed by lockbox›", "but its output is masked");
    assert!(String::from_utf8_lossy(&out.stderr).contains("approve in the lockbox app"));
}

#[test]
fn denied_run_never_starts() {
    let dir = server(Decision::Deny);
    let out = lockbox(&dir, &["run", "--", "sh", "-c", "touch ran.txt"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("denied in lockbox"));
    assert!(!dir.join("ran.txt").exists(), "nothing ran");
}

#[test]
fn env_files_and_refs() {
    let dir = server(Decision::Once);
    std::fs::write(dir.join(".env"), "USER_NAME=\"lockbox://Work/AWS Console/username\"\nREGION=eu-central-1\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lockbox"))
        .args(["run", "--env-file", ".env", "--", "sh", "-c", "printf '%s %s' \"$USER_NAME\" \"$REGION\" > got.txt"])
        .current_dir(&dir).env("LOCKBOX_DIR", &dir).env("CLAUDECODE", "1").env_remove("AWS_KEY")
        .output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(dir.join("got.txt")).unwrap(), "deploy-bot eu-central-1");

    let refs = lockbox(&dir, &["ref", "aws"]);
    let text = String::from_utf8_lossy(&refs.stdout);
    assert!(text.contains("lockbox://Work/AWS Console/password") && !text.contains("aws-secret-123"), "{text}");
}
