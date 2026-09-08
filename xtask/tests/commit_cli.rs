use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};

const MESSAGE: &str = "build(maintenance): use Rust commit checks [MTM-016]\n\nMilestone: MTM-016\nAuthority-Before: rust\nAuthority-After: rust\nAcceptance: A0,A1\nReceipt: records/iterations/ITER-016.json\nRollback: revert the dedicated commit\nManual-Pending: target checks\n";

#[test]
fn commit_cli_works_without_python_or_inherited_environment() -> Result<(), Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .args(["commit-message", "--stdin"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(MESSAGE.as_bytes())?;
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["ok"], true);
    assert_eq!(report["milestone"], "MTM-016");
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn invalid_commit_fails_without_echoing_message_contents() -> Result<(), Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .args(["commit-message", "--stdin"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let content = b"untrusted-message-content-must-not-be-echoed";
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(content)?;
    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        !output
            .stderr
            .windows(content.len())
            .any(|window| window == content)
    );
    Ok(())
}
