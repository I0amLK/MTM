#![cfg(target_os = "linux")]
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

#[test]
fn rejected_candidate_does_not_execute_or_expose_paths_and_environment()
-> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let script = temp.path().join("sensitive-candidate-name");
    fs::write(&script, "#!/bin/sh\nprintf must-never-run\n")?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .args(["qualify", "--profile", "protocol", "--binary"])
        .arg(&script)
        .args(["--sha256", &"0".repeat(64)])
        .env_clear()
        .env("API_TOKEN", "test-private-token")
        .stdin(Stdio::null())
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["candidate_launched"], false);
    assert_eq!(report["release_qualified"], false);
    for text in [
        "must-never-run",
        "sensitive-candidate-name",
        "test-private-token",
    ] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(text));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(text));
    }
    Ok(())
}

#[test]
fn qualify_rejects_implicit_release_or_skip_switches() -> Result<(), Box<dyn Error>> {
    for args in [
        vec!["qualify"],
        vec!["qualify", "--profile", "release"],
        vec!["qualify", "--skip-native"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}
