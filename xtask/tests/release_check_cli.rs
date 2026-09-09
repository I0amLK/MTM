#![cfg(target_os = "linux")]
use std::error::Error;
use std::process::{Command, Stdio};

#[test]
fn release_check_rejects_overrides_and_unsafe_inputs_without_running_the_binary()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    for arguments in [
        vec!["release-check", "--approve"],
        vec!["release-check", "--record", "--record"],
        vec![
            "release-check",
            "--binary",
            "/not-executable",
            "--manifest",
            "/etc/passwd",
        ],
        vec![
            "release-check",
            "--binary",
            "/not-executable",
            "--manifest",
            "../private.json",
        ],
        vec![
            "release-check",
            "--binary",
            "/not-executable",
            "--manifest",
            "missing.json",
            "--skip",
            "native",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args(arguments)
            .env_clear()
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
    }
    Ok(())
}
