//! CLI boundary only; never executes a readiness draft against live evidence.
#![cfg(target_os = "linux")]
use std::process::Command;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn readiness_cli_rejects_overrides_without_echoing_private_arguments() -> Result<()> {
    for option in [
        "--record",
        "--manifest",
        "--force",
        "--accept",
        "--authorize",
        "--binary",
        "--sha256",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .env_clear()
            .args(["release-readiness-schema8", option, "PRIVATE-PATH"])
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains("takes no options"));
        assert!(!error.contains("PRIVATE-PATH"));
    }
    Ok(())
}

#[test]
fn help_labels_schema8_command_as_blocked_draft_only() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .env_clear()
        .arg("help")
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("cargo xtask release-readiness-schema8"));
    assert!(help.contains("always blocked, not final release inputs or deployment authority"));
    Ok(())
}
