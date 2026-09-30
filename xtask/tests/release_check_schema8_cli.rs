//! Explicit CLI boundary only; no real readiness evaluation is executed.
#![cfg(target_os = "linux")]
use std::process::Command;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn formal_readiness_rejects_authority_or_arbitrary_input_options() -> Result<()> {
    for option in [
        "--record",
        "--accept",
        "--deploy",
        "--force",
        "--binary",
        "--authorize",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .env_clear()
            .args(["release-check-schema8", option, "PRIVATE-PATH"])
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(!error.contains("PRIVATE-PATH"));
    }
    Ok(())
}
#[test]
fn help_keeps_formal_evaluation_separate_from_acceptance() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .env_clear()
        .arg("help")
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("release-check-schema8 --inputs"));
    assert!(text.contains("independent result review and separate acceptance remain required"));
    Ok(())
}
