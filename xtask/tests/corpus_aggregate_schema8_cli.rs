//! CLI boundary only; no candidate or corpus trials are executed.
#![cfg(target_os = "linux")]
use std::process::Command;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn aggregate_cli_rejects_count_authority_and_does_not_echo_private_arguments() -> Result<()> {
    for args in [
        vec!["corpus-aggregate-check"],
        vec!["corpus-aggregate-check", "--accept", "PRIVATE"],
        vec![
            "corpus-aggregate-check",
            "--inputs",
            "PRIVATE",
            "--input-review",
            "PRIVATE",
            "--record",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .env_clear()
            .args(args)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains("use corpus-aggregate-check --inputs"));
        assert!(!error.contains("PRIVATE"));
    }
    Ok(())
}
#[test]
fn aggregate_help_is_explicitly_non_accepting() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .env_clear()
        .arg("help")
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("Read-only MTM-017 partial-corpus proposal; zero accepted delta"));
    Ok(())
}
