//! CLI boundary only; these tests never import real research evidence.
#![cfg(target_os = "linux")]
use std::process::Command;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn import_cli_rejects_authority_options_without_private_arguments_in_output() -> Result<()> {
    for args in [
        vec!["research-import-check"],
        vec!["research-import-check", "--accept", "/PRIVATE-CATALOG"],
        vec![
            "research-import-check",
            "--inputs",
            "PRIVATE-INPUT",
            "--bundle-catalog",
            "/PRIVATE-CATALOG",
        ],
        vec![
            "research-import-check",
            "--inputs",
            "PRIVATE-INPUT",
            "--bundle-catalog",
            "/PRIVATE-CATALOG",
            "--input-review",
            "PRIVATE-REVIEW",
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
        assert!(error.contains("use research-import-check --inputs"));
        assert!(!error.contains("PRIVATE"));
    }
    Ok(())
}

#[test]
fn import_help_promises_only_zero_delta_proposal() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .env_clear()
        .arg("help")
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("research-import-check --inputs <repo-relative-json>"));
    assert!(help.contains("accepted delta stays zero and a separate result review is required"));
    Ok(())
}
