//! CLI contract only; no real research records or running candidate required.
#![cfg(target_os = "linux")]

use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn research_cli_rejects_authority_overrides_without_echoing_private_arguments() -> Result<()> {
    for args in [
        vec!["research-precheck"],
        vec!["research-precheck", "--bundle", "PRIVATE-RELATIVE-PATH"],
        vec!["research-precheck", "--accept", "/PRIVATE-BUNDLE"],
        vec![
            "research-precheck",
            "--bundle",
            "/PRIVATE-BUNDLE",
            "--record",
        ],
        vec!["research-precheck", "--binary", "/PRIVATE-CANDIDATE"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .env_clear()
            .args(args)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr)?;
        assert!(error.contains("use research-precheck --bundle"));
        assert!(!error.contains("PRIVATE"));
    }
    Ok(())
}

#[test]
fn help_distinguishes_inventory_from_research_acceptance() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .env_clear()
        .arg("help")
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("research-precheck --bundle <absolute-private-directory>"));
    assert!(help.contains("NOT mathematical acceptance or corpus import"));
    Ok(())
}
