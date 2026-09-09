#![cfg(target_os = "linux")]
use std::error::Error;
use std::process::{Command, Stdio};

#[test]
fn upgrade_cli_rejects_missing_baseline_and_production_path_options() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let base = vec![
        "qualify".to_owned(),
        "--profile".into(),
        "upgrade".into(),
        "--binary".into(),
        "candidate".into(),
        "--sha256".into(),
        "a".repeat(64),
    ];
    for extra in [
        vec![],
        vec!["--baseline".to_owned(), "old".into()],
        vec![
            "--baseline".to_owned(),
            "old".into(),
            "--baseline-sha256".into(),
            "a".repeat(64),
        ],
        vec![
            "--baseline".to_owned(),
            "old".into(),
            "--baseline-sha256".into(),
            "b".repeat(64),
            "--state-root".into(),
            directory.path().to_string_lossy().into_owned(),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args(&base)
            .args(extra)
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

#[test]
fn resource_profile_requires_a_complete_distinct_baseline() -> Result<(), Box<dyn Error>> {
    let candidate = "a".repeat(64);
    let baseline = "b".repeat(64);
    for args in [
        vec![
            "qualify".to_owned(),
            "--profile".into(),
            "resource".into(),
            "--binary".into(),
            "candidate".into(),
            "--sha256".into(),
            candidate.clone(),
        ],
        vec![
            "qualify".to_owned(),
            "--profile".into(),
            "resource".into(),
            "--binary".into(),
            "candidate".into(),
            "--sha256".into(),
            candidate.clone(),
            "--baseline".into(),
            "baseline".into(),
        ],
        vec![
            "qualify".to_owned(),
            "--profile".into(),
            "resource".into(),
            "--binary".into(),
            "candidate".into(),
            "--sha256".into(),
            candidate.clone(),
            "--baseline".into(),
            "baseline".into(),
            "--baseline-sha256".into(),
            candidate.clone(),
        ],
        vec![
            "qualify".to_owned(),
            "--profile".into(),
            "protocol".into(),
            "--binary".into(),
            "candidate".into(),
            "--sha256".into(),
            candidate.clone(),
            "--baseline".into(),
            "baseline".into(),
            "--baseline-sha256".into(),
            baseline.clone(),
        ],
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
