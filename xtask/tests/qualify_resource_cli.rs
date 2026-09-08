#![cfg(target_os = "linux")]
use std::error::Error;
use std::process::{Command, Stdio};

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
