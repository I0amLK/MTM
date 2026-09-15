//! The permission lane cannot accept production paths or weakened soak bounds.
#![cfg(target_os = "linux")]
use std::error::Error;
use std::process::{Command, Stdio};

#[test]
fn permission_cli_rejects_missing_identity_baselines_and_scope_overrides()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let base = [
        "qualify",
        "--profile",
        "permissions",
        "--binary",
        "candidate",
        "--sha256",
    ];
    for extra in [
        vec![],
        vec!["a".repeat(64), "--baseline".into(), "old".into()],
        vec!["a".repeat(64), "--seconds".into(), "1".into()],
        vec![
            "a".repeat(64),
            "--state-root".into(),
            directory.path().to_string_lossy().into_owned(),
        ],
        vec!["a".repeat(64), "--human-consent".into(), "true".into()],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args(base)
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
