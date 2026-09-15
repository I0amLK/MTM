//! Read-only actual CLI acceptance with only Git exposed to the child PATH.
#![cfg(unix)]
use std::error::Error;
use std::process::{Command, Stdio};

use serde_json::Value;

#[test]
fn records_cli_needs_git_but_neither_python_nor_a_reference_checkout() -> Result<(), Box<dyn Error>>
{
    let tools = tempfile::tempdir()?;
    let git = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("git"))
                .find(|file| file.is_file())
        })
        .ok_or("Git prerequisite missing")?
        .canonicalize()?;
    std::os::unix::fs::symlink(git, tools.path().join("git"))?;
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .arg("records")
        .env_clear()
        .env("PATH", tools.path())
        .env("HOME", tools.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .output()?;
    assert!(
        output.status.success(),
        "Rust record CLI rejected the current checkout"
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["ok"], true);
    assert_eq!(report["historical_hashes_checked"], 26);
    assert_eq!(report["historical_releases"]["historical_milestones"], 12);
    assert_eq!(
        report["historical_releases"]["historical_target_milestones"],
        6
    );
    assert_eq!(
        report["historical_releases"]["historical_release_milestones"],
        6
    );
    assert_eq!(
        report["historical_releases"]["live_selectors_checked"],
        false
    );
    assert_eq!(
        report["historical_releases"]["mtm015_lifecycle_evidence"]
            .as_object()
            .map(|value| value.len()),
        Some(3)
    );
    assert_eq!(
        report["historical_releases"]["mtm015_lifecycle_evidence"]["candidate_stage"]["sha256"],
        "5787fd9d54cb8eb918833ecc8fc8cba417adde9de0baa612577042abb506aed4"
    );
    assert!(
        report["layout"]["sealed_observation_hashes_checked"]
            .as_u64()
            .is_some_and(|n| n >= 2)
    );
    assert_eq!(report["release_qualified"], false);
    assert_eq!(report["live_deployment_checked"], false);
    Ok(())
}
