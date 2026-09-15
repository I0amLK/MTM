#![cfg(target_os = "linux")]
use serde_json::Value;
use std::error::Error;
use std::process::{Command, Stdio};

#[test]
fn missing_bubblewrap_is_explicit_and_never_a_qualification() -> Result<(), Box<dyn Error>> {
    // Empty PATH prevents discovery even on hosts that have Bubblewrap installed.
    // The owned self-probe still measures unshare; it does not mutate this test.
    let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
        .arg("native-preflight")
        .env_clear()
        .env("PATH", "")
        .env("API_TOKEN", "must-not-appear-in-preflight")
        .stdin(Stdio::null())
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["classification"], "bubblewrap_unavailable");
    assert_eq!(report["passed"], false);
    assert_eq!(report["tests_skipped_by_preflight"], false);
    assert_eq!(report["release_qualified"], false);
    assert_eq!(report["production_state_modified"], false);
    assert_eq!(report["context"]["host_context_proven"], false);
    assert_eq!(
        report["candidate_defect_attribution"],
        "not_evaluated_by_preflight"
    );
    assert!(report["source_tests_passed"].is_null());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-appear-in-preflight"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-appear-in-preflight"));
    Ok(())
}

#[test]
fn diagnostic_entry_rejects_execution_and_policy_override_arguments() -> Result<(), Box<dyn Error>>
{
    for option in ["--skip-native", "--disable-isolation", "--command=true"] {
        let output = Command::new(env!("CARGO_BIN_EXE_mtm-xtask"))
            .args(["native-preflight", option])
            .env_clear()
            .stdin(Stdio::null())
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}
