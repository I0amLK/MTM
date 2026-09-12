use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_mtm-xtask")
}

#[test]
fn research_collect_cli_has_no_acceptance_or_candidate_override_surface()
-> Result<(), Box<dyn std::error::Error>> {
    for args in [
        vec!["research-collect"],
        vec![
            "research-collect",
            "--session",
            "relative",
            "--run-id",
            "run-a",
        ],
        vec![
            "research-collect",
            "--session",
            "/tmp/session",
            "--run-id",
            "../run",
        ],
        vec![
            "research-collect",
            "--session",
            "/tmp/session",
            "--run-id",
            "run-a",
            "--accept",
        ],
        vec![
            "research-collect",
            "--session",
            "/tmp/session",
            "--run-id",
            "run-a",
            "--binary",
            "/tmp/other",
        ],
    ] {
        let output = Command::new(binary()).args(args).env_clear().output()?;
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains("release_qualified\": true"));
        assert!(!stdout.contains("research_trial_passed\": true"));
        assert!(!stderr.contains("release_qualified\": true"));
        assert!(!stderr.contains("research_trial_passed\": true"));
    }
    Ok(())
}

#[test]
fn help_describes_collector_as_non_accepting_private_evidence_preparation()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(binary()).arg("help").env_clear().output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("research-collect --session"));
    assert!(stdout.contains("NOT corpus acceptance"));
    Ok(())
}
